"""
evaluate_continuous.py
======================
Continuous authentication evaluator with explicit attack-switch sessions.

Protocol:
1) Tune biometric threshold on xv (dev split).
2) Evaluate continuous sessions on xe (test split):
   - Genuine -> Impostor switch sessions
   - Genuine -> LLM/paste-assisted switch sessions
3) Report detection delay, false alarms, FAR/FRR-style online rates.

This script is meant for novelty validation of continuous authentication,
not replacement of the paper's static verification benchmarks.
"""

import argparse
import csv
import json
import os
import random
from dataclasses import dataclass
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import auc, roc_curve

import detect_llm_paste

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)
os.environ.setdefault("TF_FORCE_GPU_ALLOW_GROWTH", "true")


def configure_tf_runtime():
    """Avoid TensorFlow grabbing all VRAM at startup in shared DGX nodes."""
    try:
        import tensorflow as tf
        gpus = tf.config.list_physical_devices("GPU")
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    except Exception as e:
        print(f"[TF Runtime] Memory-growth setup warning: {e}")


@dataclass
class SessionOutcome:
    user_id: str
    attack_type: str
    detected: bool
    detection_delay_steps: int
    false_alarm_before_attack: bool
    pre_attack_reject_rate: float
    attack_accept_rate: float
    llm_block_rate: float
    total_steps: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Continuous authentication evaluation with impostor/LLM switch attacks."
    )
    parser.add_argument("dataset", help="Dataset under datasets/<name>/npy/")
    parser.add_argument("--checkpoint", default="model/checkpoint.weights.h5")
    parser.add_argument("--output-dir", default="results_continuous")
    parser.add_argument("--gallery-size", type=int, default=5)
    parser.add_argument("--impostors-per-user", type=int, default=200)
    parser.add_argument("--seed", type=int, default=int(os.environ.get("TYPE2BRANCH_SEED", "42")))

    # Session simulation
    parser.add_argument("--warmup-steps", type=int, default=40, help="Pre-attack genuine steps")
    parser.add_argument("--attack-steps", type=int, default=80, help="Post-switch attack steps")
    parser.add_argument("--decision-window", type=int, default=5, help="Moving-average window for scores")
    parser.add_argument("--alarm-consecutive", type=int, default=3, help="Consecutive reject decisions to trigger alarm")
    parser.add_argument("--sessions-per-user", type=int, default=1)

    # Scale controls
    parser.add_argument("--max-users-xv", type=int, default=1000, help="0 means all users")
    parser.add_argument("--max-users-xe", type=int, default=2000, help="0 means all users")
    parser.add_argument("--llm-pool-size", type=int, default=5000, help="Synthetic LLM pool for attack sessions")
    parser.add_argument(
        "--llm-assisted-npy",
        default=None,
        help="Optional path to external assisted-input samples (.npy) for non-synthetic evaluation",
    )
    parser.add_argument(
        "--llm-assisted-max-samples",
        type=int,
        default=5000,
        help="Max external assisted samples to load when --llm-assisted-npy is provided",
    )
    parser.add_argument("--max-human-llm-eval-samples", type=int, default=10000)
    parser.add_argument("--llm-threshold", type=float, default=0.35, help="LLM detector confidence threshold")
    parser.add_argument("--bootstrap-iters", type=int, default=1000, help="Bootstrap iterations for 95% CI")

    # Ablation toggles
    parser.add_argument("--disable-llm-gate", action="store_true", help="Disable LLM gate and use biometric-only decisions")
    parser.add_argument(
        "--disable-biometric-gate",
        action="store_true",
        help="Disable biometric gate and use LLM-only decisions",
    )
    return parser.parse_args()


def validate_partition(name: str, data: Dict) -> Tuple[int, int]:
    if len(data) == 0:
        raise ValueError(f"{name}.npy is empty.")

    first_user = next(iter(data.keys()))
    first_sample = next(iter(data[first_user].values()))
    seq_len, input_features = first_sample.shape

    for user_id, samples in data.items():
        if len(samples) == 0:
            raise ValueError(f"{name}.npy user '{user_id}' has 0 samples.")
        for sample_id, arr in samples.items():
            if arr.shape != first_sample.shape:
                raise ValueError(
                    f"{name}.npy shape mismatch user={user_id} sample={sample_id} "
                    f"shape={arr.shape} expected={first_sample.shape}"
                )

    return seq_len, input_features


def maybe_subsample_users(data: Dict, max_users: int, rng: np.random.Generator) -> Dict:
    if max_users <= 0 or max_users >= len(data):
        return data
    users = list(data.keys())
    chosen = rng.choice(len(users), size=max_users, replace=False)
    picked_users = [users[int(i)] for i in chosen]
    return {u: data[u] for u in picked_users}


def load_dataset(dataset_name: str, rng: np.random.Generator, max_users_xv: int, max_users_xe: int):
    base = os.path.join("datasets", dataset_name, "npy")
    xv_path = os.path.join(base, "xv.npy")
    xe_path = os.path.join(base, "xe.npy")
    if not os.path.exists(xv_path):
        raise FileNotFoundError(f"Missing {xv_path}")
    if not os.path.exists(xe_path):
        raise FileNotFoundError(f"Missing {xe_path}")

    xv = np.load(xv_path, allow_pickle=True).item()
    xe = np.load(xe_path, allow_pickle=True).item()

    xv = maybe_subsample_users(xv, max_users_xv, rng)
    xe = maybe_subsample_users(xe, max_users_xe, rng)

    seq_xv, feat_xv = validate_partition("xv", xv)
    seq_xe, feat_xe = validate_partition("xe", xe)
    if (seq_xv, feat_xv) != (seq_xe, feat_xe):
        raise ValueError(f"xv/xe shape mismatch: xv=({seq_xv},{feat_xv}) xe=({seq_xe},{feat_xe})")

    return xv, xe, seq_xv, feat_xv


def load_model(sequence_length: int, input_features: int, checkpoint_path: str):
    configure_tf_runtime()
    import model as model_module

    descriptor = {"SEQUENCE_LENGTH": sequence_length, "INPUT_FEATURES": input_features}
    descriptor = model_module.get_model_Type2Branch(descriptor, build_optimizer=False)
    model = descriptor["model"]

    if not os.path.exists(checkpoint_path):
        raise FileNotFoundError(f"Missing checkpoint: {checkpoint_path}")
    model.load_weights(checkpoint_path)
    return model


def compute_embeddings(model, partition: Dict) -> Dict[str, np.ndarray]:
    embeddings = {}
    users = list(partition.keys())
    for idx, user_id in enumerate(users):
        if (idx + 1) % 50 == 0 or idx == len(users) - 1:
            print(f"[Embeddings] {idx+1}/{len(users)} users processed...")
        stacked = np.stack(list(partition[user_id].values())).astype(np.float32, copy=False)
        embeddings[user_id] = model.predict(stacked, verbose=0)
    return embeddings


def score_query(gallery: np.ndarray, query: np.ndarray) -> float:
    return float(np.mean(np.linalg.norm(gallery - query, axis=1)))


def compute_eer(genuine: np.ndarray, impostor: np.ndarray, n_steps: int = 5000):
    lo = float(min(np.min(genuine), np.min(impostor)))
    hi = float(max(np.max(genuine), np.max(impostor)))
    if hi == lo:
        hi = lo + 1e-9
    thresholds = np.linspace(lo, hi, n_steps)
    fars = np.array([np.mean(impostor <= t) for t in thresholds], dtype=np.float64)
    frrs = np.array([np.mean(genuine > t) for t in thresholds], dtype=np.float64)
    idx = int(np.argmin(np.abs(fars - frrs)))
    return float(thresholds[idx]), float((fars[idx] + frrs[idx]) / 2.0), float(fars[idx]), float(frrs[idx])


def tune_threshold_xv(
    xv_embeddings: Dict[str, np.ndarray],
    gallery_size: int,
    impostors_per_user: int,
    rng: np.random.Generator,
):
    users = [u for u in xv_embeddings.keys() if len(xv_embeddings[u]) > gallery_size]
    if len(users) < 2:
        raise ValueError("Need at least 2 xv users with > gallery_size samples to tune threshold.")

    genuine_scores = []
    impostor_scores = []

    for user_id in users:
        user_emb = xv_embeddings[user_id]
        perm = rng.permutation(len(user_emb))
        gallery = user_emb[perm[:gallery_size]]
        queries = user_emb[perm[gallery_size:]]

        for q in queries:
            genuine_scores.append(score_query(gallery, q))

        candidates = [u for u in users if u != user_id]
        n_imp = min(impostors_per_user, len(candidates))
        chosen = rng.choice(len(candidates), size=n_imp, replace=False)
        for ci in chosen:
            imp_user = candidates[int(ci)]
            imp_embs = xv_embeddings[imp_user]
            pick = int(rng.integers(0, len(imp_embs)))
            impostor_scores.append(score_query(gallery, imp_embs[pick]))

    genuine = np.array(genuine_scores, dtype=np.float64)
    impostor = np.array(impostor_scores, dtype=np.float64)
    thr, eer, far, frr = compute_eer(genuine, impostor)
    return thr, eer, far, frr


def generate_llm_samples(
    seq_length: int,
    input_features: int,
    n_samples: int,
    rng: np.random.Generator,
):
    if n_samples <= 0:
        raise ValueError("llm_pool_size must be > 0.")

    samples = []
    for _ in range(n_samples):
        s = np.zeros((seq_length, input_features), dtype=np.float32)
        s[:, 0] = rng.integers(97, 123, size=seq_length) / 255.0
        s[:, 1] = rng.uniform(0.02, 0.04, size=seq_length)
        s[:, 2] = rng.uniform(0.0, 0.003, size=seq_length)
        if input_features >= 5:
            s[:, 3] = s[:, 1] - 0.1
            s[:, 4] = s[:, 2] - 0.15
        samples.append(s)
    return np.stack(samples, axis=0)


def load_assisted_samples(path: str, seq_length: int, input_features: int, max_samples: int, rng: np.random.Generator):
    obj = np.load(path, allow_pickle=True)
    samples = []

    # Format A: dense array [N, seq, feat]
    if isinstance(obj, np.ndarray) and obj.ndim == 3:
        for i in range(obj.shape[0]):
            samples.append(np.array(obj[i], dtype=np.float32))
    # Format B: object array / list-like
    elif isinstance(obj, np.ndarray) and obj.dtype == object:
        flat = obj.tolist()
        for item in flat:
            if isinstance(item, np.ndarray):
                samples.append(np.array(item, dtype=np.float32))
    # Format C: dict-like saved with np.save(..., allow_pickle=True)
    elif isinstance(obj, np.ndarray) and obj.shape == ():
        maybe = obj.item()
        if isinstance(maybe, dict):
            for v in maybe.values():
                if isinstance(v, dict):
                    for arr in v.values():
                        samples.append(np.array(arr, dtype=np.float32))
                elif isinstance(v, np.ndarray):
                    samples.append(np.array(v, dtype=np.float32))
    else:
        raise ValueError(f"Unsupported assisted sample format in {path}")

    valid = [s for s in samples if isinstance(s, np.ndarray) and s.shape == (seq_length, input_features)]
    if not valid:
        raise ValueError(
            f"No valid assisted samples with shape {(seq_length, input_features)} in {path}. "
            f"Loaded={len(samples)}"
        )

    arr = np.stack(valid, axis=0)
    if max_samples > 0 and arr.shape[0] > max_samples:
        idx = rng.choice(arr.shape[0], size=max_samples, replace=False)
        arr = arr[idx]
    return arr


def build_llm_pool(
    model,
    seq_length: int,
    input_features: int,
    llm_pool_size: int,
    assisted_npy: str,
    assisted_max_samples: int,
    llm_threshold: float,
    rng: np.random.Generator,
):
    synthetic_raw = generate_llm_samples(seq_length, input_features, llm_pool_size, rng)
    source = ["synthetic"] * len(synthetic_raw)
    llm_raw = synthetic_raw

    if assisted_npy:
        if not os.path.exists(assisted_npy):
            raise FileNotFoundError(f"Assisted sample file not found: {assisted_npy}")
        assisted_raw = load_assisted_samples(
            assisted_npy, seq_length, input_features, assisted_max_samples, rng
        )
        llm_raw = np.concatenate([synthetic_raw, assisted_raw], axis=0)
        source.extend(["assisted_external"] * len(assisted_raw))

    llm_emb = model.predict(llm_raw, verbose=0, batch_size=1024)

    llm_flags = []
    llm_conf = []
    for sample in llm_raw:
        is_llm, _, conf = detect_llm_paste.detect_llm_behavior(sample, threshold=llm_threshold)
        llm_flags.append(bool(is_llm))
        llm_conf.append(float(conf))

    return (
        llm_raw,
        llm_emb,
        np.array(llm_flags, dtype=bool),
        np.array(llm_conf, dtype=np.float32),
        np.array(source),
    )


def online_decisions(
    threshold: float,
    scores: np.ndarray,
    llm_flags: np.ndarray,
    decision_window: int,
    alarm_consecutive: int,
    use_llm_gate: bool,
    use_biometric_gate: bool,
):
    rejects = []
    llm_blocks = []
    alarm_idx = None
    consec = 0
    window = []

    for t in range(len(scores)):
        score = float(scores[t])
        window.append(score)
        if len(window) > decision_window:
            window.pop(0)
        smoothed = float(np.mean(window))

        if use_llm_gate and llm_flags[t]:
            reject = True
            llm_block = True
        else:
            reject = use_biometric_gate and (smoothed > threshold)
            llm_block = False

        rejects.append(reject)
        llm_blocks.append(llm_block)

        if reject:
            consec += 1
            if consec >= alarm_consecutive and alarm_idx is None:
                alarm_idx = t
        else:
            consec = 0

    return np.array(rejects, dtype=bool), np.array(llm_blocks, dtype=bool), alarm_idx


def simulate_session(
    user_id: str,
    attack_type: str,
    threshold: float,
    genuine_scores: np.ndarray,
    attack_scores: np.ndarray,
    attack_llm_flags: np.ndarray,
    warmup_steps: int,
    attack_steps: int,
    decision_window: int,
    alarm_consecutive: int,
    use_llm_gate: bool,
    use_biometric_gate: bool,
) -> SessionOutcome:
    pre_n = min(warmup_steps, len(genuine_scores))
    post_n = min(attack_steps, len(attack_scores))

    pre_scores = genuine_scores[:pre_n]
    post_scores = attack_scores[:post_n]
    pre_llm = np.zeros(pre_n, dtype=bool)
    post_llm = attack_llm_flags[:post_n]

    all_scores = np.concatenate([pre_scores, post_scores], axis=0)
    all_llm = np.concatenate([pre_llm, post_llm], axis=0)
    switch_idx = pre_n

    rejects, llm_blocks, alarm_idx = online_decisions(
        threshold=threshold,
        scores=all_scores,
        llm_flags=all_llm,
        decision_window=decision_window,
        alarm_consecutive=alarm_consecutive,
        use_llm_gate=use_llm_gate,
        use_biometric_gate=use_biometric_gate,
    )

    pre_reject_rate = float(np.mean(rejects[:pre_n])) if pre_n > 0 else 0.0
    post_accept_rate = float(np.mean(~rejects[switch_idx:])) if post_n > 0 else 0.0
    post_llm_block_rate = float(np.mean(llm_blocks[switch_idx:])) if post_n > 0 else 0.0

    false_alarm_before = alarm_idx is not None and alarm_idx < switch_idx
    detected = alarm_idx is not None and alarm_idx >= switch_idx
    delay = int(alarm_idx - switch_idx + 1) if detected else -1

    return SessionOutcome(
        user_id=user_id,
        attack_type=attack_type,
        detected=bool(detected),
        detection_delay_steps=delay,
        false_alarm_before_attack=bool(false_alarm_before),
        pre_attack_reject_rate=pre_reject_rate,
        attack_accept_rate=post_accept_rate,
        llm_block_rate=post_llm_block_rate,
        total_steps=int(len(all_scores)),
    )


def summarize_sessions(rows: List[SessionOutcome], attack_type: str):
    data = [r for r in rows if r.attack_type == attack_type]
    if not data:
        return {}
    det = [1.0 if r.detected else 0.0 for r in data]
    delays = [r.detection_delay_steps for r in data if r.detected and r.detection_delay_steps >= 0]
    false_alarm = [1.0 if r.false_alarm_before_attack else 0.0 for r in data]
    pre_reject = [r.pre_attack_reject_rate for r in data]
    post_accept = [r.attack_accept_rate for r in data]
    llm_block = [r.llm_block_rate for r in data]

    return {
        "sessions": len(data),
        "detection_rate": float(np.mean(det)),
        "mean_detection_delay_steps": float(np.mean(delays)) if delays else None,
        "false_alarm_before_attack_rate": float(np.mean(false_alarm)),
        "pre_attack_reject_rate": float(np.mean(pre_reject)),
        "attack_accept_rate": float(np.mean(post_accept)),
        "attack_block_rate": float(1.0 - np.mean(post_accept)),
        "llm_block_rate": float(np.mean(llm_block)),
    }


def bootstrap_mean_ci(values: np.ndarray, iters: int, seed: int):
    if values.size == 0:
        return None
    if values.size == 1:
        v = float(values[0])
        return [v, v]
    if iters <= 0:
        return None
    rng = np.random.default_rng(seed)
    n = values.size
    stats = []
    for _ in range(iters):
        sample = values[rng.integers(0, n, size=n)]
        stats.append(float(np.mean(sample)))
    return [float(np.percentile(stats, 2.5)), float(np.percentile(stats, 97.5))]


def summarize_sessions_with_ci(
    rows: List[SessionOutcome],
    attack_type: str,
    bootstrap_iters: int,
    seed: int,
):
    summary = summarize_sessions(rows, attack_type)
    if not summary:
        return summary

    data = [r for r in rows if r.attack_type == attack_type]
    det = np.array([1.0 if r.detected else 0.0 for r in data], dtype=np.float64)
    false_alarm = np.array([1.0 if r.false_alarm_before_attack else 0.0 for r in data], dtype=np.float64)
    pre_reject = np.array([r.pre_attack_reject_rate for r in data], dtype=np.float64)
    delays = np.array(
        [r.detection_delay_steps for r in data if r.detected and r.detection_delay_steps >= 0],
        dtype=np.float64,
    )

    summary["detection_rate_95ci"] = bootstrap_mean_ci(det, bootstrap_iters, seed + 11)
    summary["false_alarm_before_attack_rate_95ci"] = bootstrap_mean_ci(false_alarm, bootstrap_iters, seed + 23)
    summary["pre_attack_reject_rate_95ci"] = bootstrap_mean_ci(pre_reject, bootstrap_iters, seed + 37)
    summary["mean_detection_delay_steps_95ci"] = bootstrap_mean_ci(delays, bootstrap_iters, seed + 41)
    return summary


def save_session_csv(path: str, rows: List[SessionOutcome]):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "user_id",
                "attack_type",
                "detected",
                "detection_delay_steps",
                "false_alarm_before_attack",
                "pre_attack_reject_rate",
                "attack_accept_rate",
                "llm_block_rate",
                "total_steps",
            ]
        )
        for r in rows:
            writer.writerow(
                [
                    r.user_id,
                    r.attack_type,
                    int(r.detected),
                    r.detection_delay_steps,
                    int(r.false_alarm_before_attack),
                    r.pre_attack_reject_rate,
                    r.attack_accept_rate,
                    r.llm_block_rate,
                    r.total_steps,
                ]
            )


def save_delay_plot(path: str, rows: List[SessionOutcome]):
    imp = [r.detection_delay_steps for r in rows if r.attack_type == "impostor" and r.detected and r.detection_delay_steps >= 0]
    llm = [r.detection_delay_steps for r in rows if r.attack_type == "llm" and r.detected and r.detection_delay_steps >= 0]

    plt.figure(figsize=(10, 5))
    if imp:
        plt.hist(imp, bins=30, alpha=0.6, label="Impostor")
    if llm:
        plt.hist(llm, bins=30, alpha=0.6, label="LLM")
    plt.xlabel("Detection delay (steps after attack switch)")
    plt.ylabel("Count")
    plt.title("Continuous Authentication Detection Delays")
    plt.grid(alpha=0.3)
    if imp or llm:
        plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def save_llm_roc(path: str, labels: np.ndarray, scores: np.ndarray):
    if labels.size == 0 or scores.size == 0 or len(np.unique(labels)) < 2:
        plt.figure(figsize=(6, 6))
        plt.text(0.5, 0.5, "Insufficient class diversity for ROC", ha="center", va="center")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(path, dpi=150)
        plt.close()
        return None

    fpr, tpr, _ = roc_curve(labels, scores)
    roc_auc = float(auc(fpr, tpr))

    plt.figure(figsize=(6, 6))
    plt.plot(fpr, tpr, linewidth=2, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray", linewidth=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("LLM Detector ROC (Synthetic vs Human)")
    plt.grid(alpha=0.3)
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    return roc_auc


def save_llm_calibration(path: str, labels: np.ndarray, scores: np.ndarray, bins: int = 10):
    if labels.size == 0 or scores.size == 0:
        plt.figure(figsize=(6, 6))
        plt.text(0.5, 0.5, "Insufficient data for calibration", ha="center", va="center")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(path, dpi=150)
        plt.close()
        return None

    edges = np.linspace(0.0, 1.0, bins + 1)
    centers = []
    empirical = []
    weights = []
    total = float(labels.size)

    for i in range(bins):
        lo = edges[i]
        hi = edges[i + 1]
        if i == bins - 1:
            mask = (scores >= lo) & (scores <= hi)
        else:
            mask = (scores >= lo) & (scores < hi)
        if not np.any(mask):
            continue
        conf = scores[mask]
        y = labels[mask]
        centers.append(float(np.mean(conf)))
        empirical.append(float(np.mean(y)))
        weights.append(float(np.sum(mask)) / total)

    if not centers:
        plt.figure(figsize=(6, 6))
        plt.text(0.5, 0.5, "No populated confidence bins", ha="center", va="center")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(path, dpi=150)
        plt.close()
        return None

    centers_np = np.array(centers, dtype=np.float64)
    empirical_np = np.array(empirical, dtype=np.float64)
    weights_np = np.array(weights, dtype=np.float64)
    ece = float(np.sum(np.abs(empirical_np - centers_np) * weights_np))
    brier = float(np.mean((scores - labels) ** 2))

    plt.figure(figsize=(6, 6))
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray", linewidth=1, label="Perfect calibration")
    plt.plot(centers_np, empirical_np, marker="o", linewidth=2, label=f"ECE={ece:.4f}, Brier={brier:.4f}")
    plt.xlabel("Predicted confidence")
    plt.ylabel("Empirical positive rate")
    plt.title("LLM Detector Calibration")
    plt.grid(alpha=0.3)
    plt.legend(loc="upper left")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()

    return {"ece": ece, "brier": brier}


def main():
    args = parse_args()
    if args.gallery_size < 1:
        raise ValueError("--gallery-size must be >= 1")
    if args.impostors_per_user < 1:
        raise ValueError("--impostors-per-user must be >= 1")
    if args.warmup_steps < 1:
        raise ValueError("--warmup-steps must be >= 1")
    if args.attack_steps < 1:
        raise ValueError("--attack-steps must be >= 1")
    if args.decision_window < 1:
        raise ValueError("--decision-window must be >= 1")
    if args.alarm_consecutive < 1:
        raise ValueError("--alarm-consecutive must be >= 1")
    if args.sessions_per_user < 1:
        raise ValueError("--sessions-per-user must be >= 1")
    if args.llm_pool_size < 1:
        raise ValueError("--llm-pool-size must be >= 1")
    if args.max_human_llm_eval_samples < 1:
        raise ValueError("--max-human-llm-eval-samples must be >= 1")
    if args.llm_assisted_max_samples < 1:
        raise ValueError("--llm-assisted-max-samples must be >= 1")
    if not (0.0 <= args.llm_threshold <= 1.0):
        raise ValueError("--llm-threshold must be in [0, 1]")
    if args.disable_llm_gate and args.disable_biometric_gate:
        raise ValueError("Both gates are disabled. Enable at least one of biometric/LLM gate.")

    random.seed(args.seed)
    np.random.seed(args.seed)
    rng = np.random.default_rng(args.seed)

    print("=" * 72)
    print("CONTINUOUS AUTHENTICATION EVALUATION")
    print("=" * 72)
    print(f"[Config] dataset={args.dataset} seed={args.seed}")

    xv, xe, seq_len, input_features = load_dataset(
        args.dataset, rng, args.max_users_xv, args.max_users_xe
    )
    print(f"[Data] xv users={len(xv)} xe users={len(xe)} shape=({seq_len},{input_features})")

    model = load_model(seq_len, input_features, args.checkpoint)
    print("[Model] checkpoint loaded")

    print("[Embeddings] xv...")
    xv_embeddings = compute_embeddings(model, xv)
    print("[Embeddings] xe...")
    xe_embeddings = compute_embeddings(model, xe)

    tune_thr, tune_eer, tune_far, tune_frr = tune_threshold_xv(
        xv_embeddings,
        gallery_size=args.gallery_size,
        impostors_per_user=args.impostors_per_user,
        rng=rng,
    )
    print(f"[Threshold] tuned on xv: thr={tune_thr:.6f} eer={100.0*tune_eer:.3f}%")

    print("[LLM] building synthetic pool...")
    llm_raw, llm_emb, llm_flags, llm_conf, llm_source = build_llm_pool(
        model,
        seq_len,
        input_features,
        args.llm_pool_size,
        args.llm_assisted_npy,
        args.llm_assisted_max_samples,
        args.llm_threshold,
        rng,
    )
    syn_mask = llm_source == "synthetic"
    ext_mask = llm_source == "assisted_external"
    llm_tpr = float(np.mean(llm_flags[syn_mask])) if np.any(syn_mask) else 0.0
    llm_external_flag_rate = float(np.mean(llm_flags[ext_mask])) if np.any(ext_mask) else None

    # Human false positive estimation for LLM detector
    human_flags = []
    human_conf = []
    inspected = 0
    for user_id, samples in xe.items():
        for sample in samples.values():
            is_llm, _, conf = detect_llm_paste.detect_llm_behavior(sample, threshold=args.llm_threshold)
            human_flags.append(1.0 if is_llm else 0.0)
            human_conf.append(float(conf))
            inspected += 1
            if inspected >= args.max_human_llm_eval_samples:
                break
        if inspected >= args.max_human_llm_eval_samples:
            break
    llm_fpr_human = float(np.mean(human_flags)) if human_flags else 0.0
    llm_labels = np.concatenate(
        [np.ones(len(llm_conf), dtype=np.float64), np.zeros(len(human_conf), dtype=np.float64)],
        axis=0,
    )
    llm_detector_scores = np.concatenate(
        [llm_conf.astype(np.float64), np.array(human_conf, dtype=np.float64)],
        axis=0,
    )

    outcomes: List[SessionOutcome] = []
    users = [u for u in xe_embeddings.keys() if len(xe_embeddings[u]) > args.gallery_size + 2]
    if len(users) < 2:
        raise ValueError("Need at least 2 xe users with enough samples for continuous simulation.")

    for idx, user_id in enumerate(users):
        if (idx + 1) % 50 == 0 or idx == len(users) - 1:
            print(f"[Sessions] {idx+1}/{len(users)} users simulated...")

        user_emb = xe_embeddings[user_id]
        perm = rng.permutation(len(user_emb))
        gallery = user_emb[perm[:args.gallery_size]]
        genuine_queries = user_emb[perm[args.gallery_size:]]
        genuine_scores = np.array([score_query(gallery, q) for q in genuine_queries], dtype=np.float64)

        candidates = [u for u in users if u != user_id]
        if not candidates:
            continue

        # Build a local impostor score pool for this user
        n_imp_pool = min(max(args.impostors_per_user, args.attack_steps), len(candidates))
        chosen_imp = rng.choice(len(candidates), size=n_imp_pool, replace=False)
        imp_scores = []
        for ci in chosen_imp:
            imp_user = candidates[int(ci)]
            imp_embs = xe_embeddings[imp_user]
            pick = int(rng.integers(0, len(imp_embs)))
            imp_scores.append(score_query(gallery, imp_embs[pick]))
        impostor_scores = np.array(imp_scores, dtype=np.float64)

        # LLM score pool for this user
        llm_pick = rng.choice(len(llm_emb), size=min(len(llm_emb), max(args.attack_steps, 200)), replace=False)
        llm_attack_scores = np.array([score_query(gallery, llm_emb[int(i)]) for i in llm_pick], dtype=np.float64)
        llm_flags_local = llm_flags[llm_pick]

        for _ in range(args.sessions_per_user):
            # Impostor switch session
            imp_perm = rng.permutation(len(impostor_scores))
            outcome_imp = simulate_session(
                user_id=user_id,
                attack_type="impostor",
                threshold=tune_thr,
                genuine_scores=genuine_scores,
                attack_scores=impostor_scores[imp_perm],
                attack_llm_flags=np.zeros(len(impostor_scores), dtype=bool),
                warmup_steps=args.warmup_steps,
                attack_steps=args.attack_steps,
                decision_window=args.decision_window,
                alarm_consecutive=args.alarm_consecutive,
                use_llm_gate=(not args.disable_llm_gate),
                use_biometric_gate=(not args.disable_biometric_gate),
            )
            outcomes.append(outcome_imp)

            # LLM switch session
            llm_perm = rng.permutation(len(llm_attack_scores))
            outcome_llm = simulate_session(
                user_id=user_id,
                attack_type="llm",
                threshold=tune_thr,
                genuine_scores=genuine_scores,
                attack_scores=llm_attack_scores[llm_perm],
                attack_llm_flags=llm_flags_local[llm_perm],
                warmup_steps=args.warmup_steps,
                attack_steps=args.attack_steps,
                decision_window=args.decision_window,
                alarm_consecutive=args.alarm_consecutive,
                use_llm_gate=(not args.disable_llm_gate),
                use_biometric_gate=(not args.disable_biometric_gate),
            )
            outcomes.append(outcome_llm)

    imp_summary = summarize_sessions_with_ci(outcomes, "impostor", args.bootstrap_iters, args.seed + 101)
    llm_summary = summarize_sessions_with_ci(outcomes, "llm", args.bootstrap_iters, args.seed + 151)

    os.makedirs(args.output_dir, exist_ok=True)
    save_session_csv(os.path.join(args.output_dir, "continuous_sessions.csv"), outcomes)
    save_delay_plot(os.path.join(args.output_dir, "continuous_detection_delay.png"), outcomes)
    llm_roc_auc = save_llm_roc(
        os.path.join(args.output_dir, "continuous_llm_roc.png"),
        llm_labels,
        llm_detector_scores,
    )
    llm_calibration = save_llm_calibration(
        os.path.join(args.output_dir, "continuous_llm_calibration.png"),
        llm_labels,
        llm_detector_scores,
    )

    metrics = {
        "dataset": args.dataset,
        "seed": args.seed,
        "checkpoint": args.checkpoint,
        "protocol": {
            "threshold_tuned_on": "xv",
            "continuous_test_on": "xe",
            "warmup_steps": args.warmup_steps,
            "attack_steps": args.attack_steps,
            "decision_window": args.decision_window,
            "alarm_consecutive": args.alarm_consecutive,
            "sessions_per_user": args.sessions_per_user,
            "use_llm_gate": not args.disable_llm_gate,
            "use_biometric_gate": not args.disable_biometric_gate,
        },
        "threshold_tuning_xv": {
            "threshold": tune_thr,
            "eer": tune_eer,
            "far": tune_far,
            "frr": tune_frr,
        },
        "llm_detector": {
            "synthetic_pool_size": args.llm_pool_size,
            "external_assisted_npy": args.llm_assisted_npy,
            "external_assisted_loaded": int(np.sum(ext_mask)),
            "synthetic_tpr": llm_tpr,
            "external_assisted_flag_rate": llm_external_flag_rate,
            "human_fpr_estimate": llm_fpr_human,
            "human_samples_checked": int(len(human_flags)),
            "synthetic_mean_confidence": float(np.mean(llm_conf[syn_mask])) if np.any(syn_mask) else 0.0,
            "external_assisted_mean_confidence": float(np.mean(llm_conf[ext_mask])) if np.any(ext_mask) else None,
            "human_mean_confidence": float(np.mean(human_conf)) if human_conf else 0.0,
            "decision_threshold": args.llm_threshold,
            "roc_auc_synth_vs_human": llm_roc_auc,
            "calibration": llm_calibration,
        },
        "continuous_impostor": imp_summary,
        "continuous_llm": llm_summary,
        "users_simulated": len(users),
        "sessions_total": len(outcomes),
    }

    with open(os.path.join(args.output_dir, "continuous_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    txt = os.path.join(args.output_dir, "continuous_metrics.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("CONTINUOUS AUTHENTICATION REPORT\n")
        f.write("=" * 72 + "\n\n")
        f.write(f"Dataset: {args.dataset}\n")
        f.write(f"Users simulated: {len(users)}\n")
        f.write(f"Sessions total: {len(outcomes)}\n")
        f.write(f"Threshold tuned on xv: {tune_thr:.6f}\n")
        f.write(f"xv EER: {100.0 * tune_eer:.4f}%\n\n")
        f.write(f"Biometric gate enabled: {not args.disable_biometric_gate}\n")
        f.write(f"LLM gate enabled: {not args.disable_llm_gate}\n\n")

        f.write("LLM Detector:\n")
        f.write(f"  Decision threshold: {args.llm_threshold:.4f}\n")
        f.write(f"  Synthetic TPR: {100.0 * llm_tpr:.2f}%\n")
        if llm_external_flag_rate is not None:
            f.write(f"  External assisted flag rate: {100.0 * llm_external_flag_rate:.2f}%\n")
            f.write(f"  External assisted samples loaded: {int(np.sum(ext_mask))}\n")
        f.write(f"  Human FPR estimate: {100.0 * llm_fpr_human:.2f}%\n")
        f.write(f"  Human samples checked: {len(human_flags)}\n")
        if llm_roc_auc is not None:
            f.write(f"  ROC AUC (synthetic vs human): {llm_roc_auc:.6f}\n")
        if llm_calibration is not None:
            f.write(f"  Calibration ECE: {llm_calibration['ece']:.6f}\n")
            f.write(f"  Calibration Brier: {llm_calibration['brier']:.6f}\n")
        f.write("\n")

        f.write("Continuous Impostor Sessions:\n")
        for k, v in imp_summary.items():
            if isinstance(v, float):
                f.write(f"  {k}: {v:.6f}\n")
            else:
                f.write(f"  {k}: {v}\n")
        f.write("\n")

        f.write("Continuous LLM Sessions:\n")
        for k, v in llm_summary.items():
            if isinstance(v, float):
                f.write(f"  {k}: {v:.6f}\n")
            else:
                f.write(f"  {k}: {v}\n")
        f.write("\n")

    print("=" * 72)
    print("CONTINUOUS RESULTS")
    print("=" * 72)
    print(f"Threshold(xv): {tune_thr:.6f} | xv EER: {100.0*tune_eer:.3f}%")
    print(f"Impostor detection rate: {imp_summary.get('detection_rate', 0.0):.3f}")
    print(f"LLM detection rate: {llm_summary.get('detection_rate', 0.0):.3f}")
    print(f"LLM synthetic TPR: {llm_tpr:.3f} | human FPR est: {llm_fpr_human:.3f}")
    if llm_external_flag_rate is not None:
        print(f"LLM external-assisted flag rate: {llm_external_flag_rate:.3f} (n={int(np.sum(ext_mask))})")
    print(f"Saved: {args.output_dir}")


if __name__ == "__main__":
    main()
