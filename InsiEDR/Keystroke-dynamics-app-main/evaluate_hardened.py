"""
evaluate_hardened.py
====================
Publication-oriented biometric evaluation with strict split hygiene:
- Threshold tuning on validation users (xv)
- Final reporting on held-out test users (xe)
- No synthetic LLM samples, no heuristic leakage

Outputs:
- <output_dir>/hardened_metrics.txt
- <output_dir>/hardened_metrics.json
- <output_dir>/threshold_curve.csv
- <output_dir>/score_histogram.png
- <output_dir>/far_frr_curve.png
- <output_dir>/per_user_eer.csv
- <output_dir>/threshold_artifact.json
"""

import argparse
import csv
import json
import os
import random
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hardened keystroke biometric evaluation (xv tune, xe test)."
    )
    parser.add_argument("dataset", help="Dataset folder name under datasets/<name>/npy/")
    parser.add_argument("--checkpoint", default="model/checkpoint.weights.h5")
    parser.add_argument("--output-dir", default="results_hardened")
    parser.add_argument("--gallery-size", type=int, default=5)
    parser.add_argument("--impostors-per-user", type=int, default=200)
    parser.add_argument(
        "--max-genuine-queries-per-user",
        type=int,
        default=30,
        help="Cap genuine probe samples per user to reduce heavy-user dominance (0 = no cap).",
    )
    parser.add_argument("--seed", type=int, default=int(os.environ.get("TYPE2BRANCH_SEED", "42")))
    parser.add_argument("--bootstrap-iters", type=int, default=200)
    parser.add_argument("--max-users-xv", type=int, default=0, help="0 means use all users")
    parser.add_argument("--max-users-xe", type=int, default=0, help="0 means use all users")
    return parser.parse_args()


def validate_partition(name: str, data: Dict) -> Tuple[int, int]:
    if len(data) == 0:
        raise ValueError(f"{name}.npy is empty.")

    first_user = next(iter(data.keys()))
    first_sample = next(iter(data[first_user].values()))
    seq_len, input_features = first_sample.shape

    for user_id, samples in data.items():
        if len(samples) == 0:
            raise ValueError(f"{name}.npy has user '{user_id}' with 0 samples.")
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
    picked_idx = rng.choice(len(users), size=max_users, replace=False)
    picked = [users[i] for i in picked_idx]
    return {u: data[u] for u in picked}


def load_dataset(dataset_name: str, rng: np.random.Generator, max_users_xv: int, max_users_xe: int):
    base = os.path.join("datasets", dataset_name, "npy")
    xv_path = os.path.join(base, "xv.npy")
    xe_path = os.path.join(base, "xe.npy")

    if not os.path.exists(xv_path):
        raise FileNotFoundError(f"Missing validation split for tuning: {xv_path}")
    if not os.path.exists(xe_path):
        raise FileNotFoundError(f"Missing test split for final report: {xe_path}")

    xv = np.load(xv_path, allow_pickle=True).item()
    xe = np.load(xe_path, allow_pickle=True).item()

    xv = maybe_subsample_users(xv, max_users_xv, rng)
    xe = maybe_subsample_users(xe, max_users_xe, rng)

    seq_xv, feat_xv = validate_partition("xv", xv)
    seq_xe, feat_xe = validate_partition("xe", xe)

    if (seq_xv, feat_xv) != (seq_xe, feat_xe):
        raise ValueError(
            f"xv/xe shape mismatch: xv=({seq_xv},{feat_xv}) xe=({seq_xe},{feat_xe})"
        )

    return xv, xe, seq_xv, feat_xv


def load_model(sequence_length: int, input_features: int, checkpoint_path: str):
    configure_tf_runtime()
    import model as model_module

    descriptor = {
        "SEQUENCE_LENGTH": sequence_length,
        "INPUT_FEATURES": input_features,
    }
    descriptor = model_module.get_model_Type2Branch(descriptor, build_optimizer=False)
    model = descriptor["model"]

    if not os.path.exists(checkpoint_path):
        raise FileNotFoundError(f"Missing trained checkpoint: {checkpoint_path}")

    model.load_weights(checkpoint_path)
    return model


def compute_embeddings(model, partition: Dict) -> Dict[str, np.ndarray]:
    out = {}
    for user_id, samples in partition.items():
        stacked = np.stack(list(samples.values())).astype(np.float32, copy=False)
        emb = model.predict(stacked, verbose=0)
        out[user_id] = emb
    return out


def mean_l2_distance(gallery: np.ndarray, query: np.ndarray) -> float:
    return float(np.mean(np.linalg.norm(gallery - query, axis=1)))


def build_scores(
    embeddings_by_user: Dict[str, np.ndarray],
    gallery_size: int,
    impostors_per_user: int,
    max_genuine_queries_per_user: int,
    rng: np.random.Generator,
):
    users = [u for u in embeddings_by_user.keys() if len(embeddings_by_user[u]) > gallery_size]
    if len(users) < 2:
        raise ValueError(
            f"Need at least 2 users with > gallery_size samples (gallery_size={gallery_size}, valid_users={len(users)})."
        )

    genuine_scores: List[float] = []
    impostor_scores: List[float] = []
    per_user_eer: List[Dict] = []

    for user_id in users:
        user_emb = embeddings_by_user[user_id]
        perm = rng.permutation(len(user_emb))
        gallery_idx = perm[:gallery_size]
        query_idx = perm[gallery_size:]
        if max_genuine_queries_per_user > 0 and len(query_idx) > max_genuine_queries_per_user:
            query_idx = rng.choice(
                query_idx, size=max_genuine_queries_per_user, replace=False
            )
        gallery = user_emb[gallery_idx]

        user_genuine = [mean_l2_distance(gallery, user_emb[idx]) for idx in query_idx]
        genuine_scores.extend(user_genuine)

        impostor_candidates = [u for u in users if u != user_id]
        n_imp = min(impostors_per_user, len(impostor_candidates))
        chosen = rng.choice(len(impostor_candidates), size=n_imp, replace=False)

        user_impostor = []
        for ci in chosen:
            imp_user = impostor_candidates[int(ci)]
            imp_embs = embeddings_by_user[imp_user]
            pick = int(rng.integers(0, len(imp_embs)))
            user_impostor.append(mean_l2_distance(gallery, imp_embs[pick]))

        impostor_scores.extend(user_impostor)

        if len(user_genuine) > 1 and len(user_impostor) > 1:
            _, user_eer, _, _, _, _, _ = compute_eer(np.array(user_genuine), np.array(user_impostor))
            per_user_eer.append(
                {
                    "user_id": user_id,
                    "eer": float(user_eer),
                    "genuine_n": int(len(user_genuine)),
                    "impostor_n": int(len(user_impostor)),
                }
            )

    genuine = np.array(genuine_scores, dtype=np.float64)
    impostor = np.array(impostor_scores, dtype=np.float64)
    if len(genuine) == 0 or len(impostor) == 0:
        raise ValueError("Generated empty genuine/impostor score arrays.")

    return genuine, impostor, per_user_eer, len(users)


def compute_eer(genuine: np.ndarray, impostor: np.ndarray, num_thresholds: int = 5000):
    lo = float(min(np.min(genuine), np.min(impostor)))
    hi = float(max(np.max(genuine), np.max(impostor)))
    if hi == lo:
        hi = lo + 1e-9

    thresholds = np.linspace(lo, hi, num_thresholds)
    fars = np.array([np.mean(impostor <= t) for t in thresholds], dtype=np.float64)
    frrs = np.array([np.mean(genuine > t) for t in thresholds], dtype=np.float64)
    idx = int(np.argmin(np.abs(fars - frrs)))

    thr = float(thresholds[idx])
    far = float(fars[idx])
    frr = float(frrs[idx])
    eer = float((far + frr) / 2.0)
    return thr, eer, far, frr, thresholds, fars, frrs


def operating_point(genuine: np.ndarray, impostor: np.ndarray, threshold: float):
    far = float(np.mean(impostor <= threshold))
    frr = float(np.mean(genuine > threshold))
    hter = float((far + frr) / 2.0)
    tar = float(1.0 - frr)
    return far, frr, hter, tar


def bootstrap_ci(
    metric_fn,
    genuine: np.ndarray,
    impostor: np.ndarray,
    iters: int,
    seed: int,
):
    if iters <= 0:
        return None
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(iters):
        g = genuine[rng.integers(0, len(genuine), size=len(genuine))]
        i = impostor[rng.integers(0, len(impostor), size=len(impostor))]
        vals.append(float(metric_fn(g, i)))
    lo = float(np.percentile(vals, 2.5))
    hi = float(np.percentile(vals, 97.5))
    return lo, hi


def save_curve_csv(path: str, thresholds, fars, frrs):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["threshold", "far", "frr"])
        for t, fa, fr in zip(thresholds, fars, frrs):
            writer.writerow([float(t), float(fa), float(fr)])


def save_plots(out_dir: str, dev_genuine, dev_impostor, test_genuine, test_impostor, thr):
    plt.figure(figsize=(10, 5))
    plt.hist(test_genuine, bins=80, alpha=0.6, label="Genuine (test)", density=True)
    plt.hist(test_impostor, bins=80, alpha=0.6, label="Impostor (test)", density=True)
    plt.axvline(thr, color="black", linestyle="--", label=f"Tuned threshold {thr:.4f}")
    plt.xlabel("Distance score")
    plt.ylabel("Density")
    plt.title("Test Score Distribution (threshold tuned on xv)")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "score_histogram.png"), dpi=150)
    plt.close()

    _, _, _, _, dev_t, dev_far, dev_frr = compute_eer(dev_genuine, dev_impostor)
    _, _, _, _, tst_t, tst_far, tst_frr = compute_eer(test_genuine, test_impostor)

    plt.figure(figsize=(10, 5))
    plt.plot(dev_t, dev_far, label="FAR (xv)")
    plt.plot(dev_t, dev_frr, label="FRR (xv)")
    plt.plot(tst_t, tst_far, label="FAR (xe)", alpha=0.8)
    plt.plot(tst_t, tst_frr, label="FRR (xe)", alpha=0.8)
    plt.axvline(thr, color="black", linestyle="--", label=f"Tuned threshold {thr:.4f}")
    plt.xlabel("Threshold")
    plt.ylabel("Rate")
    plt.title("FAR/FRR Curves")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "far_frr_curve.png"), dpi=150)
    plt.close()


def save_per_user_eer(path: str, rows: List[Dict]):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["user_id", "eer", "genuine_n", "impostor_n"])
        writer.writeheader()
        writer.writerows(rows)


def main():
    args = parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    rng = np.random.default_rng(args.seed)

    print("=" * 72)
    print("HARDENED BIOMETRIC EVALUATION")
    print("=" * 72)
    print(f"[Config] dataset={args.dataset}")
    print(f"[Config] seed={args.seed}")
    print(f"[Config] gallery_size={args.gallery_size}")
    print(f"[Config] impostors_per_user={args.impostors_per_user}")
    print(f"[Config] checkpoint={args.checkpoint}")

    xv, xe, sequence_length, input_features = load_dataset(
        args.dataset, rng, args.max_users_xv, args.max_users_xe
    )
    print(f"[Data] xv users={len(xv)} xe users={len(xe)} shape=({sequence_length}, {input_features})")

    model = load_model(sequence_length, input_features, args.checkpoint)
    print("[Model] Loaded trained checkpoint successfully.")

    print("[Embeddings] Computing xv embeddings...")
    xv_emb = compute_embeddings(model, xv)
    print("[Embeddings] Computing xe embeddings...")
    xe_emb = compute_embeddings(model, xe)

    print("[Scoring] Building dev (xv) score distributions...")
    xv_genuine, xv_impostor, xv_per_user, xv_valid_users = build_scores(
        xv_emb, args.gallery_size, args.impostors_per_user, args.max_genuine_queries_per_user, rng
    )
    print("[Scoring] Building test (xe) score distributions...")
    xe_genuine, xe_impostor, xe_per_user, xe_valid_users = build_scores(
        xe_emb, args.gallery_size, args.impostors_per_user, args.max_genuine_queries_per_user, rng
    )

    tune_thr, tune_eer, tune_far, tune_frr, tune_thresholds, tune_fars, tune_frrs = compute_eer(
        xv_genuine, xv_impostor
    )

    test_far_at_tune, test_frr_at_tune, test_hter_at_tune, test_tar_at_tune = operating_point(
        xe_genuine, xe_impostor, tune_thr
    )
    test_eer_thr, test_eer, test_far_at_eer, test_frr_at_eer, _, _, _ = compute_eer(
        xe_genuine, xe_impostor
    )

    eer_ci = bootstrap_ci(
        lambda g, i: compute_eer(g, i)[1], xe_genuine, xe_impostor, args.bootstrap_iters, args.seed + 17
    )
    far_ci = bootstrap_ci(
        lambda g, i: operating_point(g, i, tune_thr)[0],
        xe_genuine,
        xe_impostor,
        args.bootstrap_iters,
        args.seed + 23,
    )
    frr_ci = bootstrap_ci(
        lambda g, i: operating_point(g, i, tune_thr)[1],
        xe_genuine,
        xe_impostor,
        args.bootstrap_iters,
        args.seed + 31,
    )

    os.makedirs(args.output_dir, exist_ok=True)
    save_curve_csv(os.path.join(args.output_dir, "threshold_curve.csv"), tune_thresholds, tune_fars, tune_frrs)
    save_per_user_eer(os.path.join(args.output_dir, "per_user_eer.csv"), xe_per_user)
    save_plots(args.output_dir, xv_genuine, xv_impostor, xe_genuine, xe_impostor, tune_thr)

    metrics = {
        "dataset": args.dataset,
        "seed": args.seed,
        "gallery_size": args.gallery_size,
        "impostors_per_user": args.impostors_per_user,
        "max_genuine_queries_per_user": args.max_genuine_queries_per_user,
        "checkpoint": args.checkpoint,
        "sequence_length": int(sequence_length),
        "input_features": int(input_features),
        "xv_users_total": len(xv),
        "xe_users_total": len(xe),
        "xv_users_used_for_scoring": xv_valid_users,
        "xe_users_used_for_scoring": xe_valid_users,
        "xv_scores": {"genuine": int(len(xv_genuine)), "impostor": int(len(xv_impostor))},
        "xe_scores": {"genuine": int(len(xe_genuine)), "impostor": int(len(xe_impostor))},
        "threshold_tuned_on_xv": tune_thr,
        "xv_eer": tune_eer,
        "xv_far_at_xv_eer_thr": tune_far,
        "xv_frr_at_xv_eer_thr": tune_frr,
        "xe_far_at_tuned_thr": test_far_at_tune,
        "xe_frr_at_tuned_thr": test_frr_at_tune,
        "xe_hter_at_tuned_thr": test_hter_at_tune,
        "xe_tar_at_tuned_thr": test_tar_at_tune,
        "xe_eer": test_eer,
        "xe_eer_threshold": test_eer_thr,
        "xe_far_at_xe_eer_thr": test_far_at_eer,
        "xe_frr_at_xe_eer_thr": test_frr_at_eer,
        "xe_eer_95ci": eer_ci,
        "xe_far_at_tuned_thr_95ci": far_ci,
        "xe_frr_at_tuned_thr_95ci": frr_ci,
        "bootstrap_iterations": args.bootstrap_iters,
    }

    threshold_artifact = {
        "source": "evaluate_hardened.py",
        "dataset": args.dataset,
        "checkpoint": args.checkpoint,
        "seed": args.seed,
        "threshold_tuned_on": "xv",
        "reported_on": "xe",
        "distance_metric": "mean_l2_distance_gallery_query",
        "threshold": tune_thr,
        "sequence_length": int(sequence_length),
        "input_features": int(input_features),
    }

    txt_path = os.path.join(args.output_dir, "hardened_metrics.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("HARDENED BIOMETRIC EVALUATION REPORT\n")
        f.write("=" * 72 + "\n\n")
        f.write(f"Dataset: {args.dataset}\n")
        f.write(f"Checkpoint: {args.checkpoint}\n")
        f.write(f"Seed: {args.seed}\n")
        f.write(f"Gallery size: {args.gallery_size}\n")
        f.write(f"Impostors per user: {args.impostors_per_user}\n\n")
        f.write(f"Max genuine queries per user: {args.max_genuine_queries_per_user}\n\n")
        f.write("Protocol:\n")
        f.write("  - Threshold tuned on validation users (xv)\n")
        f.write("  - Final metrics reported on held-out test users (xe)\n")
        f.write("  - No synthetic LLM data used in this script\n\n")
        f.write(f"Tuned threshold (xv EER): {tune_thr:.6f}\n")
        f.write(f"xv EER: {100.0 * tune_eer:.4f}%\n")
        f.write(f"xe FAR @ tuned thr: {100.0 * test_far_at_tune:.4f}%\n")
        f.write(f"xe FRR @ tuned thr: {100.0 * test_frr_at_tune:.4f}%\n")
        f.write(f"xe HTER @ tuned thr: {100.0 * test_hter_at_tune:.4f}%\n")
        f.write(f"xe TAR @ tuned thr: {100.0 * test_tar_at_tune:.4f}%\n")
        f.write(f"xe EER (independent): {100.0 * test_eer:.4f}%\n")
        if eer_ci is not None:
            f.write(f"xe EER 95% CI: [{100.0 * eer_ci[0]:.4f}%, {100.0 * eer_ci[1]:.4f}%]\n")
        if far_ci is not None:
            f.write(
                f"xe FAR @ tuned thr 95% CI: [{100.0 * far_ci[0]:.4f}%, {100.0 * far_ci[1]:.4f}%]\n"
            )
        if frr_ci is not None:
            f.write(
                f"xe FRR @ tuned thr 95% CI: [{100.0 * frr_ci[0]:.4f}%, {100.0 * frr_ci[1]:.4f}%]\n"
            )

    with open(os.path.join(args.output_dir, "hardened_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(args.output_dir, "threshold_artifact.json"), "w", encoding="utf-8") as f:
        json.dump(threshold_artifact, f, indent=2)

    print("=" * 72)
    print("HARDENED RESULTS")
    print("=" * 72)
    print(f"Tuned threshold (xv): {tune_thr:.6f}")
    print(f"xv EER: {100.0 * tune_eer:.4f}%")
    print(f"xe FAR @ tuned thr: {100.0 * test_far_at_tune:.4f}%")
    print(f"xe FRR @ tuned thr: {100.0 * test_frr_at_tune:.4f}%")
    print(f"xe HTER @ tuned thr: {100.0 * test_hter_at_tune:.4f}%")
    print(f"xe EER (independent): {100.0 * test_eer:.4f}%")
    if eer_ci is not None:
        print(f"xe EER 95% CI: [{100.0 * eer_ci[0]:.4f}%, {100.0 * eer_ci[1]:.4f}%]")
    print(f"Saved artifacts to: {args.output_dir}")


if __name__ == "__main__":
    main()
