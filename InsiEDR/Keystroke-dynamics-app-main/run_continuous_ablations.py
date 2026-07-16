"""
run_continuous_ablations.py
===========================
Run mandatory continuous-auth ablations and multi-seed robustness summary.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run continuous-auth ablations across seeds.")
    p.add_argument("dataset", help="Dataset folder name under datasets/<name>/npy/")
    p.add_argument("--checkpoint", default="model/checkpoint.weights.h5")
    p.add_argument("--output-dir", default="results_continuous/ablations")
    p.add_argument("--python-bin", default=sys.executable)
    p.add_argument("--seeds", default="42,43,44,45", help="Comma separated seeds")
    p.add_argument("--hardened-json", default="results_hardened/hardened_metrics.json")

    p.add_argument("--max-users-xv", type=int, default=1000)
    p.add_argument("--max-users-xe", type=int, default=2000)
    p.add_argument("--sessions-per-user", type=int, default=1)
    p.add_argument(
        "--session-settings",
        default="40:80,80:160",
        help="Comma separated warmup:attack pairs, e.g. 40:80,80:160",
    )
    p.add_argument("--llm-pool-size", type=int, default=5000)
    p.add_argument("--bootstrap-iters", type=int, default=1000)
    p.add_argument("--llm-threshold", type=float, default=0.35)
    p.add_argument("--llm-assisted-npy", default=None)
    p.add_argument("--llm-assisted-max-samples", type=int, default=5000)

    p.add_argument("--include-sensitivity", action="store_true", help="Add decision-window/alarm policy grid")
    p.add_argument("--skip-existing", action="store_true", help="Skip runs where metrics JSON already exists")
    p.add_argument("--continue-on-error", action="store_true", help="Continue other runs if one eval fails")
    return p.parse_args()


def parse_seeds(raw: str) -> List[int]:
    out = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        out.append(int(token))
    if not out:
        raise ValueError("No valid seeds provided.")
    return out


def parse_session_settings(raw: str) -> List[Dict[str, int]]:
    out = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" not in token:
            raise ValueError(f"Invalid session setting '{token}'. Expected warmup:attack")
        warmup_str, attack_str = token.split(":", 1)
        warmup = int(warmup_str.strip())
        attack = int(attack_str.strip())
        if warmup <= 0 or attack <= 0:
            raise ValueError(f"Session settings must be > 0. Got {token}")
        out.append({"warmup_steps": warmup, "attack_steps": attack})
    if not out:
        raise ValueError("No valid --session-settings values provided.")
    return out


def policies(args: argparse.Namespace) -> Dict[str, Dict]:
    pol = {
        "B1_cont_no_smoothing": {
            "decision_window": 1,
            "alarm_consecutive": 3,
            "disable_llm_gate": False,
            "disable_biometric_gate": False,
        },
        "B2_biometric_only": {
            "decision_window": 5,
            "alarm_consecutive": 3,
            "disable_llm_gate": True,
            "disable_biometric_gate": False,
        },
        "B3_llm_only": {
            "decision_window": 5,
            "alarm_consecutive": 3,
            "disable_llm_gate": False,
            "disable_biometric_gate": True,
        },
        "P_cont_llm_proposed": {
            "decision_window": 5,
            "alarm_consecutive": 3,
            "disable_llm_gate": False,
            "disable_biometric_gate": False,
        },
    }

    if args.include_sensitivity:
        for w in [1, 3, 5, 7]:
            for a in [1, 2, 3, 4]:
                name = f"SENS_w{w}_a{a}"
                pol[name] = {
                    "decision_window": w,
                    "alarm_consecutive": a,
                    "disable_llm_gate": False,
                    "disable_biometric_gate": False,
                }
    return pol


def run_eval(
    args: argparse.Namespace,
    policy_name: str,
    policy_cfg: Dict,
    seed: int,
    out_dir: str,
    warmup_steps: int,
    attack_steps: int,
):
    cmd = [
        args.python_bin,
        os.path.join(SCRIPT_DIR, "evaluate_continuous.py"),
        args.dataset,
        "--checkpoint",
        args.checkpoint,
        "--output-dir",
        out_dir,
        "--seed",
        str(seed),
        "--max-users-xv",
        str(args.max_users_xv),
        "--max-users-xe",
        str(args.max_users_xe),
        "--sessions-per-user",
        str(args.sessions_per_user),
        "--warmup-steps",
        str(warmup_steps),
        "--attack-steps",
        str(attack_steps),
        "--decision-window",
        str(policy_cfg["decision_window"]),
        "--alarm-consecutive",
        str(policy_cfg["alarm_consecutive"]),
        "--llm-pool-size",
        str(args.llm_pool_size),
        "--llm-threshold",
        str(args.llm_threshold),
        "--bootstrap-iters",
        str(args.bootstrap_iters),
    ]
    if args.llm_assisted_npy:
        cmd.extend(
            [
                "--llm-assisted-npy",
                args.llm_assisted_npy,
                "--llm-assisted-max-samples",
                str(args.llm_assisted_max_samples),
            ]
        )
    if policy_cfg.get("disable_llm_gate", False):
        cmd.append("--disable-llm-gate")
    if policy_cfg.get("disable_biometric_gate", False):
        cmd.append("--disable-biometric-gate")

    print(f"[Ablation] Running {policy_name} seed={seed}")
    subprocess.run(cmd, check=True, cwd=SCRIPT_DIR)


def read_metrics(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def mean_ci(values: List[float]):
    if len(values) == 0:
        return None, None
    arr = np.array(values, dtype=np.float64)
    mean = float(np.mean(arr))
    if len(arr) == 1:
        return mean, [mean, mean]
    std = float(np.std(arr, ddof=1))
    margin = 1.96 * std / np.sqrt(len(arr))
    return mean, [float(mean - margin), float(mean + margin)]


def aggregate(rows: List[Dict]):
    grouped = {}
    for r in rows:
        key = (r["policy"], r["attack_type"], r["warmup_steps"], r["attack_steps"])
        grouped.setdefault(key, []).append(r)

    out = []
    for (policy, attack_type, warmup_steps, attack_steps), items in grouped.items():
        metric_names = [
            "detection_rate",
            "false_alarm_before_attack_rate",
            "pre_attack_reject_rate",
            "attack_accept_rate",
            "attack_block_rate",
            "llm_block_rate",
            "mean_detection_delay_steps",
        ]
        agg = {
            "policy": policy,
            "attack_type": attack_type,
            "warmup_steps": warmup_steps,
            "attack_steps": attack_steps,
            "runs": len(items),
        }
        for m in metric_names:
            vals = [float(it[m]) for it in items if it[m] is not None]
            mean, ci = mean_ci(vals)
            agg[m] = mean
            agg[f"{m}_95ci"] = ci
        out.append(agg)
    return out


def save_tradeoff_plot(path: str, agg_rows: List[Dict]):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
    for ax_idx, attack_type in enumerate(["impostor", "llm"]):
        ax = axes[ax_idx]
        pts = [r for r in agg_rows if r["attack_type"] == attack_type]
        for p in pts:
            x = p["false_alarm_before_attack_rate"]
            y = p["detection_rate"]
            if x is None or y is None:
                continue
            ax.scatter(x, y, s=60)
            ax.text(x, y, f"{p['policy']}@{p['warmup_steps']}:{p['attack_steps']}", fontsize=7)
        ax.set_xlabel("False alarm before attack rate")
        ax.set_ylabel("Detection rate")
        ax.set_title(f"Policy Tradeoff ({attack_type})")
        ax.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def main():
    args = parse_args()
    seeds = parse_seeds(args.seeds)
    session_settings = parse_session_settings(args.session_settings)
    policy_map = policies(args)

    os.makedirs(args.output_dir, exist_ok=True)
    run_rows = []

    for sess in session_settings:
        warmup_steps = sess["warmup_steps"]
        attack_steps = sess["attack_steps"]
        for policy_name, policy_cfg in policy_map.items():
            for seed in seeds:
                run_dir = os.path.join(
                    args.output_dir,
                    f"warmup_{warmup_steps}_attack_{attack_steps}",
                    policy_name,
                    f"seed_{seed}",
                )
                metrics_path = os.path.join(run_dir, "continuous_metrics.json")
                if args.skip_existing and os.path.exists(metrics_path):
                    print(f"[Ablation] Skipping existing {metrics_path}")
                else:
                    os.makedirs(run_dir, exist_ok=True)
                    try:
                        run_eval(args, policy_name, policy_cfg, seed, run_dir, warmup_steps, attack_steps)
                    except subprocess.CalledProcessError as e:
                        if args.continue_on_error:
                            print(f"[Ablation] ERROR (continuing): {policy_name} seed={seed} rc={e.returncode}")
                            continue
                        raise

                if not os.path.exists(metrics_path):
                    print(f"[Ablation] WARN: missing metrics after run: {metrics_path}")
                    continue
                m = read_metrics(metrics_path)
                imp = m.get("continuous_impostor", {})
                llm = m.get("continuous_llm", {})
                run_rows.append(
                    {
                        "policy": policy_name,
                        "seed": seed,
                        "attack_type": "impostor",
                        "warmup_steps": warmup_steps,
                        "attack_steps": attack_steps,
                        "decision_window": m["protocol"]["decision_window"],
                        "alarm_consecutive": m["protocol"]["alarm_consecutive"],
                        "use_llm_gate": m["protocol"]["use_llm_gate"],
                        "use_biometric_gate": m["protocol"]["use_biometric_gate"],
                        "detection_rate": imp.get("detection_rate"),
                        "false_alarm_before_attack_rate": imp.get("false_alarm_before_attack_rate"),
                        "pre_attack_reject_rate": imp.get("pre_attack_reject_rate"),
                        "attack_accept_rate": imp.get("attack_accept_rate"),
                        "attack_block_rate": imp.get("attack_block_rate"),
                        "llm_block_rate": imp.get("llm_block_rate"),
                        "mean_detection_delay_steps": imp.get("mean_detection_delay_steps"),
                    }
                )
                run_rows.append(
                    {
                        "policy": policy_name,
                        "seed": seed,
                        "attack_type": "llm",
                        "warmup_steps": warmup_steps,
                        "attack_steps": attack_steps,
                        "decision_window": m["protocol"]["decision_window"],
                        "alarm_consecutive": m["protocol"]["alarm_consecutive"],
                        "use_llm_gate": m["protocol"]["use_llm_gate"],
                        "use_biometric_gate": m["protocol"]["use_biometric_gate"],
                        "detection_rate": llm.get("detection_rate"),
                        "false_alarm_before_attack_rate": llm.get("false_alarm_before_attack_rate"),
                        "pre_attack_reject_rate": llm.get("pre_attack_reject_rate"),
                        "attack_accept_rate": llm.get("attack_accept_rate"),
                        "attack_block_rate": llm.get("attack_block_rate"),
                        "llm_block_rate": llm.get("llm_block_rate"),
                        "mean_detection_delay_steps": llm.get("mean_detection_delay_steps"),
                    }
                )

    agg = aggregate(run_rows)

    detail_csv = os.path.join(args.output_dir, "ablation_runs.csv")
    if run_rows:
        with open(detail_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(run_rows[0].keys()))
            writer.writeheader()
            writer.writerows(run_rows)

    b0_hardened = None
    if os.path.exists(args.hardened_json):
        with open(args.hardened_json, "r", encoding="utf-8") as f:
            hard = json.load(f)
        b0_hardened = {
            "xe_eer": hard.get("xe_eer"),
            "xe_far_at_tuned_thr": hard.get("xe_far_at_tuned_thr"),
            "xe_frr_at_tuned_thr": hard.get("xe_frr_at_tuned_thr"),
            "xe_hter_at_tuned_thr": hard.get("xe_hter_at_tuned_thr"),
            "threshold_tuned_on_xv": hard.get("threshold_tuned_on_xv"),
        }

    summary_json = os.path.join(args.output_dir, "ablation_summary.json")
    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "dataset": args.dataset,
                "checkpoint": args.checkpoint,
                "seeds": seeds,
                "session_settings": session_settings,
                "policies": list(policy_map.keys()),
                "static_baseline_B0_hardened": b0_hardened,
                "rows": agg,
            },
            f,
            indent=2,
        )

    summary_csv = os.path.join(args.output_dir, "ablation_summary.csv")
    if agg:
        with open(summary_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(agg[0].keys()))
            writer.writeheader()
            writer.writerows(agg)

    tradeoff_png = os.path.join(args.output_dir, "continuous_policy_tradeoff.png")
    save_tradeoff_plot(tradeoff_png, agg)

    print(f"[Ablation] Saved {detail_csv}")
    print(f"[Ablation] Saved {summary_csv}")
    print(f"[Ablation] Saved {summary_json}")
    print(f"[Ablation] Saved {tradeoff_png}")


if __name__ == "__main__":
    main()
