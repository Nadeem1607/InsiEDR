"""
select_final_policy.py
======================
Select final continuous-auth policy using fixed ordered criteria:
1) false_alarm_before_attack_rate (lower)
2) attack_accept_rate (impostor, lower)
3) mean_detection_delay_steps (lower)
4) pre_attack_reject_rate (lower)
5) xe_eer (lower, from hardened metrics)

Selection is done per (warmup_steps, attack_steps) on impostor rows, then the
best pair is chosen globally. CI-overlap checks are used to decide whether a
"better" claim is defensible; otherwise the output marks "comparable_tradeoff".
"""

import argparse
import json
import os
from typing import Dict, List, Optional, Tuple


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Select final policy from ablation summary.")
    p.add_argument("--ablation-json", default="results_continuous/ablations/ablation_summary.json")
    p.add_argument("--hardened-json", default="results_hardened/hardened_metrics.json")
    p.add_argument("--output-dir", default="results_continuous/final_selection")
    return p.parse_args()


def ci_overlap(a: Optional[List[float]], b: Optional[List[float]]) -> bool:
    if a is None or b is None or len(a) != 2 or len(b) != 2:
        return True
    lo = max(float(a[0]), float(b[0]))
    hi = min(float(a[1]), float(b[1]))
    return lo <= hi


def rank_tuple(row: Dict, xe_eer: float) -> Tuple[float, float, float, float, float]:
    return (
        float(row.get("false_alarm_before_attack_rate", 1.0)),
        float(row.get("attack_accept_rate", 1.0)),
        float(row.get("mean_detection_delay_steps", 1e9) or 1e9),
        float(row.get("pre_attack_reject_rate", 1.0)),
        float(xe_eer),
    )


def main():
    args = parse_args()
    if not os.path.exists(args.ablation_json):
        raise FileNotFoundError(f"Missing ablation summary: {args.ablation_json}")
    if not os.path.exists(args.hardened_json):
        raise FileNotFoundError(f"Missing hardened metrics: {args.hardened_json}")

    with open(args.ablation_json, "r", encoding="utf-8") as f:
        abl = json.load(f)
    with open(args.hardened_json, "r", encoding="utf-8") as f:
        hard = json.load(f)

    xe_eer = float(hard.get("xe_eer", 1.0))
    rows = abl.get("rows", [])
    imp_rows = [
        r for r in rows
        if r.get("attack_type") == "impostor" and str(r.get("policy", "")).startswith(("B", "P"))
    ]
    if not imp_rows:
        raise ValueError("No impostor rows found in ablation summary.")

    # Group by session setting then choose best per setting.
    grouped: Dict[Tuple[int, int], List[Dict]] = {}
    for r in imp_rows:
        key = (int(r.get("warmup_steps", 0)), int(r.get("attack_steps", 0)))
        grouped.setdefault(key, []).append(r)

    per_setting_best = []
    for key, vals in grouped.items():
        best = sorted(vals, key=lambda x: rank_tuple(x, xe_eer))[0]
        per_setting_best.append(best)

    global_best = sorted(per_setting_best, key=lambda x: rank_tuple(x, xe_eer))[0]

    # Compare against strongest baseline (best non-P policy at same setting).
    same_setting = [
        r for r in grouped[(int(global_best["warmup_steps"]), int(global_best["attack_steps"]))]
    ]
    baseline = sorted(
        [r for r in same_setting if not str(r.get("policy", "")).startswith("P")],
        key=lambda x: rank_tuple(x, xe_eer),
    )[0]

    fa_ci_b = global_best.get("false_alarm_before_attack_rate_95ci")
    fa_ci_a = baseline.get("false_alarm_before_attack_rate_95ci")
    aa_ci_b = global_best.get("attack_accept_rate_95ci")
    aa_ci_a = baseline.get("attack_accept_rate_95ci")

    strict_better = (
        float(global_best.get("false_alarm_before_attack_rate", 1.0))
        < float(baseline.get("false_alarm_before_attack_rate", 1.0))
        and float(global_best.get("attack_accept_rate", 1.0))
        < float(baseline.get("attack_accept_rate", 1.0))
        and not ci_overlap(fa_ci_b, fa_ci_a)
        and not ci_overlap(aa_ci_b, aa_ci_a)
    )

    claim = "better" if strict_better else "comparable_tradeoff"

    out = {
        "dataset": abl.get("dataset"),
        "xe_eer": xe_eer,
        "selection_rule": [
            "false_alarm_before_attack_rate",
            "attack_accept_rate",
            "mean_detection_delay_steps",
            "pre_attack_reject_rate",
            "xe_eer",
        ],
        "selected_policy": global_best,
        "reference_baseline_same_setting": baseline,
        "claim_wording": claim,
    }

    os.makedirs(args.output_dir, exist_ok=True)
    out_json = os.path.join(args.output_dir, "policy_selection.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    out_txt = os.path.join(args.output_dir, "policy_selection.txt")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("FINAL POLICY SELECTION\n")
        f.write("======================\n")
        f.write(f"Claim wording: {claim}\n")
        f.write(f"Selected policy: {global_best.get('policy')}\n")
        f.write(
            f"Session setting: warmup={global_best.get('warmup_steps')} attack={global_best.get('attack_steps')}\n"
        )
        f.write(f"Selected row: {json.dumps(global_best)}\n")
        f.write(f"Baseline row: {json.dumps(baseline)}\n")
    print(f"Saved: {out_json}")
    print(f"Saved: {out_txt}")


if __name__ == "__main__":
    main()
