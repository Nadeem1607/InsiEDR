"""
generate_paper_tables.py
========================
Build paper-facing summary tables from hardened + continuous + ablation outputs.
Outputs CSV and markdown under results_paper/.
"""

import argparse
import csv
import json
import os
from typing import Dict, List


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate paper summary tables.")
    p.add_argument("--hardened-json", default="results_hardened/hardened_metrics.json")
    p.add_argument("--continuous-json", default="results_continuous/continuous_metrics.json")
    p.add_argument("--ablation-json", default="results_continuous/ablations/ablation_summary.json")
    p.add_argument("--selection-json", default="results_continuous/final_selection/policy_selection.json")
    p.add_argument("--output-dir", default="results_paper")
    return p.parse_args()


def write_csv(path: str, rows: List[Dict]):
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def pct(x: float) -> str:
    return f"{100.0 * float(x):.4f}%"


def main():
    args = parse_args()
    for path in [args.hardened_json, args.continuous_json, args.ablation_json]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing required input: {path}")

    with open(args.hardened_json, "r", encoding="utf-8") as f:
        hard = json.load(f)
    with open(args.continuous_json, "r", encoding="utf-8") as f:
        cont = json.load(f)
    with open(args.ablation_json, "r", encoding="utf-8") as f:
        abl = json.load(f)

    sel = None
    if os.path.exists(args.selection_json):
        with open(args.selection_json, "r", encoding="utf-8") as f:
            sel = json.load(f)

    os.makedirs(args.output_dir, exist_ok=True)

    static_rows = [{
        "dataset": hard.get("dataset"),
        "xe_eer": hard.get("xe_eer"),
        "xe_far_at_tuned_thr": hard.get("xe_far_at_tuned_thr"),
        "xe_frr_at_tuned_thr": hard.get("xe_frr_at_tuned_thr"),
        "xe_hter_at_tuned_thr": hard.get("xe_hter_at_tuned_thr"),
        "threshold_tuned_on_xv": hard.get("threshold_tuned_on_xv"),
    }]
    write_csv(os.path.join(args.output_dir, "table_static_metrics.csv"), static_rows)

    impostor = cont.get("continuous_impostor", {})
    llm = cont.get("continuous_llm", {})
    llmd = cont.get("llm_detector", {})
    continuous_rows = [
        {
            "attack_type": "impostor",
            "detection_rate": impostor.get("detection_rate"),
            "false_alarm_before_attack_rate": impostor.get("false_alarm_before_attack_rate"),
            "pre_attack_reject_rate": impostor.get("pre_attack_reject_rate"),
            "attack_accept_rate": impostor.get("attack_accept_rate"),
            "attack_block_rate": impostor.get("attack_block_rate"),
            "mean_detection_delay_steps": impostor.get("mean_detection_delay_steps"),
        },
        {
            "attack_type": "llm",
            "detection_rate": llm.get("detection_rate"),
            "false_alarm_before_attack_rate": llm.get("false_alarm_before_attack_rate"),
            "pre_attack_reject_rate": llm.get("pre_attack_reject_rate"),
            "attack_accept_rate": llm.get("attack_accept_rate"),
            "attack_block_rate": llm.get("attack_block_rate"),
            "mean_detection_delay_steps": llm.get("mean_detection_delay_steps"),
        },
    ]
    write_csv(os.path.join(args.output_dir, "table_continuous_metrics.csv"), continuous_rows)

    llm_rows = [{
        "synthetic_tpr": llmd.get("synthetic_tpr"),
        "human_fpr_estimate": llmd.get("human_fpr_estimate"),
        "external_assisted_loaded": llmd.get("external_assisted_loaded"),
        "external_assisted_flag_rate": llmd.get("external_assisted_flag_rate"),
        "roc_auc_synth_vs_human": llmd.get("roc_auc_synth_vs_human"),
        "decision_threshold": llmd.get("decision_threshold"),
    }]
    write_csv(os.path.join(args.output_dir, "table_llm_validity.csv"), llm_rows)

    ablation_rows = abl.get("rows", [])
    write_csv(os.path.join(args.output_dir, "table_ablation_summary.csv"), ablation_rows)

    md_path = os.path.join(args.output_dir, "paper_tables.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Paper Tables\n\n")
        f.write("## Static (xe)\n")
        s = static_rows[0]
        f.write(
            f"- EER: {pct(s['xe_eer'])}, FAR: {pct(s['xe_far_at_tuned_thr'])}, "
            f"FRR: {pct(s['xe_frr_at_tuned_thr'])}, HTER: {pct(s['xe_hter_at_tuned_thr'])}\n"
        )
        f.write(f"- Threshold tuned on xv: {s['threshold_tuned_on_xv']}\n\n")

        f.write("## Continuous\n")
        for r in continuous_rows:
            f.write(
                f"- {r['attack_type']}: detection={pct(r['detection_rate'])}, "
                f"false_alarm={pct(r['false_alarm_before_attack_rate'])}, "
                f"attack_accept={pct(r['attack_accept_rate'])}, "
                f"delay={r['mean_detection_delay_steps']}\n"
            )
        f.write("\n## LLM Validity\n")
        l = llm_rows[0]
        f.write(
            f"- Synthetic TPR={pct(l['synthetic_tpr'])}, Human FPR={pct(l['human_fpr_estimate'])}, "
            f"External assisted loaded={l['external_assisted_loaded']}, "
            f"External assisted flag rate={l['external_assisted_flag_rate']}\n"
        )
        if sel:
            f.write("\n## Final Policy Selection\n")
            f.write(f"- Claim wording: {sel.get('claim_wording')}\n")
            f.write(f"- Selected policy: {sel.get('selected_policy', {}).get('policy')}\n")

    print(f"Saved tables in: {args.output_dir}")


if __name__ == "__main__":
    main()
