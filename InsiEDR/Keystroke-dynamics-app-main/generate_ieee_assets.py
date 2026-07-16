"""
generate_ieee_assets.py
=======================
Generate IEEE-paper assets (tables + figure bundle) from existing outputs.

Required:
- results_continuous/continuous_metrics.json

Optional:
- results_continuous/continuous_detection_delay.png
- results_continuous/continuous_llm_roc.png
- results_continuous/continuous_llm_calibration.png
- results_continuous/ablations/continuous_policy_tradeoff.png
- results_continuous/continuous_sessions.csv
- results_continuous/ablations/ablation_summary.csv
- results_hardened/hardened_metrics.json
"""

import argparse
import csv
import json
import os
import shutil
from typing import Dict, List, Optional

import numpy as np
from PIL import Image, ImageDraw


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate IEEE-ready figure/table assets.")
    p.add_argument("--continuous-dir", default="results_continuous")
    p.add_argument("--ablation-csv", default="results_continuous/ablations/ablation_summary.csv")
    p.add_argument("--hardened-json", default="results_hardened/hardened_metrics.json")
    p.add_argument("--output-dir", default="results_ieee")
    return p.parse_args()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_json(path: str) -> Optional[Dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_csv(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: str, rows: List[Dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def pct(x: Optional[float], digits: int = 3) -> str:
    if x is None:
        return "NA"
    return f"{100.0 * float(x):.{digits}f}%"


def maybe_float(x):
    if x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    s = str(x).strip()
    if s == "" or s.lower() == "none":
        return None
    return float(s)


def copy_if_exists(src: str, dst: str) -> bool:
    if not os.path.exists(src):
        return False
    ensure_dir(os.path.dirname(dst))
    shutil.copyfile(src, dst)
    return True


def find_row(rows: List[Dict], policy: str, attack_type: str, warmup: int, attack: int) -> Optional[Dict]:
    for r in rows:
        if (
            str(r.get("policy")) == policy
            and str(r.get("attack_type")) == attack_type
            and int(float(r.get("warmup_steps", 0))) == warmup
            and int(float(r.get("attack_steps", 0))) == attack
        ):
            return r
    return None


def save_placeholder_system(path: str) -> None:
    img = Image.new("RGB", (1800, 950), "white")
    d = ImageDraw.Draw(img)
    boxes = [
        (80, 200, 450, 420, "Input Stream"),
        (620, 200, 990, 420, "Type2Branch\nEmbedding"),
        (1160, 200, 1530, 420, "Biometric Gate"),
        (620, 560, 990, 780, "LLM-Aware Gate"),
        (1160, 560, 1530, 780, "Alarm Logic"),
    ]
    for x1, y1, x2, y2, t in boxes:
        d.rectangle((x1, y1, x2, y2), outline="black", width=4)
        d.text((x1 + 35, y1 + 75), t, fill="black")
    d.line((450, 310, 620, 310), fill="black", width=4)
    d.line((990, 310, 1160, 310), fill="black", width=4)
    d.line((990, 670, 1160, 670), fill="black", width=4)
    d.line((805, 420, 805, 560), fill="black", width=4)
    d.text((60, 40), "System Overview Placeholder (Replace with final vector figure)", fill="black")
    img.save(path, "PNG")


def save_placeholder_timeline(path: str) -> None:
    img = Image.new("RGB", (1800, 540), "white")
    d = ImageDraw.Draw(img)
    x0 = 120
    x1 = 760
    x2 = 1620
    y1 = 190
    y2 = 350
    d.rectangle((x0, y1, x1, y2), fill=(220, 235, 250), outline="black", width=3)
    d.rectangle((x1, y1, x2, y2), fill=(250, 220, 220), outline="black", width=3)
    d.line((x1, 120, x1, 410), fill="black", width=3)
    d.text((260, 240), "Warmup (Genuine)", fill="black")
    d.text((980, 240), "Attack Window (Impostor / LLM)", fill="black")
    d.text((x1 - 30, 90), "Switch", fill="black")
    d.text((70, 30), "Protocol Timeline Placeholder (40:80 example)", fill="black")
    img.save(path, "PNG")


def draw_axes(draw: ImageDraw.ImageDraw, w: int, h: int):
    left = int(0.12 * w)
    right = int(0.95 * w)
    top = int(0.10 * h)
    bottom = int(0.88 * h)
    draw.line((left, bottom, right, bottom), fill="black", width=3)
    draw.line((left, top, left, bottom), fill="black", width=3)
    return left, right, top, bottom


def save_delay_cdf_png(sessions_csv: str, out_png: str) -> bool:
    rows = read_csv(sessions_csv)
    if not rows:
        return False

    imp = []
    llm = []
    for r in rows:
        det = int(float(r.get("detected", 0)))
        delay = maybe_float(r.get("detection_delay_steps"))
        if det != 1 or delay is None or delay < 0:
            continue
        if r.get("attack_type") == "impostor":
            imp.append(delay)
        elif r.get("attack_type") == "llm":
            llm.append(delay)
    if not imp and not llm:
        return False

    all_vals = imp + llm
    x_min = min(all_vals)
    x_max = max(all_vals)
    if x_max <= x_min:
        x_max = x_min + 1.0

    img = Image.new("RGB", (1600, 1000), "white")
    d = ImageDraw.Draw(img)
    left, right, top, bottom = draw_axes(d, 1600, 1000)

    def draw_curve(values: List[float], color: tuple):
        if not values:
            return
        arr = np.sort(np.array(values, dtype=np.float64))
        y = np.arange(1, len(arr) + 1) / len(arr)
        pts = []
        for xv, yv in zip(arr, y):
            px = left + int((xv - x_min) / (x_max - x_min) * (right - left))
            py = bottom - int(yv * (bottom - top))
            pts.append((px, py))
        if len(pts) > 1:
            d.line(pts, fill=color, width=4)

    draw_curve(imp, (30, 90, 200))
    draw_curve(llm, (190, 60, 60))
    d.text((560, 25), "Detection Delay Distribution (CDF)", fill="black")
    d.text((680, 925), "Delay (steps)", fill="black")
    d.text((65, 95), "CDF", fill="black")
    d.rectangle((1100, 90, 1500, 180), outline="black", width=2)
    d.line((1130, 120, 1220, 120), fill=(30, 90, 200), width=4)
    d.text((1240, 108), "Impostor", fill="black")
    d.line((1130, 155, 1220, 155), fill=(190, 60, 60), width=4)
    d.text((1240, 143), "LLM", fill="black")
    img.save(out_png, "PNG")
    return True


def save_tradeoff_png(ablation_rows: List[Dict], attack_type: str, out_png: str) -> bool:
    pts = []
    for r in ablation_rows:
        if r.get("attack_type") != attack_type:
            continue
        x = maybe_float(r.get("false_alarm_before_attack_rate"))
        y = maybe_float(r.get("detection_rate"))
        if x is None or y is None:
            continue
        label = f"{r.get('policy')}@{r.get('warmup_steps')}:{r.get('attack_steps')}"
        pts.append((x, y, label))
    if not pts:
        return False

    x_vals = [p[0] for p in pts]
    y_vals = [p[1] for p in pts]
    x_min, x_max = min(x_vals), max(x_vals)
    y_min, y_max = min(y_vals), max(y_vals)
    if x_max <= x_min:
        x_max = x_min + 1e-6
    if y_max <= y_min:
        y_max = y_min + 1e-6

    img = Image.new("RGB", (1600, 1000), "white")
    d = ImageDraw.Draw(img)
    left, right, top, bottom = draw_axes(d, 1600, 1000)
    d.text((500, 25), f"Policy Tradeoff ({attack_type})", fill="black")
    d.text((520, 925), "False Alarm Before Attack Rate", fill="black")
    d.text((30, 95), "Detection", fill="black")

    for x, y, label in pts:
        px = left + int((x - x_min) / (x_max - x_min) * (right - left))
        py = bottom - int((y - y_min) / (y_max - y_min) * (bottom - top))
        d.ellipse((px - 6, py - 6, px + 6, py + 6), fill=(40, 100, 210), outline="black")
        d.text((px + 8, py - 8), label, fill="black")
    img.save(out_png, "PNG")
    return True


def build_tables(
    continuous_metrics: Dict,
    ablation_rows: List[Dict],
    hardened_metrics: Optional[Dict],
    tables_dir: str,
) -> List[str]:
    written = []

    c_imp = continuous_metrics.get("continuous_impostor", {})
    c_llm = continuous_metrics.get("continuous_llm", {})
    table_i = [
        {
            "Attack Type": "Impostor",
            "Detection Rate": pct(c_imp.get("detection_rate")),
            "False Alarm (Pre-Attack)": pct(c_imp.get("false_alarm_before_attack_rate")),
            "Attack Accept Rate": pct(c_imp.get("attack_accept_rate")),
            "Attack Block Rate": pct(c_imp.get("attack_block_rate")),
            "Mean Delay (steps)": f"{maybe_float(c_imp.get('mean_detection_delay_steps')):.3f}"
            if maybe_float(c_imp.get("mean_detection_delay_steps")) is not None
            else "NA",
        },
        {
            "Attack Type": "LLM",
            "Detection Rate": pct(c_llm.get("detection_rate")),
            "False Alarm (Pre-Attack)": pct(c_llm.get("false_alarm_before_attack_rate")),
            "Attack Accept Rate": pct(c_llm.get("attack_accept_rate")),
            "Attack Block Rate": pct(c_llm.get("attack_block_rate")),
            "Mean Delay (steps)": f"{maybe_float(c_llm.get('mean_detection_delay_steps')):.3f}"
            if maybe_float(c_llm.get("mean_detection_delay_steps")) is not None
            else "NA",
        },
    ]
    p = os.path.join(tables_dir, "TABLE_I_main_continuous.csv")
    write_csv(p, table_i)
    written.append(p)

    llmd = continuous_metrics.get("llm_detector", {})
    table_ii = [
        {
            "Synthetic TPR": pct(llmd.get("synthetic_tpr")),
            "Human FPR Estimate": pct(llmd.get("human_fpr_estimate")),
            "ROC AUC (synthetic vs human)": maybe_float(llmd.get("roc_auc_synth_vs_human")),
            "Decision Threshold": maybe_float(llmd.get("decision_threshold")),
            "External Assisted Loaded": int(llmd.get("external_assisted_loaded", 0)),
            "External Assisted Flag Rate": pct(llmd.get("external_assisted_flag_rate"))
            if llmd.get("external_assisted_flag_rate") is not None
            else "NA",
        }
    ]
    p = os.path.join(tables_dir, "TABLE_II_llm_validity.csv")
    write_csv(p, table_ii)
    written.append(p)

    policies = ["B1_cont_no_smoothing", "B2_biometric_only", "B3_llm_only", "P_cont_llm_proposed"]
    table_iii = []
    for pol in policies:
        imp = find_row(ablation_rows, pol, "impostor", 40, 80)
        llm = find_row(ablation_rows, pol, "llm", 40, 80)
        table_iii.append(
            {
                "Policy": pol,
                "Imp Detection": pct(imp.get("detection_rate")) if imp else "NA",
                "Imp False Alarm": pct(imp.get("false_alarm_before_attack_rate")) if imp else "NA",
                "Imp Delay": f"{maybe_float(imp.get('mean_detection_delay_steps')):.3f}"
                if imp and maybe_float(imp.get("mean_detection_delay_steps")) is not None
                else "NA",
                "LLM Detection": pct(llm.get("detection_rate")) if llm else "NA",
                "LLM Attack Accept": pct(llm.get("attack_accept_rate")) if llm else "NA",
                "LLM Delay": f"{maybe_float(llm.get('mean_detection_delay_steps')):.3f}"
                if llm and maybe_float(llm.get("mean_detection_delay_steps")) is not None
                else "NA",
            }
        )
    p = os.path.join(tables_dir, "TABLE_III_ablation_40_80.csv")
    write_csv(p, table_iii)
    written.append(p)

    table_iv = []
    for warmup, attack in [(40, 80), (80, 160)]:
        imp = find_row(ablation_rows, "P_cont_llm_proposed", "impostor", warmup, attack)
        llm = find_row(ablation_rows, "P_cont_llm_proposed", "llm", warmup, attack)
        table_iv.append(
            {
                "Setting": f"{warmup}:{attack}",
                "Imp Detection": pct(imp.get("detection_rate")) if imp else "NA",
                "Imp Attack Accept": pct(imp.get("attack_accept_rate")) if imp else "NA",
                "Imp Delay": f"{maybe_float(imp.get('mean_detection_delay_steps')):.3f}"
                if imp and maybe_float(imp.get("mean_detection_delay_steps")) is not None
                else "NA",
                "LLM Detection": pct(llm.get("detection_rate")) if llm else "NA",
                "LLM Attack Accept": pct(llm.get("attack_accept_rate")) if llm else "NA",
                "LLM Delay": f"{maybe_float(llm.get('mean_detection_delay_steps')):.3f}"
                if llm and maybe_float(llm.get("mean_detection_delay_steps")) is not None
                else "NA",
            }
        )
    p = os.path.join(tables_dir, "TABLE_IV_session_sensitivity.csv")
    write_csv(p, table_iv)
    written.append(p)

    if hardened_metrics:
        table_v = [
            {
                "xe EER": pct(hardened_metrics.get("xe_eer")),
                "xe FAR@thr": pct(hardened_metrics.get("xe_far_at_tuned_thr")),
                "xe FRR@thr": pct(hardened_metrics.get("xe_frr_at_tuned_thr")),
                "xe HTER@thr": pct(hardened_metrics.get("xe_hter_at_tuned_thr")),
                "Threshold tuned on xv": maybe_float(hardened_metrics.get("threshold_tuned_on_xv")),
            }
        ]
        p = os.path.join(tables_dir, "TABLE_V_static_hardened.csv")
        write_csv(p, table_v)
        written.append(p)

    return written


def write_guide(path: str, figures_written: List[str], tables_written: List[str], hardened_present: bool) -> None:
    rel_fig = [os.path.relpath(p, SCRIPT_DIR) for p in figures_written]
    rel_tab = [os.path.relpath(p, SCRIPT_DIR) for p in tables_written]
    lines = [
        "# IEEE Insertion Guide",
        "",
        "Word formatting targets:",
        "- Font: Times New Roman, 10 pt body.",
        "- Figure font size after scaling: >= 8 pt.",
        "- One-column figure width: 3.5 in.",
        "- Two-column figure width: 7.16 in.",
        "- Image export: 300 dpi min (450+ dpi recommended for line charts).",
        "",
        "## Figures",
    ]
    lines.extend([f"- `{p}`" for p in rel_fig] or ["- None"])
    lines.extend(["", "## Tables"])
    lines.extend([f"- `{p}`" for p in rel_tab] or ["- None"])
    lines.extend(
        [
            "",
            "## Caption Templates",
            "- Fig. 1. System overview of the proposed continuous-authentication framework with biometric and LLM-aware gates.",
            "- Fig. 2. Session timeline with warmup and attack-switch phases.",
            "- Fig. 3. Detection delay distribution for impostor and LLM sessions.",
            "- Fig. 4. ROC of LLM-aware detector (synthetic vs human).",
            "- Fig. 5. Calibration behavior of LLM-aware detector.",
            "- Fig. 6. Detection-vs-false-alarm policy tradeoff.",
            "- Table I. Main continuous authentication metrics.",
            "- Table II. LLM detector validity and calibration metrics.",
            "- Table III. Ablation summary at 40:80 session setting.",
            "- Table IV. Session-length sensitivity for the proposed policy.",
        ]
    )
    if hardened_present:
        lines.append("- Table V. Hardened static verification metrics (xv tuned, xe reported).")
    else:
        lines.extend(
            [
                "",
                "## Note",
                "- `results_hardened/hardened_metrics.json` not found; static Table V was skipped.",
            ]
        )
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    args = parse_args()
    figures_dir = os.path.join(args.output_dir, "figures")
    tables_dir = os.path.join(args.output_dir, "tables")
    ensure_dir(figures_dir)
    ensure_dir(tables_dir)

    continuous_json = os.path.join(args.continuous_dir, "continuous_metrics.json")
    continuous_metrics = read_json(continuous_json)
    if continuous_metrics is None:
        raise FileNotFoundError(f"Missing required file: {continuous_json}")

    ablation_rows = read_csv(args.ablation_csv)
    hardened_metrics = read_json(args.hardened_json)

    figures_written: List[str] = []
    static_figs = [
        ("continuous_detection_delay.png", "FIG_delay_hist.png"),
        ("continuous_llm_roc.png", "FIG_llm_roc.png"),
        ("continuous_llm_calibration.png", "FIG_llm_calibration.png"),
    ]
    for src_name, dst_name in static_figs:
        src = os.path.join(args.continuous_dir, src_name)
        dst = os.path.join(figures_dir, dst_name)
        if copy_if_exists(src, dst):
            figures_written.append(dst)

    src_tradeoff = os.path.join(args.continuous_dir, "ablations", "continuous_policy_tradeoff.png")
    dst_tradeoff = os.path.join(figures_dir, "FIG_policy_tradeoff_combined.png")
    if copy_if_exists(src_tradeoff, dst_tradeoff):
        figures_written.append(dst_tradeoff)

    sessions_csv = os.path.join(args.continuous_dir, "continuous_sessions.csv")
    if save_delay_cdf_png(sessions_csv, os.path.join(figures_dir, "FIG_delay_cdf.png")):
        figures_written.append(os.path.join(figures_dir, "FIG_delay_cdf.png"))

    if save_tradeoff_png(ablation_rows, "impostor", os.path.join(figures_dir, "FIG_policy_tradeoff_impostor.png")):
        figures_written.append(os.path.join(figures_dir, "FIG_policy_tradeoff_impostor.png"))
    if save_tradeoff_png(ablation_rows, "llm", os.path.join(figures_dir, "FIG_policy_tradeoff_llm.png")):
        figures_written.append(os.path.join(figures_dir, "FIG_policy_tradeoff_llm.png"))

    save_placeholder_system(os.path.join(figures_dir, "FIG_system_overview_placeholder.png"))
    figures_written.append(os.path.join(figures_dir, "FIG_system_overview_placeholder.png"))
    save_placeholder_timeline(os.path.join(figures_dir, "FIG_protocol_timeline_placeholder.png"))
    figures_written.append(os.path.join(figures_dir, "FIG_protocol_timeline_placeholder.png"))

    tables_written = build_tables(continuous_metrics, ablation_rows, hardened_metrics, tables_dir)

    guide_path = os.path.join(args.output_dir, "IEEE_INSERTION_GUIDE.md")
    write_guide(guide_path, figures_written, tables_written, hardened_metrics is not None)

    print(f"Saved IEEE assets under: {args.output_dir}")
    print(f"- Figures: {len(figures_written)}")
    print(f"- Tables: {len(tables_written)}")
    print(f"- Guide: {guide_path}")
    if hardened_metrics is None:
        print("[NOTE] Hardened static table skipped: missing hardened_metrics.json")


if __name__ == "__main__":
    main()
