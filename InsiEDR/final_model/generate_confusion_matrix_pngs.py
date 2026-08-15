"""
Converts all confusion matrix CSV files inside confusion_matrices/ subfolders
into clean PNG heatmap images saved in the same folder.
"""

import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confusion_matrices")

TITLE_MAP = {
    "logon_if_confusion_matrix.csv":              "Logon Domain — Isolation Forest",
    "file_if_confusion_matrix.csv":               "File Domain — Isolation Forest",
    "device_if_confusion_matrix.csv":             "Device Domain — Isolation Forest",
    "http_if_confusion_matrix.csv":               "HTTP Domain — Isolation Forest",
    "overall_if_confusion_matrix.csv":            "Overall — Isolation Forest",
    "xgboost_multiclass_confusion_matrix.csv":    "XGBoost — Multiclass Scenario Classification",
    "xgboost_binary_confusion_matrix.csv":        "XGBoost — Binary (Insider vs Normal)",
    "redrvfl_user_confusion_matrix.csv":          "RedRVFL — User-Level Classification",
    "overall_user_confusion_matrix.csv":          "Overall Pipeline — User-Level Classification",
}


def clean_labels(labels):
    return [
        str(l)
        .replace("Predicted_", "")
        .replace("Pred_", "")
        .replace("Actual_", "")
        .replace("_", " ")
        .strip()
        for l in labels
    ]


def plot_confusion_matrix(csv_path, title, out_path):
    df = pd.read_csv(csv_path, index_col=0)
    df.index   = clean_labels(df.index.tolist())
    df.columns = clean_labels(df.columns.tolist())

    data = df.values.astype(float)
    n_rows, n_cols = data.shape

    row_sums = data.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1
    norm_data = data / row_sums

    figsize = (max(6, n_cols * 1.7), max(4.5, n_rows * 1.5))
    fig, ax = plt.subplots(figsize=figsize, dpi=150)
    fig.patch.set_facecolor("#0f0f1a")
    ax.set_facecolor("#0f0f1a")

    annots = []
    for i in range(n_rows):
        row_annots = []
        for j in range(n_cols):
            raw = int(data[i, j])
            pct = norm_data[i, j] * 100
            row_annots.append(f"{raw}\n({pct:.1f}%)")
        annots.append(row_annots)

    annot_arr = np.array(annots)
    font_size = 9 if n_cols <= 4 else 7.5

    sns.heatmap(
        norm_data,
        annot=annot_arr,
        fmt="",
        cmap=sns.color_palette("Blues", as_cmap=True),
        linewidths=0.6,
        linecolor="#1e1e2e",
        ax=ax,
        vmin=0, vmax=1,
        cbar_kws={"shrink": 0.8},
        xticklabels=df.columns.tolist(),
        yticklabels=df.index.tolist(),
        annot_kws={"size": font_size, "color": "white", "weight": "bold"},
    )

    for i in range(min(n_rows, n_cols)):
        ax.add_patch(plt.Rectangle((i, i), 1, 1, fill=False, edgecolor="#00e5ff", lw=2))

    ax.set_title(title, color="white", fontsize=13, fontweight="bold", pad=14)
    ax.set_xlabel("Predicted Label", color="#aaaacc", fontsize=10, labelpad=8)
    ax.set_ylabel("Actual Label",    color="#aaaacc", fontsize=10, labelpad=8)
    ax.tick_params(colors="#ccccee", labelsize=8.5)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", color="#ccccee")
    plt.setp(ax.get_yticklabels(), rotation=0,  color="#ccccee")

    cbar = ax.collections[0].colorbar
    plt.setp(plt.getp(cbar.ax.axes, "yticklabels"), color="#aaaacc", fontsize=8)
    cbar.set_label("Row-Normalised Proportion", color="#aaaacc", fontsize=8)

    plt.tight_layout(pad=1.5)
    plt.savefig(out_path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Saved: {out_path}")


def main():
    generated = 0
    skipped   = 0
    for subfolder in sorted(os.listdir(BASE_DIR)):
        folder_path = os.path.join(BASE_DIR, subfolder)
        if not os.path.isdir(folder_path):
            continue
        print(f"\n[{subfolder}]")
        for fname in sorted(os.listdir(folder_path)):
            if not fname.endswith(".csv"):
                continue
            csv_path = os.path.join(folder_path, fname)
            out_path = os.path.join(folder_path, fname.replace(".csv", ".png"))
            title    = TITLE_MAP.get(fname, fname.replace("_", " ").replace(".csv", "").title())
            print(f"  Processing: {fname}")
            try:
                plot_confusion_matrix(csv_path, title, out_path)
                generated += 1
            except Exception as e:
                print(f"  ERROR: {e}")
                skipped += 1

    print(f"\nDone. {generated} PNGs generated, {skipped} skipped.")


if __name__ == "__main__":
    main()
