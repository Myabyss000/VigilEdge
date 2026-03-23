import json
from pathlib import Path

import matplotlib.pyplot as plt


def load_summary(path: Path):
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def main():
    root = Path(__file__).resolve().parent
    out_dir = root / "figures"
    ensure_dir(out_dir)

    a = load_summary(root / "benchmark_profile_a_signature_only_summary.json")
    b = load_summary(root / "benchmark_profile_b_waf_plus_soc_rules_summary.json")
    c = load_summary(root / "benchmark_profile_c_summary.json")

    profiles = ["A", "B", "C"]
    data = {
        "A": a,
        "B": b,
        "C": c,
    }

    # Figure 3: Detection quality
    precision = [data[p]["precision"] for p in profiles]
    recall = [data[p]["recall"] for p in profiles]
    f1 = [data[p]["f1"] for p in profiles]
    fpr = [data[p]["false_positive_rate"] for p in profiles]

    x = range(len(profiles))
    w = 0.22

    fig, ax1 = plt.subplots(figsize=(9, 5))
    ax1.bar([i - w for i in x], precision, width=w, label="Precision")
    ax1.bar([i for i in x], recall, width=w, label="Recall")
    ax1.bar([i + w for i in x], f1, width=w, label="F1-score")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(profiles)
    ax1.set_ylim(0, 1.05)
    ax1.set_ylabel("Score")

    ax2 = ax1.twinx()
    ax2.plot(list(x), fpr, marker="o", linewidth=2, color="black", label="FPR")
    ax2.set_ylim(0, 1.05)
    ax2.set_ylabel("False Positive Rate")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="lower left")
    ax1.set_title("Detection Quality by Profile")
    fig.tight_layout()
    fig.savefig(out_dir / "fig3_detection_quality.png", dpi=220)
    plt.close(fig)

    # Figure 4: Runtime tradeoffs
    p50 = [data[p]["p50_ms"] for p in profiles]
    p95 = [data[p]["p95_ms"] for p in profiles]
    throughput = [data[p]["throughput_req_per_sec"] for p in profiles]

    fig, ax1 = plt.subplots(figsize=(9, 5))
    ax1.bar([i - w / 2 for i in x], p50, width=w, label="p50 latency (ms)")
    ax1.bar([i + w / 2 for i in x], p95, width=w, label="p95 latency (ms)")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(profiles)
    ax1.set_ylabel("Latency (ms)")

    ax2 = ax1.twinx()
    ax2.plot(list(x), throughput, marker="s", linewidth=2, color="darkred", label="Throughput (req/s)")
    ax2.set_ylabel("Throughput (req/s)")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")
    ax1.set_title("Runtime Tradeoff by Profile")
    fig.tight_layout()
    fig.savefig(out_dir / "fig4_runtime_tradeoff.png", dpi=220)
    plt.close(fig)

    # Figure 5: Confusion components
    tp = [data[p]["tp"] for p in profiles]
    fp = [data[p]["fp"] for p in profiles]
    fn = [data[p]["fn"] for p in profiles]
    tn = [data[p]["tn"] for p in profiles]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(profiles, tp, label="TP")
    ax.bar(profiles, fp, bottom=tp, label="FP")
    bottom2 = [tp[i] + fp[i] for i in range(len(profiles))]
    ax.bar(profiles, fn, bottom=bottom2, label="FN")
    bottom3 = [bottom2[i] + fn[i] for i in range(len(profiles))]
    ax.bar(profiles, tn, bottom=bottom3, label="TN")
    ax.set_ylabel("Count")
    ax.set_title("Confusion Components by Profile")
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(out_dir / "fig5_confusion_components.png", dpi=220)
    plt.close(fig)

    compiled_csv = out_dir / "figure_data_compiled.csv"
    with compiled_csv.open("w", encoding="utf-8") as f:
        f.write("profile,precision,recall,f1_score,false_positive_rate,p50_ms,p95_ms,throughput_req_per_sec,tp,fp,fn,tn\n")
        for p in profiles:
            d = data[p]
            f.write(
                f"{p},{d['precision']},{d['recall']},{d['f1']},{d['false_positive_rate']},{d['p50_ms']},{d['p95_ms']},{d['throughput_req_per_sec']},{d['tp']},{d['fp']},{d['fn']},{d['tn']}\n"
            )

    print("Generated figures:")
    print(out_dir / "fig3_detection_quality.png")
    print(out_dir / "fig4_runtime_tradeoff.png")
    print(out_dir / "fig5_confusion_components.png")
    print(compiled_csv)


if __name__ == "__main__":
    main()
