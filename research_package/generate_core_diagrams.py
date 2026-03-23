from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyArrowPatch


def draw_box(ax, xy, w, h, text, fc="#f4f7fb", ec="#1f3b5c", fs=9):
    rect = Rectangle(xy, w, h, facecolor=fc, edgecolor=ec, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(xy[0] + w / 2, xy[1] + h / 2, text, ha="center", va="center", fontsize=fs)


def draw_arrow(ax, p1, p2):
    arr = FancyArrowPatch(p1, p2, arrowstyle="->", mutation_scale=12, linewidth=1.3, color="#34495e")
    ax.add_patch(arr)


def fig1_architecture(out_path: Path):
    fig, ax = plt.subplots(figsize=(11, 4.8))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 5)
    ax.axis("off")

    draw_box(ax, (0.3, 2.0), 1.6, 1.0, "Client")
    draw_box(ax, (2.2, 2.0), 1.9, 1.0, "VigilEdge WAF\n(FastAPI)")
    draw_box(ax, (4.4, 2.0), 1.8, 1.0, "Protected\nApplication")

    draw_box(ax, (2.2, 0.4), 1.9, 1.0, "Event Emitter")
    draw_box(ax, (4.4, 0.4), 2.2, 1.0, "ThreatLoom Ingestion API")
    draw_box(ax, (7.0, 0.4), 1.9, 1.0, "Detection Engine")
    draw_box(ax, (9.2, 0.4), 1.5, 1.0, "Playbook\nActions")

    draw_arrow(ax, (1.9, 2.5), (2.2, 2.5))
    draw_arrow(ax, (4.1, 2.5), (4.4, 2.5))

    draw_arrow(ax, (3.15, 2.0), (3.15, 1.4))
    draw_arrow(ax, (4.1, 0.9), (4.4, 0.9))
    draw_arrow(ax, (6.6, 0.9), (7.0, 0.9))
    draw_arrow(ax, (8.9, 0.9), (9.2, 0.9))

    ax.text(0.3, 4.55, "Fig. 1. Hybrid WAF-SOC architecture (module-level data flow)", fontsize=11, weight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=220)
    plt.close(fig)


def fig2_pipeline(out_path: Path):
    fig, ax = plt.subplots(figsize=(11, 5.2))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6)
    ax.axis("off")

    y = 4.4
    boxes = [
        (0.4, y, 1.6, 0.9, "Request\nReceived"),
        (2.3, y, 1.8, 0.9, "Inline Check\n(Signature/Policy)"),
        (4.4, y, 1.8, 0.9, "Immediate Action\n(Allow/Block/Limit)"),
        (6.5, y, 1.8, 0.9, "Event JSON\nEmission"),
        (8.6, y, 1.8, 0.9, "SOC Ingestion\n+ Normalize"),
    ]
    for b in boxes:
        draw_box(ax, (b[0], b[1]), b[2], b[3], b[4])

    for i in range(len(boxes) - 1):
        draw_arrow(ax, (boxes[i][0] + boxes[i][2], y + 0.45), (boxes[i + 1][0], y + 0.45))

    y2 = 2.2
    boxes2 = [
        (2.3, y2, 2.1, 0.9, "Threshold +\nBehavior Analysis"),
        (4.8, y2, 2.0, 0.9, "Correlation\n(Windowed)"),
        (7.2, y2, 1.8, 0.9, "Playbook\nTrigger"),
        (9.3, y2, 1.5, 0.9, "Response\nAudit"),
    ]
    for b in boxes2:
        draw_box(ax, (b[0], b[1]), b[2], b[3], b[4])

    draw_arrow(ax, (9.5, 4.4), (3.3, 3.1))
    for i in range(len(boxes2) - 1):
        draw_arrow(ax, (boxes2[i][0] + boxes2[i][2], y2 + 0.45), (boxes2[i + 1][0], y2 + 0.45))

    ax.text(0.3, 5.5, "Fig. 2. Request-to-mitigation pipeline of the hybrid WAF-SOC architecture", fontsize=11, weight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=220)
    plt.close(fig)


def main():
    out_dir = Path(__file__).resolve().parent / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    fig1_architecture(out_dir / "fig1_architecture.png")
    fig2_pipeline(out_dir / "fig2_pipeline.png")
    print(str(out_dir / "fig1_architecture.png"))
    print(str(out_dir / "fig2_pipeline.png"))


if __name__ == "__main__":
    main()
