"""Generate Figure 6: residual risk comparison across all 14 subprocess-level
risk records in the three case studies.

Values are taken directly from Tables 2, 4, and 5 of the paper draft,
computed with services/risk_service.calculate_process_risk_metrics() on the
demo scenario inputs in seed_process_cases.py (verified against the live
SQLite database after re-seeding).
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOW, MED, HIGH = "#22c55e", "#eab308", "#ef4444"


def category_color(residual_risk):
    if residual_risk <= 3.9:
        return LOW
    if residual_risk <= 6.9:
        return MED
    return HIGH


bars = [
    ("Log\ncollection", 5.94, "Incident management"),
    ("Event\nanalysis", 8.09, "Incident management"),
    ("Incident\nclassification", 5.24, "Incident management"),
    ("Response", 6.60, "Incident management"),
    ("Reporting", 3.04, "Incident management"),
    ("Telemetry\ncollection", 6.44, "SCADA monitoring"),
    ("Deviation\nanalysis", 8.61, "SCADA monitoring"),
    ("Escalation", 6.01, "SCADA monitoring"),
    ("Response ", 7.02, "SCADA monitoring"),
    ("Data\ncollection", 7.37, "Personal-data processing"),
    ("Consent\nverification", 9.03, "Personal-data processing"),
    ("Processing", 10.21, "Personal-data processing"),
    ("Storage", 8.53, "Personal-data processing"),
    ("Deletion /\narchival", 3.60, "Personal-data processing"),
]

labels = [b[0] for b in bars]
values = [b[1] for b in bars]
colors = [category_color(v) for v in values]

fig, ax = plt.subplots(figsize=(13, 5), dpi=300)
x = range(len(bars))
ax.bar(x, values, color=colors, edgecolor="#1f2937", linewidth=0.8, width=0.62)

for xi, v in zip(x, values):
    ax.text(xi, v + 0.18, f"{v:.2f}", ha="center", va="bottom", fontsize=8.5, fontweight="bold", color="#1f2937")

ax.axhline(3.9, color="#6b7280", linestyle="--", linewidth=0.9)
ax.axhline(6.9, color="#6b7280", linestyle="--", linewidth=0.9)
ax.text(len(bars) - 0.6, 3.9, " Low/Medium (3.9)", fontsize=7.5, color="#4b5563", va="bottom")
ax.text(len(bars) - 0.6, 6.9, " Medium/High (6.9)", fontsize=7.5, color="#4b5563", va="bottom")

ax.set_xticks(list(x))
ax.set_xticklabels(labels, fontsize=8)
ax.set_ylabel("Residual risk (RR = risk level × (1 − control effectiveness))", fontsize=9)
ax.set_ylim(0, 12)
ax.set_title("Figure 6. Residual risk across all 14 subprocess-level risk records (three case studies)", fontsize=11, fontweight="bold", pad=16)

# group separators (after index 4 -> boundary at 4.5; after index 8 -> boundary at 8.5)
for sp in (4.5, 8.5):
    ax.axvline(sp, color="#d1d5db", linewidth=1)

group_label_pos = {"Incident management": 2, "SCADA monitoring": 6.5, "Personal-data processing": 11.5}
for g, pos in group_label_pos.items():
    ax.text(pos, -2.6, g, ha="center", fontsize=8.5, color="#374151", fontweight="bold")

legend_handles = [
    plt.Rectangle((0, 0), 1, 1, color=LOW, label="Low (≤3.9)"),
    plt.Rectangle((0, 0), 1, 1, color=MED, label="Medium (>3.9–6.9)"),
    plt.Rectangle((0, 0), 1, 1, color=HIGH, label="High (>6.9)"),
]
ax.legend(handles=legend_handles, loc="upper left", fontsize=8, frameon=False)

ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
fig.subplots_adjust(bottom=0.24, top=0.87)
fig.savefig("figure6_residual_risk_comparison.png", bbox_inches="tight", dpi=300)
fig.savefig("figure6_residual_risk_comparison.svg", bbox_inches="tight")
fig.savefig("figure6_residual_risk_comparison.pdf", bbox_inches="tight")
print("saved figure6_residual_risk_comparison.{png,svg,pdf}")
