"""Generate Figure 3: one-at-a-time (OAT) sensitivity analysis of residual risk (RR)
to each of the four scoring-model inputs (P, V, I, CE), holding the other
three at a baseline value, PLUS a global variance-based (Sobol) sensitivity
analysis over the full joint input space, computed to address the methodological
limitation that raw OAT spans are not comparable across inputs defined on
different domains and playing different roles in the formula (see Section 3.3
of the paper and Saltelli & Annoni 2010, https://doi.org/10.1016/j.envsoft.2010.04.012).

Uses the real formulas from services/risk_service.py:
    potentiality = max(P + V - 1, 0)
    risk_level   = potentiality * I
    residual_risk = risk_level * (1 - CE)

OAT baseline: P=2.5, V=2.5, I=2.5, CE=0.4 (mid-range on each input's domain).
Sobol sampling: P, V, I ~ Uniform(1,3); CE ~ Uniform(0,1); independent; N=200000
joint samples per input, Saltelli-style first-order/total-order estimator.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BASE_P, BASE_V, BASE_I, BASE_CE = 2.5, 2.5, 2.5, 0.4


def rr(p, v, i, ce):
    pot = np.maximum(p + v - 1, 0)
    rl = pot * i
    return rl * (1 - ce)


# ---------------------------------------------------------------------------
# OAT sweep (same as before)
# ---------------------------------------------------------------------------
p_range = np.linspace(1.0, 3.0, 21)
v_range = np.linspace(1.0, 3.0, 21)
i_range = np.linspace(1.0, 3.0, 21)
ce_range = np.linspace(0.0, 1.0, 21)

rr_p = rr(p_range, BASE_V, BASE_I, BASE_CE)
rr_v = rr(BASE_P, v_range, BASE_I, BASE_CE)
rr_i = rr(BASE_P, BASE_V, i_range, BASE_CE)
rr_ce = rr(BASE_P, BASE_V, BASE_I, ce_range)

oat_spans = {
    "P": float(rr_p.max() - rr_p.min()),
    "V": float(rr_v.max() - rr_v.min()),
    "I": float(rr_i.max() - rr_i.min()),
    "CE": float(rr_ce.max() - rr_ce.min()),
}

# ---------------------------------------------------------------------------
# Global variance-based (Sobol, Saltelli estimator) sensitivity analysis
# ---------------------------------------------------------------------------
rng = np.random.default_rng(42)
N = 200_000
domains = {"P": (1.0, 3.0), "V": (1.0, 3.0), "I": (1.0, 3.0), "CE": (0.0, 1.0)}
names = list(domains.keys())


def sample(n):
    return {k: rng.uniform(lo, hi, n) for k, (lo, hi) in domains.items()}


A = sample(N)
B = sample(N)
fA = rr(A["P"], A["V"], A["I"], A["CE"])
fB = rr(B["P"], B["V"], B["I"], B["CE"])
V_total = np.concatenate([fA, fB]).var()

S1, ST = {}, {}
for name in names:
    AB = {k: (B[k].copy() if k == name else A[k].copy()) for k in names}
    fAB = rr(AB["P"], AB["V"], AB["I"], AB["CE"])
    S1[name] = float(np.mean(fB * (fAB - fA)) / V_total)
    ST[name] = float(np.mean((fA - fAB) ** 2) / (2 * V_total))

print("OAT spans:", oat_spans)
print("Sobol S1 (first-order):", S1)
print("Sobol ST (total-order):", ST)
print(f"Var(RR) over joint uniform space = {V_total:.3f}")

# ---------------------------------------------------------------------------
# Figure: 2x2 OAT panels (top) unchanged in spirit, plus a Sobol bar panel
# ---------------------------------------------------------------------------
fig = plt.figure(figsize=(10, 9), dpi=300)
gs = fig.add_gridspec(3, 2, height_ratios=[1, 1, 0.85], hspace=0.55, wspace=0.28)

panels = [
    (fig.add_subplot(gs[0, 0]), p_range, rr_p, "Probability P (V, I, CE fixed)", "P", BASE_P),
    (fig.add_subplot(gs[0, 1]), v_range, rr_v, "Vulnerability V (P, I, CE fixed)", "V", BASE_V),
    (fig.add_subplot(gs[1, 0]), i_range, rr_i, "Impact I (P, V, CE fixed)", "I", BASE_I),
    (fig.add_subplot(gs[1, 1]), ce_range, rr_ce, "Control effectiveness CE (P, V, I fixed)", "CE", BASE_CE),
]

for ax, xr, yr, title, xlabel, base_x in panels:
    ax.plot(xr, yr, color="#2563eb", linewidth=2.2)
    ax.axhline(3.9, color="#9ca3af", linestyle="--", linewidth=0.8)
    ax.axhline(6.9, color="#9ca3af", linestyle="--", linewidth=0.8)
    base_y = rr(
        BASE_P if xlabel != "P" else base_x,
        BASE_V if xlabel != "V" else base_x,
        BASE_I if xlabel != "I" else base_x,
        BASE_CE if xlabel != "CE" else base_x,
    )
    ax.plot([base_x], [base_y], marker="o", color="#111827", markersize=5, zorder=5)
    span = float(np.max(yr) - np.min(yr))
    ax.set_title(f"{title}\nOAT span = {span:.2f}", fontsize=9)
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel("Residual risk (RR)", fontsize=9)
    ax.set_ylim(-0.3, 11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

ax_sobol = fig.add_subplot(gs[2, :])
x = np.arange(len(names))
width = 0.35
bars1 = ax_sobol.bar(x - width / 2, [S1[n] for n in names], width, label="First-order $S_1$", color="#2563eb")
bars2 = ax_sobol.bar(x + width / 2, [ST[n] for n in names], width, label="Total-order $S_T$", color="#93c5fd")
ax_sobol.set_xticks(x)
ax_sobol.set_xticklabels(["Probability (P)", "Vulnerability (V)", "Impact (I)", "Control effectiveness (CE)"], fontsize=9)
ax_sobol.set_ylabel("Sobol sensitivity index", fontsize=9)
ax_sobol.set_title(
    f"Global variance-based sensitivity (Sobol, N={N:,} joint samples, "
    f"P/V/I~Uniform(1,3), CE~Uniform(0,1))",
    fontsize=9.5,
)
for b in list(bars1) + list(bars2):
    ax_sobol.annotate(f"{b.get_height():.3f}", (b.get_x() + b.get_width() / 2, b.get_height()),
                       ha="center", va="bottom", fontsize=7.5)
ax_sobol.legend(fontsize=8, frameon=False)
ax_sobol.spines["top"].set_visible(False)
ax_sobol.spines["right"].set_visible(False)
ax_sobol.set_ylim(0, 0.8)

fig.suptitle(
    "Figure 3. Sensitivity of residual risk to each scoring-model input:\n"
    "one-at-a-time sweep (top, baseline P=V=I=2.5, CE=0.4) and global Sobol indices (bottom)",
    fontsize=11.5, fontweight="bold", y=0.995,
)
fig.savefig("figure3_sensitivity_analysis.png", bbox_inches="tight", dpi=300)
fig.savefig("figure3_sensitivity_analysis.svg", bbox_inches="tight")
fig.savefig("figure3_sensitivity_analysis.pdf", bbox_inches="tight")
print("saved figure3_sensitivity_analysis.{png,svg,pdf}")
