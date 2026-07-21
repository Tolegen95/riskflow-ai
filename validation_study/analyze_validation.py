"""Analysis pipeline for the pilot validation study (paper Section 5).

Computes, from real participant data:
  1. ICC(2,k) AND ICC(2,1) inter-rater agreement for P, V, I, CE (Task 1) —
     ICC(2,1) is the statistic relevant to the framework's normal single-
     assessor mode of use, not just the pooled k-rater figure.
  2. Fleiss' kappa inter-rater agreement for the holistic Low/Medium/High
     rating (Task 2), with a percentile bootstrap 95% CI.
  3. The PRIMARY concordance result: a *within-subject* test — each
     participant's own Task 1 (P, V, I, CE) inputs are run through the real
     framework formulas (services/risk_service.py) to get the framework's
     residual-risk category, and compared against that same participant's own
     Task 2 holistic rating for the same subprocess. This is the
     methodologically appropriate comparison for a tool a single assessor
     operates end-to-end (a superseded baseline-vs-median comparison is kept
     below only as a labeled legacy/secondary check, see paper Section 5.3).
  4. The INHERENT-VS-RESIDUAL DIAGNOSTIC (paper Section 5.4.3): the same
     within-subject comparison re-run using risk_level (risk BEFORE the
     control-effectiveness discount) instead of residual_risk, under the
     SAME fixed 3.9/6.9 thresholds. No parameter is tuned for this
     comparison — it is a direct test of whether Task 2's holistic rating
     tracked inherent risk rather than residual risk.
  5. Category-stability count: how many distinct framework categories are
     produced across raters for the same subprocess, given each rater's own
     real inputs.
  6. Mean System Usability Scale (SUS) score with a t-based 95% CI and the
     Bangor et al. (2009) adjective-rating bands (Task 3).

No external statistics dependency (no scipy/sklearn/pingouin) — everything is
implemented directly with numpy, consistent with the rest of this project's
"no new dependencies" convention. See README.md in this folder for how to
actually run the study before running this script on real data.

IMPORTANT: `--self-test` runs this script against clearly-labeled SYNTHETIC
data purely to confirm the code is correct. It does not, and must not be
mistaken for, a real validation result. Do not copy the self-test numbers
into the paper.
"""
import argparse
import csv
import random
import sys
from pathlib import Path

import numpy as np

# services/risk_service.py lives at the project root, one directory up from
# this file's parent (validation_study/).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from services.risk_service import calculate_process_risk_metrics, classify_numeric_risk  # noqa: E402

CATEGORY_ORDER = {"Low": 0, "Medium": 1, "High": 2}
RU_TO_EN_CATEGORY = {"Низкий": "Low", "Средний": "Medium", "Высокий": "High"}


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def icc_2k(matrix):
    """ICC(2,k): two-way random effects, absolute agreement, average of k raters.
    matrix: (n_subjects, k_raters) numpy array.
    Reference for interpretation bands: Koo & Li (2016)."""
    n, k = matrix.shape
    grand_mean = matrix.mean()
    row_means = matrix.mean(axis=1)
    col_means = matrix.mean(axis=0)
    sst = ((matrix - grand_mean) ** 2).sum()
    ssr = k * ((row_means - grand_mean) ** 2).sum()
    ssc = n * ((col_means - grand_mean) ** 2).sum()
    sse = sst - ssr - ssc
    msr = ssr / (n - 1)
    msc = ssc / (k - 1)
    mse = sse / ((n - 1) * (k - 1)) if (n - 1) * (k - 1) > 0 else float("nan")
    denom = msr + (msc - mse) / n
    if denom == 0:
        return float("nan")
    return (msr - mse) / denom


def icc_2_1(matrix):
    """ICC(2,1): two-way random effects, absolute agreement, SINGLE rater.
    This is the statistic relevant when the framework is used by one assessor
    at a time (its normal mode of operation), not the pooled k-rater figure."""
    n, k = matrix.shape
    grand_mean = matrix.mean()
    row_means = matrix.mean(axis=1)
    col_means = matrix.mean(axis=0)
    sst = ((matrix - grand_mean) ** 2).sum()
    ssr = k * ((row_means - grand_mean) ** 2).sum()
    ssc = n * ((col_means - grand_mean) ** 2).sum()
    sse = sst - ssr - ssc
    msr = ssr / (n - 1)
    msc = ssc / (k - 1)
    mse = sse / ((n - 1) * (k - 1)) if (n - 1) * (k - 1) > 0 else float("nan")
    denom = msr + (k - 1) * mse + k * (msc - mse) / n
    if denom == 0:
        return float("nan")
    return (msr - mse) / denom


def icc_interpretation(value):
    if np.isnan(value):
        return "undefined (insufficient data)"
    if value < 0.5:
        return "poor"
    if value < 0.75:
        return "moderate"
    if value < 0.9:
        return "good"
    return "excellent"


def fleiss_kappa(category_counts):
    """category_counts: (n_subjects, n_categories) array of rater counts per category."""
    n, _ = category_counts.shape
    k = category_counts.sum(axis=1)[0]  # assume constant raters per subject
    total_ratings = n * k
    p_j = category_counts.sum(axis=0) / total_ratings
    p_i = (
        (category_counts ** 2).sum(axis=1) - k
    ) / (k * (k - 1))
    p_bar = p_i.mean()
    p_e = (p_j ** 2).sum()
    if p_e == 1:
        return float("nan")
    return (p_bar - p_e) / (1 - p_e)


def weighted_kappa(rater_a, rater_b, n_categories, weight_power=1):
    """Linear (weight_power=1) or quadratic (weight_power=2) weighted Cohen's kappa."""
    o = np.zeros((n_categories, n_categories))
    for a, b in zip(rater_a, rater_b):
        o[a, b] += 1
    n = o.sum()
    row_marg = o.sum(axis=1)
    col_marg = o.sum(axis=0)
    e = np.outer(row_marg, col_marg) / n
    w = np.zeros((n_categories, n_categories))
    for i in range(n_categories):
        for j in range(n_categories):
            w[i, j] = (abs(i - j) / (n_categories - 1)) ** weight_power
    kappa = 1 - (w * o).sum() / (w * e).sum()
    agreement = np.trace(o) / n
    return kappa, agreement


def sus_score(row):
    """Standard SUS scoring: odd items (1,3,5,7,9) contribute (score-1);
    even items (2,4,6,8,10) contribute (5-score); sum * 2.5 -> 0-100 scale."""
    total = 0.0
    for i in range(1, 11):
        val = float(row[f"item{i}"])
        total += (val - 1) if i % 2 == 1 else (5 - val)
    return total * 2.5


def sus_band(score):
    # Bangor, Kortum & Miller (2009) adjective rating bands
    if score >= 80.3:
        return "Excellent"
    if score >= 68:
        return "Good"
    if score >= 51:
        return "OK"
    return "Poor"


def framework_category_from_inputs(P, V, I, CE, metric="residual_risk"):
    """Run real P/V/I/CE inputs through the actual framework formulas
    (services/risk_service.py) and return the English category label.

    metric="residual_risk" (default): the framework's actual, documented output
        (risk_level * (1 - CE)) -- risk AFTER the control-effectiveness discount.
    metric="risk_level": potentiality * impact -- risk BEFORE the control-
        effectiveness discount ("inherent risk" proxy). This is used only for
        the inherent-vs-residual diagnostic (paper Section 5.4.3); it is NOT
        a proposal to change what the framework reports by default.
    """
    metrics = calculate_process_risk_metrics(float(P), float(V), float(I), float(CE))
    value = metrics[metric]
    return RU_TO_EN_CATEGORY[classify_numeric_risk(value)], value


def within_subject_pairs(task1_rows, task2_rows, metric="residual_risk"):
    """For each (expert_id, subprocess), compute the framework category from
    that expert's OWN Task 1 inputs and pair it with that SAME expert's own
    Task 2 holistic rating for the same subprocess. Returns a list of dicts.
    See framework_category_from_inputs() for the `metric` parameter."""
    task2_lookup = {(r["expert_id"], r["subprocess"]): r["holistic_rating"] for r in task2_rows}
    pairs = []
    for row in task1_rows:
        key = (row["expert_id"], row["subprocess"])
        if key not in task2_lookup:
            continue
        fw_cat, value = framework_category_from_inputs(row["P"], row["V"], row["I"], row["CE"], metric=metric)
        pairs.append({
            "expert_id": row["expert_id"],
            "subprocess": row["subprocess"],
            "metric_value": value,
            "framework_category": fw_cat,
            "own_holistic_rating": task2_lookup[key],
            "agree": fw_cat == task2_lookup[key],
        })
    return pairs


def bootstrap_ci_by_participant(pairs, statistic_fn, n_boot=5000, seed=42):
    """Percentile bootstrap CI, resampling PARTICIPANTS (not individual pairs)
    with replacement, to respect the repeated-measures structure (5 pairs per
    participant are not independent observations)."""
    rng = random.Random(seed)
    experts = sorted({p["expert_id"] for p in pairs})
    by_expert = {e: [p for p in pairs if p["expert_id"] == e] for e in experts}
    values = []
    for _ in range(n_boot):
        sample_experts = [rng.choice(experts) for _ in experts]
        resampled = [p for e in sample_experts for p in by_expert[e]]
        values.append(statistic_fn(resampled))
    values = np.array(values, dtype=float)
    return float(np.nanpercentile(values, 2.5)), float(np.nanpercentile(values, 97.5))


def bootstrap_ci_by_unit(rows_per_unit, statistic_fn, n_boot=5000, seed=42):
    """Percentile bootstrap CI resampling UNITS (e.g. subprocesses) with
    replacement — for statistics computed over a small number of rating units
    such as Fleiss' kappa over 5 subprocesses."""
    rng = random.Random(seed)
    units = list(rows_per_unit.keys())
    values = []
    for _ in range(n_boot):
        sample_units = [rng.choice(units) for _ in units]
        values.append(statistic_fn([rows_per_unit[u] for u in sample_units]))
    values = np.array(values, dtype=float)
    return float(np.nanpercentile(values, 2.5)), float(np.nanpercentile(values, 97.5))


def analyze(task1_rows, task2_rows, task3_rows, framework_rows):
    print("=" * 70)
    print("TASK 1 - Inter-rater agreement on P, V, I, CE")
    print("=" * 70)
    subprocesses = sorted({r["subprocess"] for r in task1_rows})
    experts = sorted({r["expert_id"] for r in task1_rows})
    for field in ("P", "V", "I", "CE"):
        matrix = np.zeros((len(subprocesses), len(experts)))
        for r in task1_rows:
            i = subprocesses.index(r["subprocess"])
            j = experts.index(r["expert_id"])
            matrix[i, j] = float(r[field])
        v_k = icc_2k(matrix)
        v_1 = icc_2_1(matrix)

        def icc21_stat(sample_matrix_rows, _matrix=matrix):
            return icc_2_1(_matrix[sample_matrix_rows, :])

        rng = random.Random(42)
        boots = [icc21_stat([rng.randrange(len(subprocesses)) for _ in subprocesses]) for _ in range(5000)]
        v1_lo, v1_hi = float(np.nanpercentile(boots, 2.5)), float(np.nanpercentile(boots, 97.5))
        print(f"  {field}: ICC(2,{len(experts)}) = {v_k:.3f} ({icc_interpretation(v_k)})   "
              f"ICC(2,1) = {v_1:.3f} ({icc_interpretation(v_1)}), 95% CI [{v1_lo:.2f}, {v1_hi:.2f}]  <- relevant to single-assessor use")

    print()
    print("=" * 70)
    print("TASK 2 - Inter-rater agreement on holistic Low/Medium/High (Fleiss' kappa)")
    print("=" * 70)
    counts = np.zeros((len(subprocesses), 3))
    rows_per_sp = {sp: [] for sp in subprocesses}
    for r in task2_rows:
        i = subprocesses.index(r["subprocess"])
        j = CATEGORY_ORDER[r["holistic_rating"]]
        counts[i, j] += 1
        rows_per_sp[r["subprocess"]].append(CATEGORY_ORDER[r["holistic_rating"]])
    kappa = fleiss_kappa(counts)

    def fleiss_from_ratings_list(ratings_lists):
        k = len(ratings_lists[0])
        c = np.zeros((len(ratings_lists), 3))
        for i, ratings in enumerate(ratings_lists):
            for r in ratings:
                c[i, r] += 1
        return fleiss_kappa(c)

    lo, hi = bootstrap_ci_by_unit(rows_per_sp, fleiss_from_ratings_list)
    print(f"  Fleiss' kappa: {kappa:.3f}   95% CI [{lo:.2f}, {hi:.2f}] (bootstrap over {len(subprocesses)} subprocess-units)")
    print("  NOTE: with only 5 rating units this CI is necessarily wide; treat as descriptive, not a stable inferential result.")

    print()
    print("=" * 70)
    print("PRIMARY RESULT: within-subject framework-vs-own-holistic-judgment concordance")
    print("=" * 70)
    pairs = within_subject_pairs(task1_rows, task2_rows)
    n = len(pairs)
    agree = sum(1 for p in pairs if p["agree"])
    rater_a = [CATEGORY_ORDER[p["framework_category"]] for p in pairs]
    rater_b = [CATEGORY_ORDER[p["own_holistic_rating"]] for p in pairs]
    kw, _ = weighted_kappa(rater_a, rater_b, 3, weight_power=1)

    def agreement_stat(sample_pairs):
        return sum(1 for p in sample_pairs if p["agree"]) / len(sample_pairs) if sample_pairs else float("nan")

    def kappa_stat(sample_pairs):
        if not sample_pairs:
            return float("nan")
        a = [CATEGORY_ORDER[p["framework_category"]] for p in sample_pairs]
        b = [CATEGORY_ORDER[p["own_holistic_rating"]] for p in sample_pairs]
        k, _ = weighted_kappa(a, b, 3, weight_power=1)
        return k

    agr_lo, agr_hi = bootstrap_ci_by_participant(pairs, agreement_stat)
    kw_lo, kw_hi = bootstrap_ci_by_participant(pairs, kappa_stat)

    under = sum(1 for p in pairs if CATEGORY_ORDER[p["framework_category"]] < CATEGORY_ORDER[p["own_holistic_rating"]])
    over = sum(1 for p in pairs if CATEGORY_ORDER[p["framework_category"]] > CATEGORY_ORDER[p["own_holistic_rating"]])

    print(f"  n = {n} pairs ({len(experts)} participants x {len(subprocesses)} subprocesses)")
    print(f"  Exact agreement: {agree}/{n} = {agree/n*100:.1f}%   95% CI [{agr_lo*100:.1f}%, {agr_hi*100:.1f}%]")
    print(f"  Linear-weighted kappa: {kw:.3f}   95% CI [{kw_lo:.3f}, {kw_hi:.3f}]")
    print(f"  Direction of disagreement: framework LOWER than own holistic rating in {under}/{n} ({under/n*100:.1f}%), "
          f"HIGHER in {over}/{n} ({over/n*100:.1f}%)")

    print()
    print("=" * 70)
    print("INHERENT-VS-RESIDUAL DIAGNOSTIC: same comparison using RISK LEVEL")
    print("(pre-control-discount 'inherent risk' proxy) instead of residual risk,")
    print("same fixed 3.9/6.9 thresholds -- no new parameter is tuned here.")
    print("=" * 70)
    rl_pairs = within_subject_pairs(task1_rows, task2_rows, metric="risk_level")
    rl_agree = sum(1 for p in rl_pairs if p["agree"])
    rl_a = [CATEGORY_ORDER[p["framework_category"]] for p in rl_pairs]
    rl_b = [CATEGORY_ORDER[p["own_holistic_rating"]] for p in rl_pairs]
    rl_kw, _ = weighted_kappa(rl_a, rl_b, 3, weight_power=1)

    def rl_agreement_stat(sample_pairs):
        return sum(1 for p in sample_pairs if p["agree"]) / len(sample_pairs) if sample_pairs else float("nan")

    def rl_kappa_stat(sample_pairs):
        if not sample_pairs:
            return float("nan")
        a = [CATEGORY_ORDER[p["framework_category"]] for p in sample_pairs]
        b = [CATEGORY_ORDER[p["own_holistic_rating"]] for p in sample_pairs]
        k, _ = weighted_kappa(a, b, 3, weight_power=1)
        return k

    rl_agr_lo, rl_agr_hi = bootstrap_ci_by_participant(rl_pairs, rl_agreement_stat)
    rl_kw_lo, rl_kw_hi = bootstrap_ci_by_participant(rl_pairs, rl_kappa_stat)
    print(f"  Exact agreement: {rl_agree}/{n} = {rl_agree/n*100:.1f}%   95% CI [{rl_agr_lo*100:.1f}%, {rl_agr_hi*100:.1f}%]")
    print(f"  Linear-weighted kappa: {rl_kw:.3f}   95% CI [{rl_kw_lo:.3f}, {rl_kw_hi:.3f}]")
    print("  See paper Section 5.4.3: large improvement here is evidence of a construct mismatch")
    print("  (Task 2 tracked inherent, not residual, risk), not confirmation of a threshold fix.")

    print()
    print("  Category stability across raters (same subprocess, each rater's own real inputs):")
    for sp in subprocesses:
        cats = [p["framework_category"] for p in pairs if p["subprocess"] == sp]
        from collections import Counter
        dist = Counter(cats)
        print(f"    {sp}: {dict(dist)}")

    if framework_rows:
        print()
        print("-" * 70)
        print("LEGACY/SECONDARY: framework-baseline-vs-median concordance (superseded, see paper Sec. 5.3)")
        print("-" * 70)
        expert_median = {}
        for sp in subprocesses:
            ratings = [CATEGORY_ORDER[r["holistic_rating"]] for r in task2_rows if r["subprocess"] == sp]
            expert_median[sp] = int(np.median(ratings))
        fw_cat = {r["subprocess"]: CATEGORY_ORDER[r["framework_category"]] for r in framework_rows}
        a2 = [fw_cat[sp] for sp in subprocesses]
        b2 = [expert_median[sp] for sp in subprocesses]
        kappa_w2, agreement2 = weighted_kappa(a2, b2, 3, weight_power=1)
        print(f"  Percent agreement: {agreement2 * 100:.1f}%   Linear-weighted kappa: {kappa_w2:.3f}")
        print("  This compares the framework's output on ONE author-chosen baseline parameterization")
        print("  against the MEDIAN of participants' own holistic ratings. It does not test the")
        print("  framework as any single assessor would actually use it; see the PRIMARY result above.")

    print()
    print("=" * 70)
    print("TASK 3 - Usability (SUS)")
    print("=" * 70)
    scores = [sus_score(r) for r in task3_rows]
    if scores:
        mean_score = float(np.mean(scores))
        sd = float(np.std(scores, ddof=1)) if len(scores) > 1 else float("nan")
        se = sd / np.sqrt(len(scores)) if len(scores) > 1 else float("nan")
        # two-sided 95% t critical values by df, small lookup for typical pilot sizes
        t_table = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
                   7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}
        df = len(scores) - 1
        t_crit = t_table.get(df, 1.96)
        print(f"  Individual SUS scores: {[round(s, 1) for s in scores]}")
        print(f"  Mean SUS score: {mean_score:.2f} / 100 (SD={sd:.2f})  ({sus_band(mean_score)}, Bangor et al. 2009 bands)")
        if not np.isnan(se):
            print(f"  95% CI: [{mean_score - t_crit*se:.1f}, {mean_score + t_crit*se:.1f}]  (t-based, df={df})")
        print("  CAUTION (see paper Sec. 5.4.5): collected immediately after participants saw the")
        print("  framework's own output for a process they had just scored, with no control condition,")
        print("  blinding, or counterbalancing -- treat as a report-clarity signal, not unbiased usability.")
    else:
        print("  No Task 3 data provided.")


def make_synthetic_self_test_data():
    """Clearly-labeled SYNTHETIC data, used only to prove the code runs. NOT a real result."""
    subprocesses = ["SYN-1", "SYN-2", "SYN-3", "SYN-4"]
    experts = ["SYNTHETIC-E1", "SYNTHETIC-E2", "SYNTHETIC-E3", "SYNTHETIC-E4", "SYNTHETIC-E5"]
    rng = np.random.default_rng(42)
    task1_rows = []
    base = {"SYN-1": (2.5, 2.5, 2.5, 0.4), "SYN-2": (1.5, 1.5, 1.5, 0.7),
            "SYN-3": (3.0, 2.8, 3.0, 0.2), "SYN-4": (2.0, 2.0, 2.0, 0.5)}
    for sp in subprocesses:
        p0, v0, i0, ce0 = base[sp]
        for ex in experts:
            task1_rows.append({
                "expert_id": ex, "subprocess": sp,
                "P": round(float(np.clip(p0 + rng.normal(0, 0.3), 1, 3)), 2),
                "V": round(float(np.clip(v0 + rng.normal(0, 0.3), 1, 3)), 2),
                "I": round(float(np.clip(i0 + rng.normal(0, 0.3), 1, 3)), 2),
                "CE": round(float(np.clip(ce0 + rng.normal(0, 0.1), 0, 1)), 2),
            })
    holistic_base = {"SYN-1": "Medium", "SYN-2": "Low", "SYN-3": "High", "SYN-4": "Medium"}
    task2_rows = []
    for sp in subprocesses:
        for ex in experts:
            task2_rows.append({"expert_id": ex, "subprocess": sp, "holistic_rating": holistic_base[sp]})
    task3_rows = []
    for ex in experts:
        row = {"expert_id": ex}
        for i in range(1, 11):
            row[f"item{i}"] = str(rng.integers(3, 6))
        task3_rows.append(row)
    framework_rows = [{"subprocess": sp, "framework_category": holistic_base[sp]} for sp in subprocesses]
    return task1_rows, task2_rows, task3_rows, framework_rows


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--task1", help="Path to completed task1 CSV (framework scoring)")
    parser.add_argument("--task2", help="Path to completed task2 CSV (holistic rating)")
    parser.add_argument("--task3", help="Path to completed task3 CSV (SUS)")
    parser.add_argument("--framework-categories", help="Path to framework_categories CSV (optional, only used for the legacy/secondary comparison)")
    parser.add_argument("--self-test", action="store_true", help="Run against synthetic data to verify the script works (NOT a real result)")
    args = parser.parse_args()

    if args.self_test:
        print("Running self-test on SYNTHETIC data. These numbers are NOT a real validation result.\n")
        task1_rows, task2_rows, task3_rows, framework_rows = make_synthetic_self_test_data()
        analyze(task1_rows, task2_rows, task3_rows, framework_rows)
        return

    if not all([args.task1, args.task2, args.task3]):
        parser.error("Provide --task1, --task2, and --task3 (optionally --framework-categories), or use --self-test")

    task1_rows = read_csv(args.task1)
    task2_rows = read_csv(args.task2)
    task3_rows = read_csv(args.task3)
    framework_rows = read_csv(args.framework_categories) if args.framework_categories else []
    analyze(task1_rows, task2_rows, task3_rows, framework_rows)


if __name__ == "__main__":
    sys.exit(main())
