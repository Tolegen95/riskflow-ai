# SIMULATED REALISTIC PILOT — NOT REAL DATA — DO NOT CITE IN THE PAPER

This folder contains a larger, more realistic-looking synthetic pilot dataset
for testing the validation workflow on all 14 subprocess-level records from
the three illustrative case studies in the paper.

No participant completed these forms. `SIM-Expert-1` through `SIM-Expert-6`
are invented personas, not real people. The values are approximated around the
paper's case-study inputs with deliberately imperfect agreement, domain-biased
judgments, and several holistic-rating disagreements. They are suitable for:

- checking that the CSV format is usable at a larger scale than the five-row
  walkthrough;
- testing `analyze_validation.py` on 14 subprocesses and 6 raters;
- showing a future data collector what a completed dataset may look like.

They are not suitable for:

- reporting validation results in `RiskFlow_AI_Applied_Sciences_Draft.md`;
- claiming that an expert study was conducted;
- replacing real recruitment, consent/ethics checks, or domain-expert scoring;
- tuning the framework thresholds and then describing the result as empirical.

The subprocess names are prefixed (`IM -`, `SCADA -`, `PD -`) because two case
studies contain a subprocess named `Response`. Without prefixes, the analysis
script would treat those as the same rated object.

## Files

- `task1_framework_scoring_SIMULATED.csv` — synthetic P/V/I/CE ratings.
- `task2_holistic_rating_SIMULATED.csv` — synthetic holistic Low/Medium/High
  ratings, intentionally less consistent than Task 1.
- `task3_sus_SIMULATED.csv` — synthetic SUS answers and comments.
- `framework_categories_SIMULATED.csv` — framework categories from the paper's
  illustrative case-study tables.
- `analysis_output_SIMULATED.txt` — output produced by running the analysis
  script on these synthetic files.

## Command used

```bash
python3 validation_study/analyze_validation.py \
  --task1 validation_study/SIMULATED_realistic_pilot_NOT_REAL_DATA/task1_framework_scoring_SIMULATED.csv \
  --task2 validation_study/SIMULATED_realistic_pilot_NOT_REAL_DATA/task2_holistic_rating_SIMULATED.csv \
  --task3 validation_study/SIMULATED_realistic_pilot_NOT_REAL_DATA/task3_sus_SIMULATED.csv \
  --framework-categories validation_study/SIMULATED_realistic_pilot_NOT_REAL_DATA/framework_categories_SIMULATED.csv
```

For the actual pilot, copy the blank templates from the parent folder and
replace this entire simulated folder with real participant responses.
