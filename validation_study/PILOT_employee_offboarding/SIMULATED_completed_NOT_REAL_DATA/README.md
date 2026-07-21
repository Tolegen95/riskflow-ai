# SIMULATED COMPLETED PILOT — NOT REAL DATA — DO NOT CITE IN THE PAPER

This folder shows what the Employee Offboarding pilot could look like after
six real experts complete Tasks 1-3. The data are invented and must not be
reported as validation results.

The simulated raters are intentionally varied. The names below are fictional
personas, not real participants:

- `SIM-P1` — Айдар Сулейменов — balanced IT/security view.
- `SIM-P2` — Марина Кравцова — more optimistic IT operations view.
- `SIM-P3` — Тимур Жаксылыков — stricter security view.
- `SIM-P4` — Алия Нурбекова — access-management practitioner view.
- `SIM-P5` — Екатерина Морозова — HR/compliance-weighted view.
- `SIM-P6` — Данияр Ахметов — auditor view.

The same mapping is stored in `expert_roster_SIMULATED.csv`, and the simulated
answer CSVs include an `expert_name` column for readability.

Use this folder only to rehearse data entry and analysis. For the real pilot,
keep using the parent folder's `_TOFILL.csv` files and replace them only with
actual participant responses.

## Command used

```bash
cd validation_study
../.venv/bin/python analyze_validation.py \
  --task1 PILOT_employee_offboarding/SIMULATED_completed_NOT_REAL_DATA/task1_framework_scoring_SIMULATED_COMPLETED.csv \
  --task2 PILOT_employee_offboarding/SIMULATED_completed_NOT_REAL_DATA/task2_holistic_rating_SIMULATED_COMPLETED.csv \
  --task3 PILOT_employee_offboarding/SIMULATED_completed_NOT_REAL_DATA/task3_sus_SIMULATED_COMPLETED.csv \
  --framework-categories PILOT_employee_offboarding/framework_categories.csv
```
