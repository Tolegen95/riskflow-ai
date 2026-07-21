# Pilot Validation Study — Execution Kit

This folder contains everything needed to actually run the pilot validation protocol
described in Section 6.1 of `RiskFlow_AI_Applied_Sciences_Draft.md`. Nothing in here
is a substitute for running the study with real people — it is the instrument and
analysis pipeline so that once you have real responses, producing real numbers for
the paper is a five-minute script run, not a new research project.

**Nothing in this folder contains real results.** The only numbers here are clearly
labeled synthetic/example data used to prove the pipeline works correctly.

**New to this kit? Look at `EXAMPLE_walkthrough_NOT_REAL_DATA/` first.** It shows
filled-in CSVs and the resulting analysis output from five invented example
"experts," purely so you can see the mechanics — what the files look like once
populated, and what the script prints — before running this for real. Every file
in it is marked NOT REAL DATA and must never be quoted in the paper; see its own
README for the details and for why it deliberately does not use a "perfect"
result (real agreement should not be assumed before you have real data).

For a larger dry run, `SIMULATED_realistic_pilot_NOT_REAL_DATA/` contains a
synthetic 14-subprocess, 6-rater dataset based on all three illustrative case
studies from the paper. It is useful for testing the mechanics at paper scale,
but it is still simulated and must not be presented as real validation evidence.

## How to run the study (practical steps)

1. **Pick one real process** from an organization you have access to (your own
   workplace, your supervisor's department, a willing partner organization). It
   does not have to be information security — any process with 4-6 identifiable
   subprocesses and at least one plausible failure mode per subprocess works. Do
   **not** reuse the three illustrative case studies from the paper for this step;
   the pilot needs a process the framework has not already been tuned against.

2. **Recruit 5-10 participants** with genuine domain familiarity with that
   process (risk managers, process owners, analysts, auditors). Five is the
   floor for a meaningful ICC estimate (Section 6.1.2); more is better.

3. **Print or share** `rating_rubric.md` with every participant before Task 1 —
   they must use the same anchor definitions, or the whole point of measuring
   agreement is lost.

4. **Run Task 1** using `task1_framework_scoring_template.csv`: each participant
   fills in one row per subprocess, independently, without seeing anyone else's
   answers. Keep them physically or virtually separated while doing this.

5. **Run Task 2** using `task2_holistic_rating_template.csv`: same participants,
   same subprocesses, but now just an overall Low/Medium/High gut call, still
   without seeing the framework's own output.

6. **Only now**, show participants the framework's actual computed output for the
   process (enter the process into the running application first, or compute it
   by hand with `services/risk_service.py`), and run Task 3 usability using
   `task3_sus_questionnaire.md` / `task3_sus_template.csv`.

7. **Run the analysis**:
   ```bash
   python3 analyze_validation.py \
       --task1 task1_framework_scoring_completed.csv \
       --task2 task2_holistic_rating_completed.csv \
       --task3 task3_sus_completed.csv \
       --framework-categories framework_categories.csv
   ```
   (see `analyze_validation.py --help` for the exact expected columns; run
   `python3 analyze_validation.py --self-test` first to confirm the script works
   on your machine before collecting real data.)

8. **Report the real output** — ICC per input, Fleiss' kappa, framework-vs-expert
   concordance, mean SUS score — in Section 6.1 of the paper, replacing the
   "Status: not yet executed" note with the actual numbers, whatever they turn
   out to be. A weak result (low agreement, low concordance) is a legitimate and
   reportable finding, not a reason to hide the study.

## Files

- `rating_rubric.md` — the P/V/I/CE anchor definitions (same content as Table 1 in the paper).
- `task1_framework_scoring_template.csv` — blank template for Task 1.
- `task2_holistic_rating_template.csv` — blank template for Task 2.
- `task3_sus_questionnaire.md` — the 10 standard SUS items plus 4 open-ended questions.
- `task3_sus_template.csv` — blank template for Task 3 responses.
- `framework_categories_template.csv` — where you record the framework's own computed category per subprocess, for the concordance calculation.
- `analyze_validation.py` — computes ICC(2,k), Fleiss' kappa, weighted-kappa concordance, and SUS scoring, in pure Python + numpy (no scipy/sklearn/pingouin dependency, consistent with the rest of this project).
