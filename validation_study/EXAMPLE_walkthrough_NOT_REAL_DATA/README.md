# ⚠️ ILLUSTRATIVE WALKTHROUGH — NOT REAL DATA — DO NOT CITE IN THE PAPER

Everything in this folder is **invented by the author of this repository for
demonstration purposes only**, so you can see what a completed pilot run
looks like end to end before recruiting real participants. **"EXAMPLE-Expert-1"
through "EXAMPLE-Expert-5" are not real people.** No study was conducted. No
finding here may be reported, quoted, or paraphrased as a result in the paper.

If you copy any number from `analysis_output_EXAMPLE.txt` into
`RiskFlow_AI_Applied_Sciences_Draft.md` and present it as a real finding, that
is data fabrication — the exact failure mode Section 6.1.4 of the paper
explicitly promises reviewers will not happen. Section 6.1 must stay marked
"not yet executed" until you replace this folder's contents with responses
from real participants.

## What this folder actually demonstrates

1. **What the filled-in CSVs look like** once real participants have done
   Tasks 1–3 (`task1_framework_scoring_EXAMPLE.csv`,
   `task2_holistic_rating_EXAMPLE.csv`, `task3_sus_EXAMPLE.csv`,
   `framework_categories_EXAMPLE.csv`).
2. **What `analyze_validation.py`'s output looks like** on a full, populated
   dataset (`analysis_output_EXAMPLE.txt`) — including a realistic, imperfect
   pattern (good-to-excellent agreement on the continuous P/V/I/CE scores,
   only fair agreement on the coarser three-category holistic rating, and one
   subprocess — Response — where the experts' median judgment (High) disagreed
   with the framework's own category (Medium), giving 80% concordance rather
   than a suspiciously perfect 100%). Real pilot data may look better, worse,
   or different in pattern entirely — this is illustrative of the *shape* of
   the output, not a prediction of the *result*.
3. **Why this process (Case Study 1) is a convenient but methodologically
   weak choice for the *real* pilot**: Section 6.1.1 of the paper specifically
   requires a process not already used as one of the paper's own illustrative
   case studies, to avoid the pilot being run on a case the framework was
   effectively tuned against. This walkthrough reuses Case Study 1 purely
   because its subprocesses and framework categories were already fully
   specified in the paper, which made it fast to build a realistic-looking
   worked example — that convenience is exactly why it must **not** be reused
   for the actual pilot.

## What to do next for a real pilot

1. Copy the *blank* templates from the parent folder (`../task1_framework_scoring_template.csv`, etc.) — not the files in this folder.
2. Pick a real, different process (see README.md in the parent folder, step 1).
3. Recruit real participants and run Tasks 1–3 for real.
4. Run `analyze_validation.py` on the real completed CSVs.
5. Report the real numbers — whatever they are — in Section 6.1 of the paper.
