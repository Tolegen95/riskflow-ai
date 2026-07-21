"""Merge per-expert response CSVs (downloaded from the web forms, or typed up
by hand) into the combined task1/task2/task3 files that analyze_validation.py
expects.

Usage:
    ../.venv/bin/python merge_responses.py --task1 responses/task1_*.csv --task2 responses/task2_*.csv --task3 responses/task3_*.csv

Put all the individual files an administrator collects back from experts
(e.g. task1_P1.csv, task1_P2.csv, ...) into one folder, then point this
script at them with a glob pattern. It writes:
    task1_framework_scoring_MERGED.csv
    task2_holistic_rating_MERGED.csv
    task3_sus_MERGED.csv
in the current directory, ready to pass to analyze_validation.py.

This script only concatenates and validates — it does not invent, alter, or
drop any values, and it will refuse to merge if it finds an empty field or a
subprocess name that doesn't match the five expected names exactly (the same
subprocess-name-collision risk noted in the project's other READMEs).
"""
import argparse
import csv
import glob
import sys

EXPECTED_SUBPROCESSES = {
    "Offboarding request submission",
    "Access inventory and revocation",
    "Asset return and verification",
    "Knowledge transfer and handover",
    "Compliance archival",
}


def load_and_validate(patterns, required_fields, check_subprocess=True):
    rows = []
    files = []
    for pattern in patterns:
        files.extend(sorted(glob.glob(pattern)))
    if not files:
        print(f"WARNING: no files matched {patterns}")
        return rows
    for path in files:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                for field in required_fields:
                    if row.get(field, "") == "":
                        raise ValueError(f"{path}: empty value for '{field}' in row {row} — refusing to merge incomplete data.")
                if check_subprocess and row["subprocess"] not in EXPECTED_SUBPROCESSES:
                    raise ValueError(
                        f"{path}: unexpected subprocess name '{row['subprocess']}'. "
                        f"Expected exactly one of: {sorted(EXPECTED_SUBPROCESSES)}. "
                        "Fix the source file rather than editing the merged output."
                    )
                rows.append(row)
        print(f"  loaded {path} ({sum(1 for _ in open(path)) - 1} rows)")
    return rows


def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})
    print(f"wrote {path} ({len(rows)} rows)")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--task1", nargs="+", default=[], help="Glob pattern(s) for task1 per-expert CSVs")
    parser.add_argument("--task2", nargs="+", default=[], help="Glob pattern(s) for task2 per-expert CSVs")
    parser.add_argument("--task3", nargs="+", default=[], help="Glob pattern(s) for task3 per-expert CSVs")
    args = parser.parse_args()

    if not (args.task1 or args.task2 or args.task3):
        parser.error("Provide at least one of --task1, --task2, --task3 with glob patterns")

    if args.task1:
        rows = load_and_validate(args.task1, ["expert_id", "subprocess", "P", "V", "I", "CE"])
        write_csv("task1_framework_scoring_MERGED.csv", rows, ["expert_id", "subprocess", "P", "V", "I", "CE"])

    if args.task2:
        rows = load_and_validate(args.task2, ["expert_id", "subprocess", "holistic_rating"])
        write_csv("task2_holistic_rating_MERGED.csv", rows, ["expert_id", "subprocess", "holistic_rating"])

    if args.task3:
        fields = ["expert_id"] + [f"item{i}" for i in range(1, 11)] + ["q11_clarity", "q12_trust", "q13_changed_mind", "q14_improvement"]
        rows = load_and_validate(args.task3, ["expert_id"] + [f"item{i}" for i in range(1, 11)], check_subprocess=False)
        write_csv("task3_sus_MERGED.csv", rows, fields)


if __name__ == "__main__":
    sys.exit(main())
