#!/usr/bin/env python3
"""
Sanity-check the 0.8 'Unusual' cutoff in unusual_git_commit.py against a handful
of known-clean repos: for each repo, score the last N commits and report what
fraction would be flagged at several candidate thresholds. Pick the lowest
threshold whose false-positive rate on clean repos stays low (~5%).
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from unusual_git_commit import extract_commits, detect  # noqa: E402
from git import Repo  # noqa: E402

REPOS = ["pallets/flask", "pallets/click", "psf/requests", "Textualize/rich"]
LIMIT = 150
CANDIDATES = [0.80, 0.85, 0.90, 0.95, 0.97, 0.99]
WORKDIR = "/tmp/unusual-git-commit-calib"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-reasons", type=float, default=None,
                    help="also print every flagged commit + its top reasons at this threshold, per repo")
    args = ap.parse_args()

    os.makedirs(WORKDIR, exist_ok=True)
    all_vals = []
    for repo_name in REPOS:
        dest = os.path.join(WORKDIR, repo_name.replace("/", "__"))
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        print(f"cloning {repo_name} ...", file=sys.stderr)
        repo = Repo.clone_from(f"https://github.com/{repo_name}.git", dest)
        rows = extract_commits(repo)
        results = detect(rows, limit=min(LIMIT, len(rows)), threshold=0.0)
        vals = [r["decision_val"] for r in results]
        all_vals.extend(vals)
        print(f"\n{repo_name}: {len(vals)} commits scored")
        for t in CANDIDATES:
            flagged = sum(1 for v in vals if v >= t)
            print(f"  threshold {t:.2f}: {flagged}/{len(vals)} flagged ({100*flagged/len(vals):.1f}%)")

        if args.dump_reasons is not None:
            flagged_rows = [r for r in results if r["decision_val"] >= args.dump_reasons]
            print(f"\n  --- flagged commits @ threshold {args.dump_reasons:.2f} ({len(flagged_rows)}) ---")
            for r in sorted(flagged_rows, key=lambda r: -r["decision_val"]):
                print(f"  {r['sha']}  {r['email']:<30} score={r['decision_val']:.3f}")
                for reason in r["top_reasons"][:3]:
                    print(f"      - {reason}")

    print(f"\n=== combined across {len(all_vals)} commits from {len(REPOS)} clean repos ===")
    for t in CANDIDATES:
        flagged = sum(1 for v in all_vals if v >= t)
        print(f"  threshold {t:.2f}: {flagged}/{len(all_vals)} flagged ({100*flagged/len(all_vals):.1f}%)")


if __name__ == "__main__":
    main()
