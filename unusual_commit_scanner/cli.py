"""Command-line entry point.

Usage:
    python -m unusual_commit_scanner <github_user>/<repo> [--limit 200] [--out result.tsv]
    python -m unusual_commit_scanner /path/to/local/repo
"""
import argparse
import os
import shutil
import sys

from git import Repo

from .detect import THRESHOLD, detect
from .extract import extract_commits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", help="GitHub 'user/repo' to clone, or a path to a local git repo")
    ap.add_argument("--limit", type=int, default=200, help="number of most recent commits to score (default 200)")
    ap.add_argument("--out", default=None, help="TSV output path (default: stdout summary only)")
    ap.add_argument("--workdir", default="/tmp/unusual-commit-scanner", help="scratch dir for clones")
    ap.add_argument("--threshold", type=float, default=THRESHOLD, help=f"decision_val cutoff for 'Unusual' (default {THRESHOLD})")
    args = ap.parse_args()

    if os.path.isdir(args.repo) and os.path.isdir(os.path.join(args.repo, ".git")):
        repo = Repo(args.repo)
        label = args.repo
    else:
        url = args.repo if args.repo.startswith("http") else f"https://github.com/{args.repo}.git"
        dest = os.path.join(args.workdir, args.repo.replace("/", "__"))
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.makedirs(args.workdir, exist_ok=True)
        print(f"Cloning {url} -> {dest} ...", file=sys.stderr)
        repo = Repo.clone_from(url, dest)
        label = args.repo

    print("Extracting commit stats ...", file=sys.stderr)
    rows = extract_commits(repo)
    print(f"{len(rows)} non-merge commits found; scoring last {min(args.limit, len(rows))} ...", file=sys.stderr)

    if len(rows) < 2:
        print("Not enough commits to build a baseline distribution.", file=sys.stderr)
        sys.exit(1)

    results = detect(rows, limit=args.limit, threshold=args.threshold)
    unusual = [r for r in results if r["decision"] == "Unusual"]

    print(f"\n{label}: {len(results)} commits scored, {len(unusual)} flagged Unusual (score >= {args.threshold})\n")
    for r in unusual:
        print(f"  {r['sha']}  {r['email']:<30} score={r['decision_val']:.3f}")
        for reason in r["top_reasons_explained"][:3]:
            print(f"      - {reason}")

    if args.out:
        import csv
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(["sha", "email", "decision", "decision_val", "total_loc", "loc_added",
                        "loc_removed", "files_changed", "files_added", "files_removed",
                        "commit_msg_words", "hour_utc", "top_reasons", "top_reasons_explained"])
            for r in results:
                w.writerow([r["sha"], r["email"], r["decision"], r["decision_val"], r["total_loc"],
                            r["loc_added"], r["loc_removed"], r["files_changed"], r["files_added"],
                            r["files_removed"], r["commit_msg_words"], r["hour_utc"],
                            " | ".join(r["top_reasons"]), " | ".join(r["top_reasons_explained"])])
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
