#!/bin/bash
cd /tmp/experiments_scan
for b in 19 20 21 22 23 24 25 26 27 28 29 3 30 31 32 33 34 35 36 37 38 39 4 40 41 42 43 44 45 46 47 48 49 5 50 51 52 53 54 55 56 57 58 6 7 8 9; do
  git checkout -f "$b" >/tmp/exp_results/checkout_$b.log 2>&1
  echo "=== branch $b ===" >> /tmp/exp_results/summary.txt
  timeout 90 python3 /home/tom/unusual_git_commit.py /tmp/experiments_scan --out /tmp/exp_results/branch_$b.tsv >> /tmp/exp_results/summary.txt 2>&1
  echo "" >> /tmp/exp_results/summary.txt
done
echo ALL_DONE >> /tmp/exp_results/summary.txt
