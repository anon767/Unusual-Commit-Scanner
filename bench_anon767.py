#!/usr/bin/env python3
"""Benchmark guarddog against anon767/experiments branches.

Ground truth: all listed branches are labeled MALICIOUS by the user.
Only recall matters here (no clean branches in the set).
"""
import json, os, pathlib, subprocess, sys, time

REPO = pathlib.Path('/tmp/anon767-experiments')
GUARDDOG = '/home/tom/.local/bin/guarddog'
OUT = pathlib.Path('/tmp/gd_bench'); OUT.mkdir(exist_ok=True)
WT_ROOT = pathlib.Path('/tmp/anon767-wts'); WT_ROOT.mkdir(exist_ok=True)

BRANCHES = [
    '0','1','2','3','4','5','6',
    '14','16','17',
    '21','22','24','25','26','28','29',
    '31','32','33','34',
    '37','38','39','40','41','42','43','44','45','46','47','48',
    '50','51','52','53','54','55','56','57','58',
]

def ecosystem(d: pathlib.Path):
    if (d/'package.json').exists() or (d/'package-lock.json').exists() or (d/'yarn.lock').exists() or (d/'pnpm-lock.yaml').exists():
        return ('npm', d)
    if (d/'pyproject.toml').exists() or (d/'setup.py').exists() or (d/'requirements.txt').exists() or (d/'poetry.lock').exists():
        return ('pypi', d)
    if (d/'go.mod').exists():
        return ('go', d)
    for p in d.rglob('package.json'):
        if 'node_modules' not in p.parts:
            return ('npm', p.parent)
    for p in d.rglob('pyproject.toml'):
        return ('pypi', p.parent)
    return None

def run_gd(eco, target):
    args = [GUARDDOG, eco, 'scan', '--no-sandbox', '--output-format', 'json', str(target)]
    t0 = time.monotonic()
    try:
        r = subprocess.run(args, capture_output=True, timeout=120)
        dt = time.monotonic() - t0
        raw = r.stdout.decode(errors='replace').strip()
        if not raw:
            return {'ok': False, 'reason': 'empty stdout', 'stderr': r.stderr.decode(errors='replace')[:200], 'dt': dt}
        try:
            j = json.loads(raw)
        except json.JSONDecodeError as e:
            return {'ok': False, 'reason': f'json err: {e}', 'raw': raw[:200], 'dt': dt}
        hits = {k: v for k, v in j.get('results', {}).items() if v}
        return {'ok': True, 'rules_fired': list(hits.keys()), 'n_hits': len(hits),
                'errors': j.get('errors'), 'dt': dt}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'reason': 'timeout', 'dt': 120}

# --- run ---
results = []
print(f"scanning {len(BRANCHES)} branches of anon767/experiments...", file=sys.stderr)
os.chdir(REPO)

# clean up any old worktrees
subprocess.run(['git', 'worktree', 'prune'], capture_output=True)

for i, br in enumerate(BRANCHES, 1):
    wt = WT_ROOT / f'wt-{br}'
    if wt.exists():
        subprocess.run(['git', 'worktree', 'remove', '--force', str(wt)], capture_output=True)
    # add worktree at that branch
    r = subprocess.run(['git', 'worktree', 'add', '-f', '--detach', str(wt), f'origin/{br}'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        results.append({'branch': br, 'gt': 'malicious', 'ecosystem': None,
                        'error': f'worktree failed: {r.stderr.strip()[:200]}'})
        print(f"[{i:2}/{len(BRANCHES)}] br={br:<4} WORKTREE FAIL: {r.stderr.strip()[:100]}", file=sys.stderr)
        continue

    eco = ecosystem(wt)
    if eco is None:
        # sniff dir contents for hint
        top = sorted([p.name for p in wt.iterdir() if not p.name.startswith('.')])[:6]
        results.append({'branch': br, 'gt': 'malicious', 'ecosystem': None,
                        'reason': 'no compatible manifest', 'top': top})
        print(f"[{i:2}/{len(BRANCHES)}] br={br:<4} SKIP (no manifest) top={top}", file=sys.stderr)
        subprocess.run(['git', 'worktree', 'remove', '--force', str(wt)], capture_output=True)
        continue
    eco_name, target = eco
    r = run_gd(eco_name, target)
    if r['ok']:
        detected = r['n_hits'] > 0
        outcome = 'TP' if detected else 'FN'  # all ground-truth malicious
        results.append({'branch': br, 'gt': 'malicious', 'ecosystem': eco_name,
                        'detected': detected, 'outcome': outcome,
                        'n_hits': r['n_hits'], 'rules_fired': r['rules_fired'], 'dt': r['dt']})
        print(f"[{i:2}/{len(BRANCHES)}] br={br:<4} {eco_name:<4} n_hits={r['n_hits']:<3} {outcome}  {r['dt']:.1f}s", file=sys.stderr)
    else:
        results.append({'branch': br, 'gt': 'malicious', 'ecosystem': eco_name,
                        'detected': None, 'error': r['reason'], 'dt': r['dt']})
        print(f"[{i:2}/{len(BRANCHES)}] br={br:<4} {eco_name:<4} ERROR: {r['reason']}", file=sys.stderr)
    subprocess.run(['git', 'worktree', 'remove', '--force', str(wt)], capture_output=True)

# summary
tp = sum(1 for r in results if r.get('outcome')=='TP')
fn = sum(1 for r in results if r.get('outcome')=='FN')
sk = sum(1 for r in results if r.get('detected') is None)
print("", file=sys.stderr)
print("=== guarddog vs anon767/experiments (all branches labeled malicious) ===", file=sys.stderr)
print(f"total branches:  {len(BRANCHES)}", file=sys.stderr)
print(f"TP (detected):   {tp}", file=sys.stderr)
print(f"FN (missed):     {fn}", file=sys.stderr)
print(f"errors/skipped:  {sk}", file=sys.stderr)
if tp+fn > 0:
    print(f"recall:          {tp/(tp+fn)*100:.1f}%  (of scannable branches)", file=sys.stderr)

json.dump(results, open('/tmp/gd_bench/anon767_results.json','w'), indent=2)
print(f"full JSON: /tmp/gd_bench/anon767_results.json", file=sys.stderr)
