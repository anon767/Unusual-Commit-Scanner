#!/usr/bin/env python3
"""Benchmark guarddog against shai-hulud-detect test-cases.

Ground truth: parsed from shai-hulud-detect/run-tests.sh EXPECTED table.
Exit code 0 -> clean, exit code 1/2 -> malicious. december-2025-attack was
added to their test suite after run-tests.sh last updated -> label by name.
"""
import json, os, re, pathlib, subprocess, sys, time

TC_DIR = pathlib.Path('/home/tom/shai-hulud-detect/test-cases')
RUN_TESTS = pathlib.Path('/home/tom/shai-hulud-detect/run-tests.sh')
GUARDDOG = '/home/tom/.local/bin/guarddog'
OUT_DIR = pathlib.Path('/tmp/gd_bench'); OUT_DIR.mkdir(exist_ok=True)

# --- ground truth ---
truth = {}
for line in RUN_TESTS.read_text().splitlines():
    m = re.match(r'\s*\["([^"]+)"\]="(\d+)\|', line)
    if m:
        truth[m.group(1)] = 'clean' if int(m.group(2)) == 0 else 'malicious'
# missing from EXPECTED but present as dir
truth.setdefault('december-2025-attack', 'malicious')  # -attack by name

# --- pick ecosystem per case ---
def ecosystem(d: pathlib.Path):
    # Prefer npm/pypi (guarddog's strongest); go is supported; others skip.
    if (d/'package.json').exists() or (d/'package-lock.json').exists() or (d/'pnpm-lock.yaml').exists() or (d/'yarn.lock').exists():
        return 'npm'
    if (d/'pyproject.toml').exists() or (d/'setup.py').exists() or (d/'requirements.txt').exists() or (d/'poetry.lock').exists():
        return 'pypi'
    if (d/'go.mod').exists():
        return 'go'
    # scan any nested package.json — some test-cases nest one under a subdir
    for p in d.rglob('package.json'):
        if 'node_modules' not in p.parts:
            return ('npm', p.parent)
    return None

def run_gd(eco, target):
    args = [GUARDDOG, eco, 'scan', '--no-sandbox', '--output-format', 'json', str(target)]
    t0 = time.monotonic()
    try:
        r = subprocess.run(args, capture_output=True, timeout=120)
        dt = time.monotonic() - t0
        raw = r.stdout.decode(errors='replace').strip()
        if not raw:
            return {'ok': False, 'reason': 'empty stdout', 'stderr': r.stderr.decode(errors='replace')[:300], 'dt': dt}
        try:
            j = json.loads(raw)
        except json.JSONDecodeError as e:
            return {'ok': False, 'reason': f'json err: {e}', 'raw': raw[:300], 'dt': dt}
        # collect nonempty rules
        hits = {k: v for k, v in j.get('results', {}).items() if v}
        return {'ok': True, 'rules_fired': list(hits.keys()), 'n_hits': len(hits),
                'errors': j.get('errors'), 'dt': dt}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'reason': 'timeout', 'dt': 120}

# --- iterate ---
results = []
cases = sorted(os.listdir(TC_DIR))
print(f"scanning {len(cases)} cases...", file=sys.stderr)
for i, name in enumerate(cases, 1):
    d = TC_DIR / name
    if not d.is_dir(): continue
    eco = ecosystem(d)
    if eco is None:
        results.append({'name': name, 'gt': truth.get(name, '?'), 'ecosystem': None,
                        'detected': None, 'reason': 'no compatible manifest'})
        print(f"[{i:3}/{len(cases)}] {name:<40} SKIP (no manifest)  gt={truth.get(name)}", file=sys.stderr)
        continue
    if isinstance(eco, tuple):
        eco_name, target = eco
    else:
        eco_name, target = eco, d
    r = run_gd(eco_name, target)
    gt = truth.get(name, '?')
    if r['ok']:
        detected = r['n_hits'] > 0
        verdict = 'malicious' if detected else 'clean'
        outcome = 'TP' if gt=='malicious' and detected else \
                  'TN' if gt=='clean' and not detected else \
                  'FP' if gt=='clean' and detected else \
                  'FN' if gt=='malicious' and not detected else '?'
        results.append({'name': name, 'gt': gt, 'ecosystem': eco_name,
                        'detected': detected, 'verdict': verdict, 'outcome': outcome,
                        'n_hits': r['n_hits'], 'rules_fired': r['rules_fired'], 'dt': r['dt']})
        print(f"[{i:3}/{len(cases)}] {name:<40} {eco_name:<4} n_hits={r['n_hits']:<3} gt={gt:<9} pred={verdict:<9} {outcome}  {r['dt']:.1f}s", file=sys.stderr)
    else:
        results.append({'name': name, 'gt': gt, 'ecosystem': eco_name,
                        'detected': None, 'error': r['reason'], 'dt': r['dt']})
        print(f"[{i:3}/{len(cases)}] {name:<40} {eco_name:<4} ERROR: {r['reason']}", file=sys.stderr)

# --- summary ---
tp = sum(1 for r in results if r.get('outcome')=='TP')
tn = sum(1 for r in results if r.get('outcome')=='TN')
fp = sum(1 for r in results if r.get('outcome')=='FP')
fn = sum(1 for r in results if r.get('outcome')=='FN')
sk = sum(1 for r in results if r.get('detected') is None)

print("", file=sys.stderr)
print("=== confusion matrix (guarddog vs shai-hulud EXPECTED ground truth) ===", file=sys.stderr)
print(f"                    | predicted MAL | predicted CLEAN", file=sys.stderr)
print(f"actual malicious    |     {tp:4}      |     {fn:4}      (recall  = {tp/(tp+fn)*100:.1f}%  if den>0)" if tp+fn else "                    | 0 malicious cases scanned", file=sys.stderr)
print(f"actual clean        |     {fp:4}      |     {tn:4}      (specificity = {tn/(tn+fp)*100:.1f}%  if den>0)" if tn+fp else "                    | 0 clean cases scanned", file=sys.stderr)
print(f"skipped (no manifest): {sk}", file=sys.stderr)
if tp+fp>0:
    print(f"precision:  {tp/(tp+fp)*100:.1f}%", file=sys.stderr)
if tp+fn>0:
    print(f"recall:     {tp/(tp+fn)*100:.1f}%", file=sys.stderr)

json.dump(results, open('/tmp/gd_bench/results.json','w'), indent=2)
print(f"\nfull JSON: /tmp/gd_bench/results.json", file=sys.stderr)
