#!/usr/bin/env python3
"""Plot the guarddog benchmark results — 6 charts to /tmp/gd_bench/plots/."""
import json, pathlib, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = pathlib.Path('/tmp/gd_bench/plots'); OUT.mkdir(parents=True, exist_ok=True)
shai = json.load(open('/tmp/gd_bench/results.json'))
anon = json.load(open('/tmp/gd_bench/anon767_results.json'))

plt.rcParams.update({
    'font.size': 11, 'axes.spines.top': False, 'axes.spines.right': False,
    'axes.grid': True, 'grid.alpha': 0.25, 'figure.facecolor': 'white',
})

# ============================================================================
# 1. Shai-hulud confusion matrix (heat map)
# ============================================================================
def cm(r):
    tp = sum(1 for x in r if x.get('outcome')=='TP')
    fn = sum(1 for x in r if x.get('outcome')=='FN')
    fp = sum(1 for x in r if x.get('outcome')=='FP')
    tn = sum(1 for x in r if x.get('outcome')=='TN')
    sk = sum(1 for x in r if x.get('outcome') is None)
    return tp, fn, fp, tn, sk

tp, fn, fp, tn, sk = cm(shai)

fig, ax = plt.subplots(figsize=(6.5, 5))
mat = np.array([[tp, fn], [fp, tn]])
ax.imshow(mat, cmap='Blues', aspect='auto')
for i in range(2):
    for j in range(2):
        color = 'white' if mat[i, j] > mat.max()/2 else 'black'
        ax.text(j, i, str(mat[i, j]), ha='center', va='center', fontsize=28, color=color, weight='bold')
ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
ax.set_xticklabels(['flagged malicious', 'flagged clean'])
ax.set_yticklabels(['actually malicious', 'actually clean'])
ax.set_title(f'guarddog vs shai-hulud test-cases\n(precision {tp/(tp+fp)*100:.1f}% · recall {tp/(tp+fn)*100:.1f}% · {sk} skipped)', pad=15)
ax.grid(False)
plt.tight_layout(); plt.savefig(OUT/'1_shai_confusion.png', dpi=120); plt.close()

# ============================================================================
# 2. Recall comparison — the headline
# ============================================================================
fig, ax = plt.subplots(figsize=(7, 4.5))
labels = ['shai-hulud\ntest-cases\n(80 cases)', 'anon767/experiments\nbranches\n(42 branches)']
recalls = [tp/(tp+fn)*100, sum(1 for x in anon if x.get('outcome')=='TP') /
           (sum(1 for x in anon if x.get('outcome') in ('TP','FN')) or 1) * 100]
colors = ['#d94a4a', '#3aa03a']
bars = ax.bar(labels, recalls, color=colors, edgecolor='black', linewidth=0.6)
for b, v in zip(bars, recalls):
    ax.text(b.get_x()+b.get_width()/2, v+2, f'{v:.1f}%', ha='center', fontsize=14, weight='bold')
ax.set_ylabel('Recall (% of malicious samples correctly flagged)')
ax.set_ylim(0, 105)
ax.set_title('guarddog detection rate — where it works vs where it doesn\'t', pad=10)
ax.axhline(50, color='gray', linestyle='--', alpha=0.4)
plt.tight_layout(); plt.savefig(OUT/'2_recall_comparison.png', dpi=120); plt.close()

# ============================================================================
# 3. Outcome breakdown per corpus — grouped bar
# ============================================================================
fig, ax = plt.subplots(figsize=(9, 4.5))
categories = ['TP\n(correct catch)', 'FN\n(missed)', 'TN\n(correct pass)', 'FP\n(wrong flag)', 'Skipped\n(no manifest)']
shai_counts = [tp, fn, tn, fp, sk]
a_tp = sum(1 for x in anon if x.get('outcome')=='TP')
a_fn = sum(1 for x in anon if x.get('outcome')=='FN')
a_sk = sum(1 for x in anon if x.get('outcome') is None)
anon_counts = [a_tp, a_fn, 0, 0, a_sk]  # no clean cases in anon767

x = np.arange(len(categories)); w = 0.38
b1 = ax.bar(x - w/2, shai_counts, w, label='shai-hulud (80)', color='#4a89d9', edgecolor='black', linewidth=0.4)
b2 = ax.bar(x + w/2, anon_counts, w, label='anon767 (42)',    color='#f0a03a', edgecolor='black', linewidth=0.4)
for b in list(b1)+list(b2):
    if b.get_height() > 0:
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+0.4, str(int(b.get_height())), ha='center', fontsize=10)
ax.set_xticks(x); ax.set_xticklabels(categories)
ax.set_ylabel('# cases')
ax.set_title('Per-corpus outcome breakdown')
ax.legend()
plt.tight_layout(); plt.savefig(OUT/'3_outcome_breakdown.png', dpi=120); plt.close()

# ============================================================================
# 4. Guarddog rules — which fired most often across all TPs (both corpora)
# ============================================================================
rule_counts = collections.Counter()
for x in shai + anon:
    if x.get('outcome') == 'TP':
        for r in x.get('rules_fired', []):
            rule_counts[r] += 1

top = rule_counts.most_common(15)
fig, ax = plt.subplots(figsize=(9, 6))
names = [n.replace('threat-', '').replace('capability-', '(cap) ') for n, _ in reversed(top)]
counts = [c for _, c in reversed(top)]
ax.barh(names, counts, color='#4a89d9', edgecolor='black', linewidth=0.4)
for i, c in enumerate(counts):
    ax.text(c+0.15, i, str(c), va='center', fontsize=10)
ax.set_xlabel('# times fired across TP cases (both corpora)')
ax.set_title('Top guarddog rules driving detections')
plt.tight_layout(); plt.savefig(OUT/'4_top_rules.png', dpi=120); plt.close()

# ============================================================================
# 5. anon767 branch grid — one cell per branch, colored by outcome
# ============================================================================
outcomes = {x['branch']: x for x in anon}
branches = ['0','1','2','3','4','5','6','14','16','17','21','22','24','25','26','28','29',
            '31','32','33','34','37','38','39','40','41','42','43','44','45','46','47','48',
            '50','51','52','53','54','55','56','57','58']
COLS = 7; ROWS = (len(branches) + COLS - 1) // COLS
fig, ax = plt.subplots(figsize=(9, ROWS*1.1+0.6))
cmap = {'TP': '#3aa03a', 'FN': '#d94a4a', None: '#9b9b9b'}
for i, br in enumerate(branches):
    row = i // COLS; col = i % COLS
    o = outcomes.get(br, {}).get('outcome')
    color = cmap.get(o, '#9b9b9b')
    ax.add_patch(plt.Rectangle((col, ROWS-row-1), 0.95, 0.95, facecolor=color, edgecolor='black', linewidth=0.6))
    ax.text(col+0.475, ROWS-row-1+0.65, br, ha='center', va='center', fontsize=14, color='white', weight='bold')
    label = o or 'no-manifest'
    ax.text(col+0.475, ROWS-row-1+0.25, label, ha='center', va='center', fontsize=8, color='white')
ax.set_xlim(0, COLS); ax.set_ylim(0, ROWS)
ax.set_aspect('equal'); ax.axis('off'); ax.grid(False)
handles = [plt.Rectangle((0,0),1,1,color=c) for c in ['#3aa03a','#d94a4a','#9b9b9b']]
ax.legend(handles, ['TP — detected','FN — missed','no compatible manifest'],
          loc='lower center', bbox_to_anchor=(0.5, -0.06), ncol=3, frameon=False)
ax.set_title('anon767/experiments — per-branch outcome (all branches labeled malicious)')
plt.tight_layout(); plt.savefig(OUT/'5_anon767_grid.png', dpi=120); plt.close()

# ============================================================================
# 6. Per-ecosystem detection rate — grouped by npm/pypi/go, per corpus
# ============================================================================
def eco_rates(data):
    stats = collections.defaultdict(lambda: [0, 0])  # [tp+fn total, tp]
    for x in data:
        eco = x.get('ecosystem')
        if not eco: continue
        o = x.get('outcome')
        if o == 'TP':
            stats[eco][0] += 1; stats[eco][1] += 1
        elif o == 'FN':
            stats[eco][0] += 1
    return {e: (t[1]/t[0]*100 if t[0] else 0, t[0]) for e, t in stats.items()}

s_eco = eco_rates(shai); a_eco = eco_rates(anon)
ecos = sorted(set(s_eco) | set(a_eco))
x = np.arange(len(ecos)); w = 0.38
fig, ax = plt.subplots(figsize=(8, 4.5))
sh = [s_eco.get(e, (0,0))[0] for e in ecos]
an = [a_eco.get(e, (0,0))[0] for e in ecos]
b1 = ax.bar(x - w/2, sh, w, label='shai-hulud', color='#4a89d9', edgecolor='black', linewidth=0.4)
b2 = ax.bar(x + w/2, an, w, label='anon767', color='#f0a03a', edgecolor='black', linewidth=0.4)
for i, (bar, val, n) in enumerate(zip(b1, sh, [s_eco.get(e,(0,0))[1] for e in ecos])):
    ax.text(bar.get_x()+bar.get_width()/2, val+1.5, f'{val:.0f}%\n(n={n})', ha='center', fontsize=9)
for i, (bar, val, n) in enumerate(zip(b2, an, [a_eco.get(e,(0,0))[1] for e in ecos])):
    ax.text(bar.get_x()+bar.get_width()/2, val+1.5, f'{val:.0f}%\n(n={n})', ha='center', fontsize=9)
ax.set_xticks(x); ax.set_xticklabels([e.upper() for e in ecos])
ax.set_ylabel('Recall (%)')
ax.set_ylim(0, 118)
ax.set_title('Per-ecosystem recall (only cases with a compatible manifest)')
ax.legend()
plt.tight_layout(); plt.savefig(OUT/'6_per_ecosystem.png', dpi=120); plt.close()

# summary
print("plots written:")
for p in sorted(OUT.glob('*.png')):
    print(f"  {p}  ({p.stat().st_size//1024}k)")
