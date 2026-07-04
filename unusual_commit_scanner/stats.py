"""Statistical rarity scoring: power-law tail fits, circular (von Mises) time-of-day/weekday
density, and the per-metric checks (gap, churn, directory, signing, author/committer mismatch,
filetype) that turn a commit's raw numbers into rarity scores against both global and
per-author history.

Ported from the original goyalr41/UnusualGitCommit Java project (DataStatistics.java,
FileTypeStatistics.java, Detect.java's aggregate/mapping/expocdffitval/timecheck), plus new
rules not in the original (day-of-week, gap, delay, churn, directory, signing, email mismatch).
"""
import math
from collections import defaultdict

import numpy as np

from .models import AuthorHistory, ResultVal

EPS = 1e-6
MIN_LOG_STD = 1.5  # floor below which a fitted log-normal is too tight to be discriminative


def aggregate(a, b):
    return a + b - a * b


def mapping(x):
    return 1 - (1 - x) ** (1.0 / 15.0)


def fit_powerlaw(values):
    """Port of the R snippet used by DataStatistics.java to fit alpha/beta.

    P(X > x) ~= (alpha / x) ** beta  =>  log(1 - ecdf(x)) = beta*log(alpha) - beta*log(x)
    Fitted via ordinary least squares on log(x+eps) vs log(1+eps - ecdf(x)).
    Returns (alpha, beta).
    """
    p = np.array(values, dtype=float)
    if p.max() == p.min():
        p = np.append(p, p.max() + 1)  # avoid a degenerate (zero-variance) ECDF

    sorted_p = np.sort(p)
    # ecdf(x) = fraction of samples <= x
    ecdf = np.searchsorted(sorted_p, p, side="right") / len(p)

    x = np.log(p + EPS)
    y = np.log(1.0 + EPS - ecdf)

    slope, intercept = np.polyfit(x, y, 1)
    beta = -slope
    alpha = math.exp(intercept / beta) if beta != 0 else 0.0
    return alpha, beta


def expocdffitval(value, alpha_g, beta_g, alpha_a, beta_a, exists):
    if value != 0:
        j = 1 - (alpha_g / value) ** beta_g
        if j < 0:
            j = 0.0
    else:
        j = 0.0
    g = mapping(j)

    rds = ResultVal(value=value, globalorg=j, globalmapped=g)

    if exists:
        if value != 0:
            j = 1 - (alpha_a / value) ** beta_a
            if j < 0:
                j = 0.0
        else:
            j = 0.0
    else:
        j = 0.5  # no author profile -> assume median

    rds.authororg = j
    rds.authormapped = mapping(j)
    return rds


def vonmises_density(samples, query, period=24.0, kappa=4.0):
    """Circular KDE density of a set of period-wrapping samples at `query`.

    Hour-of-day (period=24) and day-of-week (period=7) aren't tail-distributed,
    they're circular (23:00/00:00, Sun/Mon are adjacent) and typically
    multimodal -- a von Mises kernel per sample point, averaged, models that
    directly instead of forcing a power-law tail fit onto it.
    """
    theta = np.asarray(samples, dtype=float) / period * 2 * np.pi
    q = query / period * 2 * np.pi
    denom = 2 * np.pi * np.i0(kappa)
    return float(np.mean(np.exp(kappa * np.cos(theta - q))) / denom)


def circular_rarity_check(value, exists, author_samples, period):
    """Shared scorer for hour-of-day / day-of-week: rarity of `value` against
    an author's circular profile of period `period`."""
    rds = ResultVal(value=value)
    if exists and author_samples:
        dens = vonmises_density(author_samples, value, period=period)
        max_dens = max(vonmises_density(author_samples, s, period=period) for s in range(int(period)))
        rarity = 1.0 - (dens / max_dens if max_dens > 0 else 0.0)
        rds.authororg = rarity
        rds.authormapped = mapping(rarity)
    else:
        rds.authororg = 0.5
        rds.authormapped = mapping(0.5)
    rds.globalorg = 0.0
    rds.globalmapped = mapping(0.0)
    return rds


def timecheck(value, exists, author_hours):
    """Score how rare `value` (hour of day, UTC) is against an author's circular commit-time profile."""
    return circular_rarity_check(value, exists, author_hours, period=24.0)


def weekdaycheck(value, exists, author_weekdays):
    """Score how rare `value` (weekday, UTC, 0=Mon) is against an author's circular commit-day profile."""
    return circular_rarity_check(value, exists, author_weekdays, period=7.0)


def tail_prob_z(value, mean, std):
    """Two-sided tail probability of `value` under N(mean, std) in log-space callers
    already applied -- returns ~1.0 for extreme values (either direction), ~0 for typical
    ones. Used for gap/churn rules where both "too fast" and "too slow/skewed" are suspicious.
    """
    if std <= 0:
        return 0.0
    z = abs((value - mean) / std)
    return math.erf(z / math.sqrt(2))


def gapcheck(current_gap, hist_gaps, min_samples=5):
    """Score how unusual the time-since-this-author's-last-commit is (log-normal).

    Both directions are suspicious: a much shorter gap than usual can indicate
    automation/rapid-fire commits, and a much longer gap (dormancy) followed by
    a commit is the pattern seen in real-world dormant-account-takeover backdoors
    (event-stream, colors.js).
    """
    if current_gap is None or len(hist_gaps) < min_samples:
        return ResultVal(authororg=0.5, authormapped=mapping(0.5))
    logs = [math.log(g + 1.0) for g in hist_gaps]
    mean = float(np.mean(logs))
    std = float(np.std(logs, ddof=1)) if len(logs) > 1 else 0.0
    if std < MIN_LOG_STD:
        # e.g. author-vs-commit delay is almost always ~0: near-zero variance
        # makes any nonzero deviation blow the z-score up to a saturated 1.0,
        # which isn't a meaningful signal -- treat as undiscriminative instead.
        return ResultVal(authororg=0.5, authormapped=mapping(0.5))
    j = tail_prob_z(math.log(current_gap + 1.0), mean, std)
    return ResultVal(authororg=j, authormapped=mapping(j))


def churncheck(current_ratio, hist_ratios, min_samples=5):
    """Score how unusual this commit's added:removed LOC ratio is vs. the author's norm.

    Most legitimate edits mix additions and deletions; a commit that's almost
    all insertions (or all deletions) relative to an author's normal churn
    pattern can indicate injected code rather than a real edit.
    """
    if len(hist_ratios) < min_samples:
        return ResultVal(authororg=0.5, authormapped=mapping(0.5))
    mean = float(np.mean(hist_ratios))
    std = float(np.std(hist_ratios, ddof=1)) if len(hist_ratios) > 1 else 0.0
    if std < MIN_LOG_STD:
        return ResultVal(authororg=0.5, authormapped=mapping(0.5))
    j = tail_prob_z(current_ratio, mean, std)
    return ResultVal(authororg=j, authormapped=mapping(j))


def dircheck(top_dirs, dir_counts, total, min_samples=5):
    """Score how rare it is for this author to touch these top-level directories.

    Analogous to the filetype-combo rarity rule but on directory prefixes --
    catches e.g. an author touching `lib/` or `auth/` for the first time ever.
    """
    if total < min_samples or not top_dirs:
        return ResultVal(authororg=0.5, authormapped=mapping(0.5))
    freqs = [dir_counts.get(d, 0) / total for d in set(top_dirs)]
    rarity = 1.0 - min(freqs)
    return ResultVal(authororg=rarity, authormapped=mapping(rarity))


def signingcheck(signed, signed_count, signed_total, min_samples=5):
    """Binary rule: if an author usually GPG-signs and this commit isn't signed, flag it."""
    if signed_total < min_samples:
        return 0.0
    sign_rate = signed_count / signed_total
    return 0.85 if (sign_rate > 0.5 and not signed) else 0.0


def mismatchcheck(mismatch, mismatch_count, mismatch_total, min_samples=5, max_score=0.35):
    """Scored against the author's own history: if this author's commits are
    normally self-committed (author == committer, e.g. they push their own
    work) but this one suddenly isn't, that's a mild account-identity anomaly.

    Weighted down from an earlier flat 0.85: real-world FPR testing (rich,
    requests, click, flask) showed this rule firing constantly on completely
    routine GitHub workflows -- squash-merges/web edits committed as
    noreply@github.com, or a maintainer pushing someone else's patch -- none
    of which are meaningfully suspicious on their own. Scaled proportionally
    to how rare a mismatch is for this author (rarer mismatch -> higher
    score), capped at max_score instead of firing at a flat high value.
    """
    if not mismatch or mismatch_total < min_samples:
        return 0.0
    mismatch_rate = mismatch_count / mismatch_total
    if mismatch_rate >= 0.2:
        return 0.0
    return max_score * (1 - mismatch_rate / 0.2)


def filetypecheck(filetypes, fts, exists):
    """Port of Detect.filetypecheck: returns (filpercentchan, filpercommit, combfrequency, combprobability).

    Averages across the file types (and type-pairs) actually present in the
    commit, rather than taking the worst-case minimum across them. The
    original min()-based version meant a single rare/never-seen extension
    mixed in among several ordinary ones (e.g. one new CI yaml alongside
    routine .py changes) tanked the whole commit's score -- so every extra
    distinct file type in a commit was one more chance to trip the rule,
    which over-fired constantly on ordinary multi-file-kind commits (FPR
    testing against rich/requests/click/flask). Averaging means a commit is
    only scored as rare if its file types are *rare on the whole*, not if
    it happens to touch >1 kind of file.
    """
    filecounts = defaultdict(int)
    for ft in filetypes:
        filecounts[ft] += 1
    combinations = sorted(filecounts.keys())

    filpercentchan = ResultVal(valuestrglb="NA", globalorg=100.0, valuestrauth="NA", authororg=100.0)
    filpercommit = ResultVal(valuestrglb="NA", globalorg=1.0, valuestrauth="NA", authororg=1.0)

    pct_vals_g, cnt_vals_g = [], []
    pct_vals_a, cnt_vals_a = [], []

    # Track the single rarest file type too -- only for narration (which
    # extension to name in a human-readable reason), never fed back into the
    # averaged score itself.
    rarest_pct_g = rarest_cnt_g = None
    rarest_pct_a = rarest_cnt_a = None

    for ft in filecounts:
        v_pct_g = fts.map_file_pct_changed.get(ft, 0.0)
        v_cnt_g = fts.map_file_commit_changed[ft] / fts.total_commits if ft in fts.map_file_commit_changed else 0.0
        pct_vals_g.append(v_pct_g)
        cnt_vals_g.append(v_cnt_g)
        if rarest_pct_g is None or v_pct_g < rarest_pct_g[0]:
            rarest_pct_g = (v_pct_g, ft)
        if rarest_cnt_g is None or v_cnt_g < rarest_cnt_g[0]:
            rarest_cnt_g = (v_cnt_g, ft)

        if exists:
            v_pct_a = fts.map_auth_file_pct_changed.get(ft, 0.0)
            v_cnt_a = (
                fts.map_auth_file_commit_changed[ft] / fts.author_total_commits
                if ft in fts.map_auth_file_commit_changed else 0.0
            )
            pct_vals_a.append(v_pct_a)
            cnt_vals_a.append(v_cnt_a)
            if rarest_pct_a is None or v_pct_a < rarest_pct_a[0]:
                rarest_pct_a = (v_pct_a, ft)
            if rarest_cnt_a is None or v_cnt_a < rarest_cnt_a[0]:
                rarest_cnt_a = (v_cnt_a, ft)

    if pct_vals_g:
        filpercentchan.globalorg = sum(pct_vals_g) / len(pct_vals_g)
        filpercentchan.valuestrglb = rarest_pct_g[1]
    if cnt_vals_g:
        filpercommit.globalorg = sum(cnt_vals_g) / len(cnt_vals_g)
        filpercommit.valuestrglb = rarest_cnt_g[1]

    if exists:
        filpercentchan.authororg = sum(pct_vals_a) / len(pct_vals_a) if pct_vals_a else 100.0
        filpercommit.authororg = sum(cnt_vals_a) / len(cnt_vals_a) if cnt_vals_a else 1.0
        if pct_vals_a:
            filpercentchan.valuestrauth = rarest_pct_a[1]
        if cnt_vals_a:
            filpercommit.valuestrauth = rarest_cnt_a[1]
    else:
        filpercentchan.authororg = 100.0
        filpercommit.authororg = 1.0

    combfrequency = ResultVal(valuestrglb="NA", globalorg=1.0, valuestrauth="NA", authororg=1.0)
    combprobability = ResultVal(valuestrglb="NA", globalorg=1.0, valuestrauth="NA", authororg=1.0)

    freq_vals_g, freq_vals_a = [], []
    prob_vals_g, prob_vals_a = [], []
    rarest_freq_g = rarest_prob_g = rarest_freq_a = rarest_prob_a = None

    for s in range(len(combinations)):
        for u in range(s + 1, len(combinations)):
            key = f"{combinations[s]},{combinations[u]}"

            v_freq_g = len(fts.twocombinations[key]) / fts.total_commits if key in fts.twocombinations else 0.0
            freq_vals_g.append(v_freq_g)
            if rarest_freq_g is None or v_freq_g < rarest_freq_g[0]:
                rarest_freq_g = (v_freq_g, key)

            if key in fts.meanmap and key in fts.sdtmap:
                chck = math.log10(filecounts[combinations[s]] / filecounts[combinations[u]])
                denom = chck - fts.meanmap[key]
                v_prob_g = (fts.sdtmap[key] ** 2) / (denom ** 2) if denom != 0 else 1.0
                prob_vals_g.append(v_prob_g)
                if rarest_prob_g is None or v_prob_g < rarest_prob_g[0]:
                    rarest_prob_g = (v_prob_g, key)

            if exists:
                v_freq_a = (
                    len(fts.auth_twocombinations[key]) / fts.author_total_commits
                    if key in fts.auth_twocombinations else 0.0
                )
                freq_vals_a.append(v_freq_a)
                if rarest_freq_a is None or v_freq_a < rarest_freq_a[0]:
                    rarest_freq_a = (v_freq_a, key)

                if key in fts.auth_meanmap and key in fts.auth_sdtmap:
                    chck = math.log10(filecounts[combinations[s]] / filecounts[combinations[u]])
                    denom = chck - fts.auth_meanmap[key]
                    v_prob_a = (fts.auth_sdtmap[key] ** 2) / (denom ** 2) if denom != 0 else 1.0
                    prob_vals_a.append(v_prob_a)
                    if rarest_prob_a is None or v_prob_a < rarest_prob_a[0]:
                        rarest_prob_a = (v_prob_a, key)

    if freq_vals_g:
        combfrequency.globalorg = sum(freq_vals_g) / len(freq_vals_g)
        combfrequency.valuestrglb = rarest_freq_g[1]
    if prob_vals_g:
        combprobability.globalorg = sum(prob_vals_g) / len(prob_vals_g)
        combprobability.valuestrglb = rarest_prob_g[1]

    if exists:
        combfrequency.authororg = sum(freq_vals_a) / len(freq_vals_a) if freq_vals_a else 1.0
        combprobability.authororg = sum(prob_vals_a) / len(prob_vals_a) if prob_vals_a else 1.0
        if freq_vals_a:
            combfrequency.valuestrauth = rarest_freq_a[1]
        if prob_vals_a:
            combprobability.valuestrauth = rarest_prob_a[1]
    else:
        combfrequency.authororg = 1.0
        combprobability.authororg = 1.0

    filpercentchan.globalmapped = mapping(1.0 - filpercentchan.globalorg / 100.0)
    filpercommit.globalmapped = mapping(1.0 - filpercommit.globalorg)
    combfrequency.globalmapped = mapping(1.0 - combfrequency.globalorg)
    combprobability.globalmapped = mapping(1.0 - combprobability.globalorg)

    filpercentchan.authormapped = mapping(1.0 - filpercentchan.authororg / 100.0)
    filpercommit.authormapped = mapping(1.0 - filpercommit.authororg)
    combfrequency.authormapped = mapping(1.0 - combfrequency.authororg)
    combprobability.authormapped = mapping(1.0 - combprobability.authororg)

    return filpercentchan, filpercommit, combfrequency, combprobability


class DataStatistics:
    METRICS = ["total_loc", "loc_added", "loc_removed", "files_changed",
               "files_added", "files_removed", "commit_msg_words"]

    def __init__(self, rows):
        self.rows = rows
        self.global_fit = {}
        self.author_fit = {}
        self.author_time_fit = {}

    def calc_global(self):
        for m in self.METRICS:
            vals = [getattr(r, m) for r in self.rows]
            self.global_fit[m] = fit_powerlaw(vals)

    def calc_author(self, email):
        auth_rows = [r for r in self.rows if r.email == email]
        fit = {}
        for m in self.METRICS:
            vals = [getattr(r, m) for r in auth_rows]
            fit[m] = fit_powerlaw(vals)
        self.author_fit[email] = fit
        self.author_time_fit[email] = fit_powerlaw([r.hour_utc for r in auth_rows])
        return fit


class FileTypeStatistics:
    def __init__(self, rows):
        self.rows = rows
        self.total_commits = len(rows)
        self.map_file_pct_changed = {}
        self.map_file_commit_changed = {}
        self.twocombinations = {}
        self.meanmap = {}
        self.sdtmap = {}

        self.author_total_commits = 0
        self.map_auth_file_pct_changed = {}
        self.map_auth_file_commit_changed = {}
        self.auth_twocombinations = {}
        self.auth_meanmap = {}
        self.auth_sdtmap = {}
        self.author_hours = []

    def calc_global(self):
        counts = defaultdict(int)
        for r in self.rows:
            for ft in r.filetypes:
                counts[ft] += 1
        total = sum(counts.values()) or 1
        self.map_file_pct_changed = {k: v * 100.0 / total for k, v in counts.items()}

        commit_counts = defaultdict(int)
        for r in self.rows:
            for ft in set(r.filetypes):
                commit_counts[ft] += 1
        self.map_file_commit_changed = dict(commit_counts)

        self._combinations(self.rows, self.twocombinations)
        self.meanmap, self.sdtmap = self._combination_stats(self.twocombinations)

    def calc_author(self, email):
        auth_rows = [r for r in self.rows if r.email == email]
        self.author_total_commits = len(auth_rows)

        counts = defaultdict(int)
        for r in auth_rows:
            for ft in r.filetypes:
                counts[ft] += 1
        total = sum(counts.values()) or 1
        self.map_auth_file_pct_changed = {k: v * 100.0 / total for k, v in counts.items()}

        commit_counts = defaultdict(int)
        for r in auth_rows:
            for ft in set(r.filetypes):
                commit_counts[ft] += 1
        self.map_auth_file_commit_changed = dict(commit_counts)

        self._combinations(auth_rows, self.auth_twocombinations)
        self.auth_meanmap, self.auth_sdtmap = self._combination_stats(self.auth_twocombinations)

        profile_rows = auth_rows[:-1] if len(auth_rows) > 1 else auth_rows
        self.author_hours = [r.hour_utc for r in profile_rows]

    @staticmethod
    def _combinations(rows, out):
        for r in rows:
            counts = defaultdict(int)
            for ft in r.filetypes:
                counts[ft] += 1
            types = sorted(counts.keys())
            for s in range(len(types)):
                for u in range(s + 1, len(types)):
                    key = f"{types[s]},{types[u]}"
                    out.setdefault(key, []).append((counts[types[s]], counts[types[u]]))

    @staticmethod
    def _combination_stats(combos, min_samples=10):
        meanmap, sdtmap = {}, {}
        for key, pairs in combos.items():
            if len(pairs) < min_samples:
                continue
            ratios = [math.log10(a / b) for a, b in pairs]
            meanmap[key] = float(np.mean(ratios))
            sdtmap[key] = float(np.std(ratios, ddof=1)) if len(ratios) > 1 else 0.0
        return meanmap, sdtmap


def build_author_history(rows, email):
    auth_rows = [r for r in rows if r.email == email]
    profile_rows = auth_rows[:-1] if len(auth_rows) > 1 else auth_rows
    dir_counts = defaultdict(int)
    for r in profile_rows:
        for d in set(r.top_dirs):
            dir_counts[d] += 1
    return AuthorHistory(
        weekdays=[r.weekday_utc for r in profile_rows],
        gaps=[r.gap_seconds for r in profile_rows if r.gap_seconds is not None],
        delays=[r.commit_delay_seconds for r in profile_rows],
        churn_ratios=[r.churn_ratio for r in profile_rows],
        dir_counts=dict(dir_counts),
        total=len(profile_rows),
        signed_count=sum(1 for r in profile_rows if r.gpg_signed),
        signed_total=len(profile_rows),
        mismatch_count=sum(1 for r in profile_rows if r.author_committer_mismatch),
        mismatch_total=len(profile_rows),
    )
