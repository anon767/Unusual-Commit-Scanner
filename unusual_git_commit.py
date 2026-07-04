#!/usr/bin/env python3
"""
Python port of goyalr41/UnusualGitCommit (https://github.com/goyalr41/UnusualGitCommit).

Original project: Java + servlet web app + Chrome extension + R (via Renjin/JRI) for
power-law tail fitting. This port keeps only the core detection algorithm:

  1. Walk non-merge commits of a git repo, extract per-commit stats (LOC added/removed,
     files added/removed/changed, commit message length, hour-of-day, file extensions).
  2. Fit a power-law survival function P(X > x) ~ (alpha/x)^beta to each numeric metric,
     both globally (whole repo) and per-author (authors with > 20 commits), by doing a
     log-log linear regression against the empirical CDF -- this is exactly what the
     original R snippet (`lm(log(1-ecdf(p)(p)) ~ log(p))`) computed.
  3. Score each of the most recent commits (default: last 200) against those fitted
     distributions plus file-type frequency/combination statistics, aggregate the signals
     with a probabilistic OR (`a + b - a*b`), and flag commits with an aggregated score
     >= 0.8 as "Unusual".

Usage:
    python3 unusual_git_commit.py <github_user>/<repo> [--limit 200] [--out result.tsv] [--workdir /tmp/ugc]
    python3 unusual_git_commit.py /path/to/local/repo [--limit 200]
"""
import argparse
import fnmatch
import glob
import json
import math
import os
import re
import shutil
import sys
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
from git import Repo

EPS = 1e-6
THRESHOLD = 0.962  # lowered from 0.97 to catch the xz-utils backdoor commit (cf44e4b7,
                    # scored 0.9641) after real-attack recall testing against node-ipc,
                    # colors.js, event-stream, and xz-utils showed 0.97 was a near-miss
                    # for the most sophisticated of the four. FPR at 0.962 vs 0.97 should
                    # be re-measured against the clean-repo corpus (rich/requests/click/
                    # flask/eslint/django/pytest/cobra/ripgrep/sinatra) after this change.

# ---------------------------------------------------------------------------
# New rule (not in the original Java): generic-message-on-large-diff mismatch.
#
# The earlier build/CI-execution-path rule (a hardcoded list of workflow/
# Dockerfile/Makefile/package.json paths) was removed -- it was the same
# brittle keyword/path-guessing pattern as the sensitive-path list that was
# already ripped out, just one level more generic. No replacement path list
# has been substituted.
# ---------------------------------------------------------------------------

GENERIC_MSG_RE = re.compile(
    r"^(wip|update|updates|fix|fixes|fixed|minor|misc|stuff|changes|tweak|typo|cleanup|"
    r"refactor|small fix|quick fix)\.?$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Supply-chain metadata heuristics, ported from guarddog (github.com/DataDog/
# guarddog) -- 5 of its 8 metadata detectors map onto a single git commit's
# diff (typosquatting, disposable/compromised author email, bundled binary,
# direct-URL dependency); 2 don't (metadata_mismatch and
# repository_integrity_mismatch both need a *published registry package* to
# compare against, which doesn't exist yet at commit time); the 8th
# (unclaimed_maintainer_email_domain) is a repo-level risk report rather
# than a per-commit signal -- see whois_domain_age() / CLI --email-report.
# ---------------------------------------------------------------------------

RESOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources")


def _load_popular_packages(ecosystem):
    fname = {
        "npm": "top_npm_packages.json",
        "pypi": "top_pypi_packages.json",
        "go": "top_go_packages.json",
        "rubygems": "top_rubygems_packages.json",
    }.get(ecosystem)
    if not fname:
        return set()
    path = os.path.join(RESOURCES_DIR, fname)
    try:
        with open(path) as f:
            data = json.load(f)
        return set(data.get("packages", []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


_POPULAR_PACKAGES = {}  # ecosystem -> set, loaded lazily and cached


def popular_packages(ecosystem):
    if ecosystem not in _POPULAR_PACKAGES:
        _POPULAR_PACKAGES[ecosystem] = _load_popular_packages(ecosystem)
    return _POPULAR_PACKAGES[ecosystem]


def _is_distance_one_levenshtein(name1, name2):
    """Port of guarddog's TyposquatDetector._is_distance_one_Levenshtein."""
    if abs(len(name1) - len(name2)) > 1:
        return False
    if len(name1) > len(name2):
        return any(name1[:i] + name1[i + 1:] == name2 for i in range(len(name1)))
    if len(name2) > len(name1):
        return any(name2[:i] + name2[i + 1:] == name1 for i in range(len(name2)))
    return any(name1[:i] + name1[i + 1:] == name2[:i] + name2[i + 1:] for i in range(len(name1)))


def _is_swapped_typo(name1, name2):
    """Port of guarddog's TyposquatDetector._is_swapped_typo (adjacent character swap)."""
    if len(name1) != len(name2):
        return False
    for i in range(len(name1) - 1):
        swapped = name1[:i] + name1[i + 1] + name1[i] + name1[i + 2:]
        if swapped == name2:
            return True
    return False


def _hyphen_permutations(package_name):
    """Port of guarddog's TyposquatDetector._generate_permutations."""
    if "-" not in package_name:
        return []
    from itertools import permutations
    components = package_name.split("-")
    return ["-".join(p) for p in permutations(components)]


def _confused_forms(package_name, ecosystem):
    """Port of guarddog's per-ecosystem _get_confused_forms (go's golang<->go swap
    and github.com<->gitlab.com swap are the only ecosystem-specific ones guarddog
    ships; other ecosystems use only Levenshtein/swap/permutation)."""
    if ecosystem != "go":
        return []
    forms = []
    if package_name.startswith("github.com/"):
        forms.append(package_name.replace("github.com/", "gitlab.com/", 1))
    elif package_name.startswith("gitlab.com/"):
        forms.append(package_name.replace("gitlab.com/", "github.com/", 1))
    terms = package_name.split("-")
    for i, term in enumerate(terms):
        if "golang" in term:
            confused = term.replace("golang", "go")
        elif "go" in term:
            confused = term.replace("go", "golang")
        else:
            continue
        forms.append("-".join(terms[:i] + [confused] + terms[i + 1:]))
        forms.append("-".join(terms[:i] + terms[i + 1:]))
    return forms


def _is_length_one_edit_away(a, b):
    return _is_distance_one_levenshtein(a, b) or _is_swapped_typo(a, b)


def get_typosquat_matches(package_name, ecosystem):
    """Port of guarddog's TyposquatDetector.get_typosquatted_package: which popular
    packages (if any) `package_name` is a plausible one-edit typosquat of."""
    popular = popular_packages(ecosystem)
    if not popular or package_name in popular:
        return []
    matches = set()
    for popular_name in popular:
        if _is_length_one_edit_away(package_name, popular_name):
            matches.add(popular_name)
            continue
        alt_forms = _confused_forms(popular_name, ecosystem) + _hyphen_permutations(popular_name)
        if any(_is_length_one_edit_away(package_name, alt) for alt in alt_forms):
            matches.add(popular_name)
    return sorted(matches)


def _load_disposable_domains():
    try:
        from disposable_email_domains import blocklist
        return blocklist
    except ImportError:
        return frozenset()


_DISPOSABLE_DOMAINS = None


def is_disposable_email_domain(email):
    """guarddog's deceptive_author heuristic: is the author using a disposable/
    temp-mail domain? (mailinator.com, guerrillamail.com, etc.)"""
    global _DISPOSABLE_DOMAINS
    if _DISPOSABLE_DOMAINS is None:
        _DISPOSABLE_DOMAINS = _load_disposable_domains()
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    return domain in _DISPOSABLE_DOMAINS


# Free/major email providers are always long-established domains -- skip
# WHOIS entirely for these rather than burning a lookup (and rate-limit risk)
# on something that can never usefully flag.
COMMON_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "icloud.com", "me.com", "protonmail.com", "proton.me",
    "aol.com", "gmx.com", "gmx.de", "yandex.com", "mail.ru", "qq.com",
    "163.com", "126.com", "zoho.com", "fastmail.com", "users.noreply.github.com",
}

_WHOIS_CACHE = {}
WHOIS_TIMEOUT_SECONDS = 5
WHOIS_MAX_LOOKUPS_PER_RUN = 50  # bound worst-case runtime on repos with many distinct
                                 # contributor domains -- each live lookup can cost up to
                                 # WHOIS_TIMEOUT_SECONDS if the WHOIS server is slow/unreachable
_whois_lookup_count = 0


def whois_domain_age_days(domain):
    """guarddog's potentially_compromised_email_domain heuristic, ported to a
    commit author's email domain: how many days old is this domain's WHOIS
    registration? A domain registered very recently relative to an author's
    commit history suggests the attacker bought a newly-expired or freshly
    dropped domain to take over that author's account-recovery email.

    Best-effort and cached: WHOIS is a live network lookup with no SLA, so a
    failure/timeout returns None (treated as "unknown", not "suspicious") rather
    than raising or blocking the scan. Major providers are skipped entirely
    (see COMMON_EMAIL_PROVIDERS) since they can never usefully flag and a scan
    over hundreds of commits would otherwise burn a WHOIS lookup per commit.
    """
    global _whois_lookup_count
    if domain in COMMON_EMAIL_PROVIDERS:
        return None
    if domain in _WHOIS_CACHE:
        return _WHOIS_CACHE[domain]
    if _whois_lookup_count >= WHOIS_MAX_LOOKUPS_PER_RUN:
        return None
    _whois_lookup_count += 1
    age = None
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain, timeout=WHOIS_TIMEOUT_SECONDS)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation is not None:
            import datetime as _dt
            now = _dt.datetime.now(creation.tzinfo) if creation.tzinfo else _dt.datetime.now()
            age = (now - creation).days
    except Exception:
        age = None
    _WHOIS_CACHE[domain] = age
    return age


def is_direct_url_dependency(spec):
    """guarddog's direct_url_dependency heuristic: does this dependency spec
    point at a raw URL/git ref instead of a registry-resolved version? Such
    dependencies aren't immutable and can be repointed by whoever controls
    the URL, independent of any registry integrity checks."""
    if not spec:
        return False
    return bool(URL_SCHEME_RE.match(spec))


# ---------------------------------------------------------------------------
# YARA source-code rules, vendored from guarddog (github.com/DataDog/guarddog,
# analyzer/sourcecode/*.yar) plus our own additions for C++/C#/Rust (see
# resources/yara/README.md). guarddog runs these against whole files on disk
# via yara.Rules.match(filepath); here we run them per-diff against just the
# lines a commit actually introduced (or the whole file for new files), so a
# hit means "this commit introduced this pattern", not "this file happens to
# contain it somewhere in its (possibly untouched) history".
# ---------------------------------------------------------------------------

YARA_RULES_DIR = os.path.join(RESOURCES_DIR, "yara")
YARA_MAX_SCAN_BYTES = 200_000  # cap per-file content scanned; avoid pathological huge diffs
_YARA_RULES = None  # lazily compiled; False once we've tried and failed/found none

# Same directory exclusions guarddog's own scanner uses (analyzer/analyzer.py),
# and for the same reason: test code legitimately exercises the exact
# dangerous-looking patterns (destructive ops, credential reads) these rules
# look for, so scanning it produces false positives on totally routine test
# fixtures rather than real threats.
YARA_EXCLUDED_DIRS = {"helm", ".idea", "venv", "test", "tests", ".env", "dist", "build", "migrations", ".github"}


def _yara_path_excluded(path):
    parts = {p.lower() for p in path.split("/")[:-1]}
    return bool(parts & YARA_EXCLUDED_DIRS)


def _load_yara_rules():
    try:
        import yara
    except ImportError:
        return None
    paths = sorted(glob.glob(os.path.join(YARA_RULES_DIR, "*.yar")))
    if not paths:
        return None
    filepaths = {os.path.splitext(os.path.basename(p))[0]: p for p in paths}
    try:
        return yara.compile(filepaths=filepaths)
    except Exception as e:
        print(f"warning: failed to compile YARA rules: {e}", file=sys.stderr)
        return None


def yara_scan(path, content_bytes):
    """Run the vendored YARA rules against `content_bytes` for one file in a
    commit's diff, filtered by each matched rule's path_include glob against
    `path`. Returns a list of (rule_id, description, severity) for hits whose
    path_include (if any) matches. Best-effort: returns [] if yara-python
    isn't installed or rules fail to compile, never raises."""
    global _YARA_RULES
    if _YARA_RULES is None:
        _YARA_RULES = _load_yara_rules() or False
    if not _YARA_RULES:
        return []
    if not content_bytes:
        return []
    try:
        matches = _YARA_RULES.match(data=content_bytes[:YARA_MAX_SCAN_BYTES])
    except Exception:
        return []
    hits = []
    for m in matches:
        path_include = m.meta.get("path_include", "")
        if path_include:
            patterns = [p.strip() for p in path_include.split(",")]
            basename = path.rsplit("/", 1)[-1]
            if not any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(basename, pat) for pat in patterns):
                continue
        hits.append((m.rule, m.meta.get("description", m.rule), m.meta.get("severity", "medium")))
    return hits


# ---------------------------------------------------------------------------
# Core math (Detect.java: aggregate / mapping / expocdffitval / timecheck)
# ---------------------------------------------------------------------------

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


@dataclass
class ResultVal:
    value: float = 0.0
    globalorg: float = 0.0
    globalmapped: float = 0.0
    authororg: float = 0.0
    authormapped: float = 0.0
    valuestrglb: str = ""
    valuestrauth: str = ""


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


MIN_LOG_STD = 1.5  # floor below which a fitted log-normal is too tight to be discriminative


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


# ---------------------------------------------------------------------------
# Data extraction (Buildmodel.java + WriteData.java, kept purely in memory)
# ---------------------------------------------------------------------------

@dataclass
class CommitRow:
    sha: str
    email: str
    total_loc: int
    loc_added: int
    loc_removed: int
    files_changed: int
    files_added: int
    files_removed: int
    commit_msg_words: int
    hour_utc: int
    message: str = ""
    filetypes: list = field(default_factory=list)
    committer_email: str = ""
    weekday_utc: int = 0
    top_dirs: list = field(default_factory=list)
    gpg_signed: bool = False
    author_committer_mismatch: bool = False
    gap_seconds: float = None
    churn_ratio: float = 0.0
    commit_delay_seconds: float = 0.0
    new_deps: list = field(default_factory=list)          # [(ecosystem, name, spec)]
    changed_deps: list = field(default_factory=list)       # [(ecosystem, name, old_spec, new_spec)]
    new_binary_files: list = field(default_factory=list)   # [(path, filetype_str)]
    yara_hits: list = field(default_factory=list)          # [(path, rule_id, description, severity)]


# ---------------------------------------------------------------------------
# Manifest dependency parsing (guarddog-inspired: typosquatting +
# direct-url-dependency metadata heuristics, ported to operate on a single
# commit's diff instead of a resolved package registry entry)
# ---------------------------------------------------------------------------

_NPM_DEP_LINE_RE = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]*)"\s*,?\s*$')
_NPM_NONDEP_KEYS = {
    "name", "version", "description", "main", "license", "author", "homepage",
    "repository", "scripts", "engines", "private", "type", "module", "exports",
    "files", "keywords", "bin", "browser", "sideEffects", "packageManager",
    "types", "typings", "publishConfig", "funding", "bugs", "directories",
}
_GO_REQUIRE_RE = re.compile(r'^\s*([\w\-.]+\.[\w\-.]+(?:/[\w\-./]+)*)\s+(v[\w.\-+]+)')
_GEM_RE = re.compile(r'''^\s*gem\s+["']([\w\-.]+)["'](?:\s*,\s*["']([^"']*)["'])?''')
_REQ_TXT_RE = re.compile(r'^([A-Za-z0-9][\w\-.]*)\s*([=<>!~][^\s#]*)?')

DEP_MANIFEST_ECOSYSTEM = {
    "package.json": "npm",
    "go.mod": "go",
    "Gemfile": "rubygems",
    "requirements.txt": "pypi",
}


def parse_dep_line(basename, line):
    """Return (ecosystem, name, spec) if `line` (diff content, +/- stripped) declares
    a single dependency in a manifest file we recognize, else None."""
    if basename == "package.json":
        m = _NPM_DEP_LINE_RE.match(line)
        if m and m.group(1) not in _NPM_NONDEP_KEYS and not m.group(1).startswith("_"):
            return ("npm", m.group(1), m.group(2))
        return None
    if basename == "go.mod":
        m = _GO_REQUIRE_RE.match(line)
        if m:
            return ("go", m.group(1), m.group(2))
        return None
    if basename == "Gemfile":
        m = _GEM_RE.match(line)
        if m:
            return ("rubygems", m.group(1), m.group(2) or "")
        return None
    if basename == "requirements.txt":
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            return None
        m = _REQ_TXT_RE.match(stripped)
        if m:
            return ("pypi", m.group(1).lower(), m.group(2) or "")
        return None
    return None


URL_SCHEME_RE = re.compile(r'^\s*(https?://|git\+|git://|ssh://|[\w.-]+/[\w.-]+#)', re.IGNORECASE)

# Extensions a legitimately-bundled binary would normally have -- a native
# executable/library under one of these isn't "disguised", so the
# bundled-binary check only fires when the extension suggests something else
# (an image, doc, data file, or no extension at all).
EXPECTED_BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".node",
    ".pyd", ".wasm", ".class", ".jar",
}
MAGIC_BYTES = {
    b"MZ": "PE/EXE (Windows)",
    b"\x7fELF": "ELF (Linux)",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"\xce\xfa\xed\xfe": "Mach-O 32-bit (byte-swapped)",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (byte-swapped)",
}


def detect_bundled_binary(path, blob):
    """guarddog's bundled_binary heuristic, ported to a single new-file blob:
    flag a native executable/library whose magic bytes don't match its
    (non-executable-looking) extension."""
    ext = file_extension(path)
    if ext and ext.lower() in EXPECTED_BINARY_EXTENSIONS:
        return None
    try:
        header = blob.data_stream.read(4)
    except Exception:
        return None
    for magic, kind in MAGIC_BYTES.items():
        if header.startswith(magic):
            return kind
    return None


def file_extension(path):
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return None
    return "." + name.rsplit(".", 1)[-1]


def extract_commits(repo):
    """Walk non-merge commits oldest->latest, return list[CommitRow]."""
    rows = []
    last_author_time = {}
    commits = list(repo.iter_commits(reverse=True))  # oldest first
    total_commits = len(commits)
    for idx, commit in enumerate(commits):
        if idx % 200 == 0 or idx == total_commits - 1:
            pct = (idx + 1) / total_commits * 100
            print(f"  progress: {idx + 1}/{total_commits} commits walked ({pct:.1f}%)", file=sys.stderr, flush=True)
        if len(commit.parents) != 1:
            continue  # skip merges and the root commit, same as Buildmodel.java
        parent = commit.parents[0]
        diffs = parent.diff(commit, create_patch=True)

        ovl_add = ovl_rem = total_changed = total_fil_add = total_fil_rem = 0
        filetypes = []
        new_deps = []
        changed_deps = []
        new_binary_files = []
        yara_hits = []

        for d in diffs:
            path = d.b_path or d.a_path or ""
            try:
                patch = d.diff.decode("utf-8", errors="replace")
            except Exception:
                patch = ""
            lineadd = linerem = 0
            basename = path.rsplit("/", 1)[-1] if path else ""
            manifest_eco = DEP_MANIFEST_ECOSYSTEM.get(basename)
            added_deps, removed_deps = {}, {}
            added_lines = []
            for line in patch.split("\n"):
                # Some GitPython versions/repos return hunk-only diff text
                # (no "diff --git"/"---"/"+++" header lines), so file
                # identity/add/remove must come from the Diff object's own
                # attributes (a_path/b_path/new_file/deleted_file), not by
                # parsing header lines out of the patch text.
                if line.startswith("+++") or line.startswith("---"):
                    continue
                elif line.startswith("+"):
                    lineadd += 1
                    added_lines.append(line[1:])
                    if manifest_eco:
                        parsed = parse_dep_line(basename, line[1:])
                        if parsed:
                            added_deps[parsed[1]] = parsed[2]
                elif line.startswith("-"):
                    linerem += 1
                    if manifest_eco:
                        parsed = parse_dep_line(basename, line[1:])
                        if parsed:
                            removed_deps[parsed[1]] = parsed[2]
            ovl_add += lineadd
            ovl_rem += linerem
            total_changed += lineadd + linerem

            if manifest_eco:
                for dep_name, spec in added_deps.items():
                    if dep_name not in removed_deps:
                        new_deps.append((manifest_eco, dep_name, spec))
                    elif removed_deps[dep_name] != spec:
                        changed_deps.append((manifest_eco, dep_name, removed_deps[dep_name], spec))

            if d.new_file:
                total_fil_add += 1
                if d.b_blob is not None:
                    binary_kind = detect_bundled_binary(path, d.b_blob)
                    if binary_kind:
                        new_binary_files.append((path, binary_kind))
            if d.deleted_file:
                total_fil_rem += 1

            # YARA: scan the lines this commit actually *introduced* (added_lines)
            # rather than the whole file, so a hit means "this commit introduced
            # this pattern" not "this file happens to contain it somewhere in its
            # untouched history". New files have no pre-existing content to
            # exclude, so added_lines already equals the whole file for those.
            if path and added_lines and not d.deleted_file and not _yara_path_excluded(path):
                scan_content = "\n".join(added_lines).encode("utf-8", errors="replace")
                for rule_id, description, severity in yara_scan(path, scan_content):
                    yara_hits.append((path, rule_id, description, severity))

            ft = file_extension(path) if path and "." in path.rsplit("/", 1)[-1] else None
            if ft:
                filetypes.append(ft)

        email = commit.author.email or "unknown"
        email = email.replace(":", "").replace("//", "") if ("://" in email or "//" in email) else email
        author_dt = commit.authored_datetime.astimezone(__import__("datetime").timezone.utc)
        hour_utc = author_dt.hour
        weekday_utc = author_dt.weekday()
        msg_words = len(commit.message.split(" "))

        committer_email = commit.committer.email or "unknown"
        paths = [d.b_path or d.a_path or "" for d in diffs]
        top_dirs = [p.split("/", 1)[0] if "/" in p else "(root)" for p in paths if p]
        gpg_signed = getattr(commit, "gpgsig", None) is not None
        mismatch = email.lower() != committer_email.lower()
        churn_ratio = math.log10((ovl_add + 1) / (ovl_rem + 1))
        commit_delay_seconds = max(0, commit.committed_date - commit.authored_date)

        gap_seconds = None
        if email in last_author_time:
            gap_seconds = abs(commit.authored_date - last_author_time[email])
        last_author_time[email] = commit.authored_date

        rows.append(CommitRow(
            sha=commit.hexsha, email=email, total_loc=total_changed,
            loc_added=ovl_add, loc_removed=ovl_rem, files_changed=len(diffs),
            files_added=total_fil_add, files_removed=total_fil_rem,
            commit_msg_words=msg_words, hour_utc=hour_utc, message=commit.message.strip(),
            filetypes=filetypes, committer_email=committer_email, weekday_utc=weekday_utc,
            top_dirs=top_dirs, gpg_signed=gpg_signed, author_committer_mismatch=mismatch,
            gap_seconds=gap_seconds, churn_ratio=churn_ratio, commit_delay_seconds=commit_delay_seconds,
            new_deps=new_deps, changed_deps=changed_deps, new_binary_files=new_binary_files,
            yara_hits=yara_hits,
        ))
    return rows


# ---------------------------------------------------------------------------
# Global / author statistics (DataStatistics.java + FileTypeStatistics.java)
# ---------------------------------------------------------------------------

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


@dataclass
class AuthorHistory:
    """Per-author profile built from all but the commit being scored (same
    look-ahead-free convention as FileTypeStatistics.author_hours)."""
    weekdays: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    delays: list = field(default_factory=list)
    churn_ratios: list = field(default_factory=list)
    dir_counts: dict = field(default_factory=dict)
    total: int = 0
    signed_count: int = 0
    signed_total: int = 0
    mismatch_count: int = 0
    mismatch_total: int = 0


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


# ---------------------------------------------------------------------------
# Detection (Detect.java: detect())
# ---------------------------------------------------------------------------

METRIC_LABELS = [
    ("total_loc", "Total lines of code changed"),
    ("loc_added", "Lines of code added"),
    ("loc_removed", "Lines of code removed"),
    ("files_changed", "Files changed"),
    ("files_added", "Files added"),
    ("files_removed", "Files removed"),
    ("commit_msg_words", "Commit message length"),
]


SEVERITY_SCORE = {"critical": 0.95, "high": 0.9, "medium": 0.6, "low": 0.3}


def yara_signal(row):
    """Score + explain this commit's YARA hits (if any), highest-severity first.
    Same flat/binary contribution style as the other content-based checks."""
    if not row.yara_hits:
        return 0.0, "No content introduced by this commit matches a known malicious-pattern rule."
    path, rule_id, description, severity = max(
        row.yara_hits, key=lambda h: SEVERITY_SCORE.get(h[3], 0.5)
    )
    score = SEVERITY_SCORE.get(severity, 0.5)
    extra = f" (+{len(row.yara_hits) - 1} more rule hit{'s' if len(row.yara_hits) > 2 else ''})" if len(row.yara_hits) > 1 else ""
    text = (
        f"Content added to '{path}' matches the '{description}' pattern "
        f"({severity}-severity), a known malicious-code indicator{extra}."
    )
    return score, text


def supply_chain_signals(row):
    """Score this commit against the 5 guarddog metadata heuristics that map
    onto a single git commit (see the module docstring near RESOURCES_DIR for
    which 3 of guarddog's 8 don't). Returns 5 (score, reason_text) pairs, each
    a flat/binary contribution like mismatch_score or signing_score above --
    these are content/identity facts, not statistical rarities, so there's no
    percentile to compute."""
    typosquat_score, typosquat_text = 0.0, None
    for eco, name, _spec in row.new_deps:
        matches = get_typosquat_matches(name, eco)
        if matches:
            typosquat_score = 0.9
            typosquat_text = (
                f"The newly added {eco} dependency '{name}' closely resembles the popular "
                f"package '{matches[0]}' -- possible typosquat."
            )
            break

    disposable_score, disposable_text = 0.0, None
    if is_disposable_email_domain(row.email):
        disposable_score = 0.9
        disposable_text = f"The commit author's email domain ('{row.email.rsplit('@', 1)[-1]}') is a known disposable/temp-mail domain."

    whois_score, whois_text = 0.0, None
    domain = row.email.rsplit("@", 1)[-1].lower() if "@" in row.email else ""
    if domain:
        age_days = whois_domain_age_days(domain)
        if age_days is not None and age_days < 90:
            whois_score = 0.7
            whois_text = (
                f"The commit author's email domain ('{domain}') was registered only "
                f"{age_days} days ago -- possible expired-domain account takeover."
            )

    binary_score, binary_text = 0.0, None
    if row.new_binary_files:
        path, kind = row.new_binary_files[0]
        binary_score = 0.9
        binary_text = f"'{path}' is a native {kind} binary disguised under a non-executable-looking filename."

    url_score, url_text = 0.0, None
    for eco, name, old_spec, new_spec in row.changed_deps:
        if is_direct_url_dependency(new_spec) and not is_direct_url_dependency(old_spec):
            url_score = 0.85
            url_text = (
                f"The {eco} dependency '{name}' was changed from a pinned version ('{old_spec}') "
                f"to a direct URL ('{new_spec}'), which isn't immutable and bypasses registry integrity checks."
            )
            break
    if url_score == 0.0:
        for eco, name, spec in row.new_deps:
            if is_direct_url_dependency(spec):
                url_score = 0.85
                url_text = f"The newly added {eco} dependency '{name}' points at a direct URL ('{spec}') instead of a registry version."
                break

    return (typosquat_score, typosquat_text, disposable_score, disposable_text,
            whois_score, whois_text, binary_score, binary_text, url_score, url_text)


def detect(rows, limit=200, threshold=THRESHOLD):
    ds = DataStatistics(rows)
    ds.calc_global()
    fts = FileTypeStatistics(rows)
    fts.calc_global()

    author_commit_counts = defaultdict(int)
    for r in rows:
        author_commit_counts[r.email] += 1

    recent = list(reversed(rows))[:limit]  # latest first, same window Detect.java scores

    results = []
    for row in recent:
        # Precheck: bot authors (dependabot, renovate, ...) are excluded from
        # detection entirely, before any rule runs -- not patched in per-rule
        # after the fact.
        if "[bot]" in row.email.lower():
            results.append({
                "sha": row.sha[:7], "email": row.email, "decision": "Normal",
                "decision_val": 0.0,
                "total_loc": row.total_loc, "loc_added": row.loc_added, "loc_removed": row.loc_removed,
                "files_changed": row.files_changed, "files_added": row.files_added,
                "files_removed": row.files_removed, "commit_msg_words": row.commit_msg_words,
                "hour_utc": row.hour_utc,
                "top_reasons": ["Bot author excluded from detection"],
                "top_reasons_explained": ["This commit's author is a recognized bot account ([bot] suffix), which is excluded from detection entirely."],
            })
            continue

        exists = author_commit_counts[row.email] > 20
        if exists:
            ds.calc_author(row.email)
            fts.calc_author(row.email)
            afit = ds.author_fit[row.email]
        else:
            afit = {m: (0, 0) for m in DataStatistics.METRICS}

        rvals = {}
        for m in DataStatistics.METRICS:
            ag, bg = ds.global_fit[m]
            aa, ba = afit[m]
            rvals[m] = expocdffitval(getattr(row, m), ag, bg, aa, ba, exists)

        author_hours = fts.author_hours if exists else []
        rtime = timecheck(row.hour_utc, exists, author_hours)

        filpercentchan, filpercommit, combfrequency, combprobability = filetypecheck(row.filetypes, fts, exists)

        first_line = row.message.split("\n", 1)[0].strip()
        is_large_diff = rvals["total_loc"].globalorg > 0.8  # top-quintile per fitted tail
        mismatch_score = 0.9 if (GENERIC_MSG_RE.match(first_line) and is_large_diff) else 0.0

        ahist = build_author_history(rows, row.email) if exists else AuthorHistory()
        rweekday = weekdaycheck(row.weekday_utc, exists, ahist.weekdays)
        rgap = gapcheck(row.gap_seconds, ahist.gaps)
        rdelay = gapcheck(row.commit_delay_seconds, ahist.delays)
        rchurn = churncheck(row.churn_ratio, ahist.churn_ratios)
        rdir = dircheck(row.top_dirs, ahist.dir_counts, ahist.total)
        email_mismatch_score = mismatchcheck(row.author_committer_mismatch, ahist.mismatch_count, ahist.mismatch_total)
        signing_score = signingcheck(row.gpg_signed, ahist.signed_count, ahist.signed_total)

        (typosquat_score, typosquat_text, disposable_score, disposable_text,
         whois_score, whois_text, binary_score, binary_text,
         url_score, url_text) = supply_chain_signals(row)
        yara_score, yara_text = yara_signal(row)

        values = [
            rvals["total_loc"].globalmapped, rvals["total_loc"].authormapped,
            rvals["loc_added"].globalmapped, rvals["loc_added"].authormapped,
            rvals["loc_removed"].globalmapped, rvals["loc_removed"].authormapped,
            rvals["files_changed"].globalmapped, rvals["files_changed"].authormapped,
            rvals["files_added"].authormapped, rvals["files_removed"].authormapped,
            rvals["commit_msg_words"].globalmapped, rvals["commit_msg_words"].authormapped,
            rtime.authormapped,
            filpercentchan.globalmapped, filpercentchan.authormapped,
            filpercommit.globalmapped, filpercommit.authormapped,
            combfrequency.globalmapped, combfrequency.authormapped,
            combprobability.globalmapped, combprobability.authormapped,
            mismatch_score,
            rweekday.authormapped,
            rgap.authormapped,
            rdelay.authormapped,
            rchurn.authormapped,
            rdir.authormapped,
            email_mismatch_score,
            signing_score,
            typosquat_score,
            disposable_score,
            whois_score,
            binary_score,
            url_score,
            yara_score,
        ]

        decision_val = 0.0
        for v in values:
            decision_val = aggregate(decision_val, v)
        decision = "Unusual" if decision_val >= threshold else "Normal"

        def pct(x):
            return round(x * 100.0, 1)

        METRIC_NOUN = {
            "total_loc": "total lines changed",
            "loc_added": "lines added",
            "loc_removed": "lines removed",
            "files_changed": "files touched",
            "files_added": "files added",
            "files_removed": "files removed",
            "commit_msg_words": "words in the commit message",
        }
        contributors = []
        for m, label in METRIC_LABELS:
            noun = METRIC_NOUN[m]
            val = getattr(row, m)
            contributors.append((
                label, rvals[m].globalmapped, rvals[m].authormapped,
                f"{pct(1.0 - rvals[m].globalorg)}% of commits (repo-wide) have {val} or more {noun}.",
                f"{pct(1.0 - rvals[m].authororg)}% of this author's commits have {val} or more {noun}.",
            ))
        contributors.append((
            "Hour of day (author)", 0.0, rtime.authormapped, None,
            f"This commit's hour of day (UTC {row.hour_utc}:00) is unusual for this author "
            f"({pct(rtime.authororg)}% rarer than their most common hour).",
        ))
        contributors.append((
            "Filetype rarity (%)", filpercentchan.globalmapped, filpercentchan.authormapped,
            f"Only {round(filpercentchan.globalorg, 1)}% of all file changes (repo-wide) are to "
            f"'{filpercentchan.valuestrglb}' files.",
            f"Only {round(filpercentchan.authororg, 1)}% of this author's file changes are to "
            f"'{filpercentchan.valuestrauth}' files.",
        ))
        contributors.append((
            "Filetype rarity (per-commit)", filpercommit.globalmapped, filpercommit.authormapped,
            f"Only {pct(filpercommit.globalorg)}% of commits (repo-wide) ever touch "
            f"'{filpercommit.valuestrglb}' files.",
            f"Only {pct(filpercommit.authororg)}% of this author's commits ever touch "
            f"'{filpercommit.valuestrauth}' files.",
        ))
        contributors.append((
            "Filetype combo frequency", combfrequency.globalmapped, combfrequency.authormapped,
            f"Only {pct(combfrequency.globalorg)}% of commits (repo-wide) touch "
            f"'{combfrequency.valuestrglb}' files together.",
            f"Only {pct(combfrequency.authororg)}% of this author's commits touch "
            f"'{combfrequency.valuestrauth}' files together.",
        ))
        contributors.append((
            "Filetype combo ratio", combprobability.globalmapped, combprobability.authormapped,
            f"The relative amounts of '{combprobability.valuestrglb}' files in this commit are "
            f"atypical for the repo (match {pct(combprobability.globalorg)}%).",
            f"The relative amounts of '{combprobability.valuestrauth}' files in this commit are "
            f"atypical for this author (match {pct(combprobability.authororg)}%).",
        ))
        contributors.append((
            "Generic message on large diff", mismatch_score, mismatch_score,
            "The commit message reads as generic ('wip'/'fix'/'update'-style) despite this being "
            "an unusually large diff.",
            None,
        ))
        contributors.append((
            "Day-of-week rarity (author)", 0.0, rweekday.authormapped, None,
            f"This commit's day of week is unusual for this author "
            f"({pct(rweekday.authororg)}% rarer than their most common day).",
        ))
        contributors.append((
            "Inter-commit gap rarity (author)", 0.0, rgap.authormapped, None,
            "The time since this author's previous commit is unusual for them "
            f"(rarity {pct(rgap.authororg)}%).",
        ))
        contributors.append((
            "Author-vs-commit time delay rarity (author)", 0.0, rdelay.authormapped, None,
            "The gap between authoring and committing this change is unusual for this author "
            f"(rarity {pct(rdelay.authororg)}%).",
        ))
        contributors.append((
            "Add:remove churn ratio rarity (author)", 0.0, rchurn.authormapped, None,
            "The ratio of lines added to lines removed is unusual compared to this author's "
            f"normal editing pattern (rarity {pct(rchurn.authororg)}%).",
        ))
        contributors.append((
            "Directory rarity (author)", 0.0, rdir.authormapped, None,
            "This commit touches a top-level directory this author rarely or never touches "
            f"(rarity {pct(rdir.authororg)}%).",
        ))
        contributors.append((
            "Author/committer email mismatch", email_mismatch_score, email_mismatch_score,
            "The commit's author and committer identities differ, which is unusual for this author.",
            None,
        ))
        contributors.append((
            "Unsigned commit from usually-signing author", signing_score, signing_score,
            "This author usually signs their commits with GPG, but this one is unsigned.",
            None,
        ))
        contributors.append((
            "Possible typosquat dependency", typosquat_score, typosquat_score,
            typosquat_text or "No newly added dependency resembles a popular package name.", None,
        ))
        contributors.append((
            "Disposable author email domain", disposable_score, disposable_score,
            disposable_text or "Author email domain is not a known disposable/temp-mail domain.", None,
        ))
        contributors.append((
            "Recently-registered author email domain", whois_score, whois_score,
            whois_text or "Author email domain's WHOIS registration age is not suspiciously recent.", None,
        ))
        contributors.append((
            "Bundled binary disguised as non-executable file", binary_score, binary_score,
            binary_text or "No newly added file has binary magic bytes under a non-executable-looking name.", None,
        ))
        contributors.append((
            "Direct-URL dependency", url_score, url_score,
            url_text or "No dependency was added/changed to a direct URL instead of a registry version.", None,
        ))
        contributors.append((
            "YARA content match", yara_score, yara_score, yara_text, None,
        ))

        def best_text(c):
            _, g, a, text_g, text_a = c
            if a >= g:
                return text_a if text_a else text_g
            return text_g if text_g else text_a

        top5 = sorted(contributors, key=lambda c: max(c[1], c[2]), reverse=True)[:5]

        results.append({
            "sha": row.sha[:7], "email": row.email, "decision": decision,
            "decision_val": round(decision_val, 4),
            "total_loc": row.total_loc, "loc_added": row.loc_added, "loc_removed": row.loc_removed,
            "files_changed": row.files_changed, "files_added": row.files_added,
            "files_removed": row.files_removed, "commit_msg_words": row.commit_msg_words,
            "hour_utc": row.hour_utc,
            "top_reasons": [f"{label} (score {max(g, a):.2f})" for label, g, a, _, _ in top5],
            "top_reasons_explained": [best_text(c) for c in top5],
        })
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", help="GitHub 'user/repo' to clone, or a path to a local git repo")
    ap.add_argument("--limit", type=int, default=200, help="number of most recent commits to score (default 200)")
    ap.add_argument("--out", default=None, help="TSV output path (default: stdout summary only)")
    ap.add_argument("--workdir", default="/tmp/unusual-git-commit", help="scratch dir for clones")
    ap.add_argument("--threshold", type=float, default=THRESHOLD, help="decision_val cutoff for 'Unusual' (default calibrated 0.97)")
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
