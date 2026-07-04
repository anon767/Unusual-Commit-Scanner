"""Ties everything together: scores each of the most recent commits against the
statistical-rarity checks (stats.py) and supply-chain/YARA checks (supply_chain.py,
yara_rules.py), combines them via a probabilistic OR, and produces a natural-language
explanation for every contributing signal.

Ported from Detect.java's detect().
"""
import re
from collections import defaultdict

from .models import AuthorHistory
from .stats import (
    DataStatistics, FileTypeStatistics, aggregate, build_author_history, churncheck,
    dircheck, expocdffitval, filetypecheck, gapcheck, mapping, mismatchcheck, signingcheck,
    timecheck, weekdaycheck,
)
from .supply_chain import (
    get_typosquat_matches, is_direct_url_dependency, is_disposable_email_domain,
    whois_domain_age_days,
)
from .yara_rules import yara_scan  # noqa: F401 (re-exported for convenience)

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

METRIC_LABELS = [
    ("total_loc", "Total lines of code changed"),
    ("loc_added", "Lines of code added"),
    ("loc_removed", "Lines of code removed"),
    ("files_changed", "Files changed"),
    ("files_added", "Files added"),
    ("files_removed", "Files removed"),
    ("commit_msg_words", "Commit message length"),
]

METRIC_NOUN = {
    "total_loc": "total lines changed",
    "loc_added": "lines added",
    "loc_removed": "lines removed",
    "files_changed": "files touched",
    "files_added": "files added",
    "files_removed": "files removed",
    "commit_msg_words": "words in the commit message",
}

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
    onto a single git commit (see supply_chain.py's module docstring for which
    3 of guarddog's 8 don't). Returns 5 (score, reason_text) pairs, each a
    flat/binary contribution like mismatch_score or signing_score -- these
    are content/identity facts, not statistical rarities, so there's no
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
