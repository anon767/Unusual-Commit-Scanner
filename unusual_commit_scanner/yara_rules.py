"""YARA source-code rules, vendored from guarddog (github.com/DataDog/guarddog,
analyzer/sourcecode/*.yar) plus additional coverage for C++/C#/Rust (guarddog itself only
covers Python/JS/Go/Ruby). guarddog runs these against whole files on disk via
yara.Rules.match(filepath); here we run them per-diff against just the lines a commit
actually introduced (or the whole file for new files), so a hit means "this commit
introduced this pattern", not "this file happens to contain it somewhere in its
(possibly untouched) history".
"""
import fnmatch
import glob
import os
import sys

from .resources import RESOURCES_DIR

YARA_RULES_DIR = os.path.join(RESOURCES_DIR, "yara")
YARA_MAX_SCAN_BYTES = 200_000  # cap per-file content scanned; avoid pathological huge diffs
_YARA_RULES = None  # lazily compiled; False once we've tried and failed/found none

# Same directory exclusions guarddog's own scanner uses (analyzer/analyzer.py),
# and for the same reason: test code legitimately exercises the exact
# dangerous-looking patterns (destructive ops, credential reads) these rules
# look for, so scanning it produces false positives on totally routine test
# fixtures rather than real threats.
YARA_EXCLUDED_DIRS = {"helm", ".idea", "venv", "test", "tests", ".env", "dist", "build", "migrations", ".github"}


def yara_path_excluded(path):
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
