"""Walks a repo's non-merge commits and turns each into a CommitRow: LOC/file stats,
filetypes, manifest dependency changes (for typosquat/direct-URL checks), newly-added
binary files, and YARA content hits on the lines the commit actually introduced.

Ported from Buildmodel.java + WriteData.java (kept purely in memory, no CSV round-trip).
"""
import math
import re
import sys
from datetime import timezone

from .models import CommitRow
from .yara_rules import yara_path_excluded, yara_scan

# ---------------------------------------------------------------------------
# Manifest dependency parsing (guarddog-inspired: typosquatting + direct-url-
# dependency metadata heuristics, ported to operate on a single commit's diff
# instead of a resolved package registry entry)
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


def file_extension(path):
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return None
    return "." + name.rsplit(".", 1)[-1]


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
            if path and added_lines and not d.deleted_file and not yara_path_excluded(path):
                scan_content = "\n".join(added_lines).encode("utf-8", errors="replace")
                for rule_id, description, severity in yara_scan(path, scan_content):
                    yara_hits.append((path, rule_id, description, severity))

            ft = file_extension(path) if path and "." in path.rsplit("/", 1)[-1] else None
            if ft:
                filetypes.append(ft)

        email = commit.author.email or "unknown"
        email = email.replace(":", "").replace("//", "") if ("://" in email or "//" in email) else email
        author_dt = commit.authored_datetime.astimezone(timezone.utc)
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
