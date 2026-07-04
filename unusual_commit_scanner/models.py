"""Data model shared across the scanner: one row per scored commit, plus the intermediate
per-metric and per-author result types."""
from dataclasses import dataclass, field


@dataclass
class ResultVal:
    value: float = 0.0
    globalorg: float = 0.0
    globalmapped: float = 0.0
    authororg: float = 0.0
    authormapped: float = 0.0
    valuestrglb: str = ""
    valuestrauth: str = ""


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
