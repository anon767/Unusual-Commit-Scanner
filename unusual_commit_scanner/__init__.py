"""
unusual_commit_scanner -- flags anomalous git commits that look like supply-chain sabotage.

Python port of goyalr41/UnusualGitCommit, extended with statistical fixes, natural-language
explanations, and supply-chain heuristics + YARA rules ported from DataDog/guarddog.
"""
from .detect import THRESHOLD, detect
from .extract import extract_commits

__all__ = ["THRESHOLD", "detect", "extract_commits"]
__version__ = "0.2.0"
