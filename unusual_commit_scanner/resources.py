"""Location of vendored resources (YARA rules, popular-package lists, disposable-email list).

Not shipped in the public repo (kept out to avoid duplicating guarddog's own distribution) --
every consumer of RESOURCES_DIR degrades gracefully (empty set / no-op) when the directory or
individual files underneath it don't exist, so running without it just disables those specific
checks rather than crashing.
"""
import os

RESOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources")
