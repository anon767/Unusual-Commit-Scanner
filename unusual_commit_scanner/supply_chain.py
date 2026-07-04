"""Supply-chain metadata heuristics, ported from guarddog (github.com/DataDog/guarddog) --
5 of its 8 metadata detectors map onto a single git commit's diff (typosquatting,
disposable/compromised author email, bundled binary, direct-URL dependency); 2 don't
(metadata_mismatch and repository_integrity_mismatch both need a *published registry
package* to compare against, which doesn't exist yet at commit time); the 8th
(unclaimed_maintainer_email_domain) is a repo-level risk report rather than a per-commit
signal and isn't implemented here.
"""
import json
import os
import re
from itertools import permutations

from .resources import RESOURCES_DIR

URL_SCHEME_RE = re.compile(r'^\s*(https?://|git\+|git://|ssh://|[\w.-]+/[\w.-]+#)', re.IGNORECASE)


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
