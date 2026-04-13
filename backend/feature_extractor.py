from __future__ import annotations

import math
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

FEATURE_NAMES: List[str] = [
    "url_length",
    "num_dots",
    "subdomain_count",
    "num_slashes",
    "has_at",
    "has_hyphen",
    "query_param_count",
    "has_suspicious_kw",
    "url_entropy",
    "domain_length",
    "is_ip_address",
    "tld_length",
    "has_https",
    "domain_age_days",
    "blacklist_flag",
]

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "bank",
    "account",
    "password",
    "signin",
    "update",
    "wallet",
    "confirm",
    "user",
    "pay",
]

# Default off for training to avoid slow WHOIS dependency and intermittent socket timeouts.
ENABLE_WHOIS_LOOKUP = False


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    return h[4:] if h.startswith("www.") else h


def _is_ipv4(host: str) -> bool:
    if not host:
        return False
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))


def _safe_parse(raw_url: str):
    raw = (raw_url or "").strip()
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        return urlparse(candidate)
    except Exception:
        cleaned = re.sub(r"[\s\[\]<>]+", "", candidate)
        try:
            return urlparse(cleaned)
        except Exception:
            return urlparse("http://invalid.local")


def load_openphish_blacklist() -> Set[str]:
    blacklist = set()
    try:
        root = Path(__file__).resolve().parent.parent
        source = root / "Datasets" / "OpenPhish.csv"
        if source.exists():
            import pandas as pd

            df = pd.read_csv(source)
            url_col = next((c for c in df.columns if c.lower() == "url"), df.columns[0])
            for u in df[url_col].astype(str).dropna().unique():
                h = _normalize_host(urlparse(u if "://" in u else f"http://{u}").hostname or "")
                if h:
                    blacklist.add(h)
    except Exception:
        pass
    return blacklist


def _parse_whois_creation_date(value) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (list, tuple, set)):
        for v in value:
            candidate = _parse_whois_creation_date(v)
            if candidate:
                return candidate
        return None
    if isinstance(value, str):
        text = value.strip()
        for fmt in (
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S %Z",
            "%d-%b-%Y",
            "%d-%b-%Y %H:%M:%S",
        ):
            try:
                return datetime.strptime(text, fmt)
            except Exception:
                continue
        try:
            return datetime.fromisoformat(text)
        except Exception:
            pass
    return None


def _estimate_domain_age_days(host: str) -> float:
    host = _normalize_host(host)
    if not host or _is_ipv4(host):
        return 0.0

    if ENABLE_WHOIS_LOOKUP:
        try:
            import whois

            details = whois.whois(host)
            creation = getattr(details, 'creation_date', None) or getattr(details, 'created_date', None)
            created = _parse_whois_creation_date(creation)

            if created is None and isinstance(details, dict):
                creation = details.get('creation_date') or details.get('created_date')
                created = _parse_whois_creation_date(creation)

            if created:
                now = datetime.utcnow()
                if created.tzinfo is not None:
                    created = created.astimezone(timezone.utc).replace(tzinfo=None)
                age_days = (now - created).days
                if age_days < 0:
                    age_days = 0
                return float(min(age_days, 3650))

        except Exception as exc:
            # WHOIS lookups may fail due network or server timeout.
            # We swallow errors and default to safe heuristic values.
            logging = __import__('logging')
            logging.getLogger(__name__).warning(
                'WHOIS lookup failed for %s: %s (continuing with heuristic)', host, exc
            )

    # Fallback heuristic for training/offline use (fast, deterministic).
    return float(max(0, min(3650, len(host) * 5 + host.count(".") * 15)))


def _blacklist_flag(host: str, blacklist: Optional[Set[str]] = None) -> float:
    if blacklist is None:
        return 0.0
    h = _normalize_host(host)
    return float(int(h in blacklist))


def extract_features(url: str, blacklist: Optional[Set[str]] = None) -> Dict[str, float]:
    parsed = _safe_parse(url)
    full = parsed.geturl().lower()
    try:
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""

    normalized_host = _normalize_host(host)
    path = (parsed.path or "").lower()
    query = parsed.query or ""

    query_count = len(parse_qs(query))
    has_keyword = int(any(k in normalized_host or k in path for k in SUSPICIOUS_KEYWORDS))
    tld_length = len(normalized_host.split(".")[-1]) if "." in normalized_host else 0
    subdomain_count = float(len(normalized_host.split(".")) - 1 if normalized_host else 0)

    feats = {
        "url_length": float(len(full)),
        "num_dots": float(normalized_host.count(".")),
        "subdomain_count": subdomain_count,
        "num_slashes": float(full.count("/")),
        "has_at": float(int("@" in full)),
        "has_hyphen": float(int("-" in normalized_host)),
        "query_param_count": float(query_count),
        "has_suspicious_kw": float(has_keyword),
        "url_entropy": float(round(_entropy(normalized_host or full), 6)),
        "domain_length": float(len(normalized_host)),
        "is_ip_address": float(int(_is_ipv4(host))),
        "tld_length": float(tld_length),
        "has_https": float(int(full.startswith("https://"))),
        "domain_age_days": float(_estimate_domain_age_days(host)),
        "blacklist_flag": _blacklist_flag(host, blacklist),
    }

    return {name: feats.get(name, 0.0) for name in FEATURE_NAMES}


def annotate_features(features: Dict[str, float]) -> Dict[str, dict]:
    return {
        "url_length": {
            "label": "URL Length",
            "value": features["url_length"],
            "status": "safe" if features["url_length"] < 85 else "suspicious",
            "explanation": "Long URLs can hide malicious segments.",
        },
        "num_dots": {
            "label": "Subdomain Depth",
            "value": features["num_dots"],
            "status": "safe" if features["num_dots"] <= 3 else "suspicious",
            "explanation": "Too many subdomains are often used for spoofing.",
        },
        "subdomain_count": {
            "label": "Subdomain Count",
            "value": features["subdomain_count"],
            "status": "safe" if features["subdomain_count"] <= 3 else "suspicious",
            "explanation": "Excessive subdomains may signal phishing.",
        },
        "num_slashes": {
            "label": "Slash Count",
            "value": features["num_slashes"],
            "status": "safe" if features["num_slashes"] <= 8 else "suspicious",
            "explanation": "Excessive path nesting may indicate obfuscation.",
        },
        "has_at": {
            "label": "@ Symbol",
            "value": bool(features["has_at"]),
            "status": "safe" if features["has_at"] == 0 else "suspicious",
            "explanation": "@ in URLs can trick users about the real host.",
        },
        "has_hyphen": {
            "label": "Hyphen in Domain",
            "value": bool(features["has_hyphen"]),
            "status": "safe" if features["has_hyphen"] == 0 else "suspicious",
            "explanation": "Look-alike phishing domains often use hyphens.",
        },
        "query_param_count": {
            "label": "Query Parameter Count",
            "value": features["query_param_count"],
            "status": "safe" if features["query_param_count"] <= 5 else "suspicious",
            "explanation": "Excessive parameters can indicate tracking or payload tricks.",
        },
        "has_suspicious_kw": {
            "label": "Suspicious Keywords",
            "value": bool(features["has_suspicious_kw"]),
            "status": "safe" if features["has_suspicious_kw"] == 0 else "suspicious",
            "explanation": "Common phishing lure terms were detected.",
        },
        "url_entropy": {
            "label": "URL Entropy",
            "value": features["url_entropy"],
            "status": "safe" if features["url_entropy"] < 4.2 else "suspicious",
            "explanation": "High randomness is common in generated phishing URLs.",
        },
        "domain_length": {
            "label": "Domain Length",
            "value": features["domain_length"],
            "status": "safe" if features["domain_length"] <= 30 else "suspicious",
            "explanation": "Very long domain names can be deceptive.",
        },
        "is_ip_address": {
            "label": "IP Address Host",
            "value": bool(features["is_ip_address"]),
            "status": "safe" if features["is_ip_address"] == 0 else "suspicious",
            "explanation": "Direct IP hosts are uncommon for trusted services.",
        },
        "tld_length": {
            "label": "TLD Length",
            "value": features["tld_length"],
            "status": "safe" if 2 <= features["tld_length"] <= 10 else "suspicious",
            "explanation": "Unusual TLD shapes can correlate with abuse.",
        },
        "has_https": {
            "label": "HTTPS",
            "value": bool(features["has_https"]),
            "status": "safe" if features["has_https"] == 1 else "suspicious",
            "explanation": "HTTPS is expected for modern legitimate services.",
        },
        "domain_age_days": {
            "label": "Domain Age (Days)",
            "value": features["domain_age_days"],
            "status": "safe" if features["domain_age_days"] > 365 else "suspicious",
            "explanation": "Older domains tend to be more reputable.",
        },
        "blacklist_flag": {
            "label": "Blacklist Flag",
            "value": bool(features["blacklist_flag"]),
            "status": "safe" if features["blacklist_flag"] == 0 else "suspicious",
            "explanation": "Known malicious domains are flagged.",
        },
    }
