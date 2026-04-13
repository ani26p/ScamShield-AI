from __future__ import annotations

import json
import math
import re
import socket
import logging
import concurrent.futures
import urllib.request
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

# Enabled for live API use. Set to False only during batch training to avoid slow WHOIS calls.
ENABLE_WHOIS_LOOKUP = True

# Max seconds to wait for a WHOIS response before giving up and using heuristic.
WHOIS_TIMEOUT_SECONDS = 6


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
        # Now 3 levels up from backend/app/
        root = Path(__file__).resolve().parent.parent.parent
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


def _get_registrable_domain(host: str) -> str:
    """Strip subdomains - return only registrable domain (e.g. sub.google.com → google.com).
    Contains heuristics for common two-part TLDs like .co.uk, .com.au, .gov.in.
    """
    if not host or _is_ipv4(host):
        return host
    parts = host.lower().split('.')
    if len(parts) <= 2:
        return host
        
    # Heuristic for 2nd-level TLDs (e.g., .co.uk, .com.br, .gov.in)
    # Most 2nd-level TLDs have a length of 2 or 3 (co, com, edu, gov, net, org)
    second_to_last = parts[-2]
    if second_to_last in ('co', 'com', 'edu', 'gov', 'net', 'org') and len(parts) >= 3:
        return '.'.join(parts[-3:])
        
    return '.'.join(parts[-2:])


def _rdap_domain_age(host: str) -> Optional[datetime]:
    """Fetch domain creation date via RDAP (modern REST-based WHOIS replacement).
    Uses only Python built-ins - no third-party packages required.
    RDAP ref: https://www.iana.org/assignments/rdap-json-values/
    """
    logger = logging.getLogger(__name__)
    domain = _get_registrable_domain(host)
    # Expanded list of RDAP bootstrap servers for higher reliability
    rdap_urls = [
        f"https://rdap.org/domain/{domain}",
        f"https://rdap.verisign.com/com/v1/domain/{domain}", # .com, .net
        f"https://rdap.arin.net/registry/domain/{domain}",
        f"https://rdap.db.ripe.net/rdap/domain/{domain}",   # Europe
        f"https://rdap.apnic.net/domain/{domain}",          # Asia-Pacific
        f"https://rdap.lacnic.net/rdap/domain/{domain}",   # Latin America
    ]
    for url in rdap_urls:
        try:
            req = urllib.request.Request(
                url,
                headers={'Accept': 'application/rdap+json, application/json'},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            for event in data.get('events', []):
                action = (event.get('eventAction') or '').lower()
                if action == 'registration':
                    date_str = event.get('eventDate', '')
                    if date_str:
                        # RDAP dates are ISO 8601, e.g. "1997-09-15T04:00:00Z"
                        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception as exc:
            logger.debug('RDAP lookup failed (%s) for %s: %s', url, domain, exc)
            continue
    return None


def _pywhois_domain_age(host: str) -> Optional[datetime]:
    """Fallback: use python-whois or whois package if RDAP fails."""
    logger = logging.getLogger(__name__)
    domain = _get_registrable_domain(host)
    try:
        import whois as _w
        # python-whois uses whois.whois(); whois package uses whois.query()
        if hasattr(_w, 'whois'):
            d = _w.whois(domain)
            creation = getattr(d, 'creation_date', None) or (d.get('creation_date') if isinstance(d, dict) else None)
            result = _parse_whois_creation_date(creation)
            if result:
                return result
        if hasattr(_w, 'query'):
            d = _w.query(domain)
            if d:
                creation = getattr(d, 'creation_date', None)
                result = _parse_whois_creation_date(creation)
                if result:
                    return result
    except Exception as exc:
        logger.debug('whois package fallback failed for %s: %s', domain, exc)
    return None


def _lookup_creation_date(host: str) -> Optional[datetime]:
    """Try RDAP first (reliable, fast), then python-whois as fallback."""
    result = _rdap_domain_age(host)
    if result:
        return result
    return _pywhois_domain_age(host)


def _estimate_domain_age_days(host: str) -> float:
    host = _normalize_host(host)
    if not host or _is_ipv4(host):
        return 0.0

    if ENABLE_WHOIS_LOOKUP:
        try:
            # Run lookup in a thread to enforce a hard timeout.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_lookup_creation_date, host)
                created = future.result(timeout=WHOIS_TIMEOUT_SECONDS)

            if created:
                now = datetime.utcnow()
                if created.tzinfo is not None:
                    created = created.astimezone(timezone.utc).replace(tzinfo=None)
                age_days = (now - created).days
                return float(max(0, min(age_days, 36500)))  # cap at ~100 years

        except concurrent.futures.TimeoutError:
            logging.getLogger(__name__).warning(
                'Domain age lookup timed out for %s after %ss', host, WHOIS_TIMEOUT_SECONDS
            )
        except Exception as exc:
            logging.getLogger(__name__).warning('Domain age lookup error for %s: %s', host, exc)

    # Fallback heuristic: calculate an estimate based on domain complexity
    # This ensures the ML model still gets a signal even if WHOIS is down.
    # We use a negative value so _format_domain_age knows it's an estimate.
    # Formula: Baseline 3 years (1095 days) minus penalties for suspicious traits.
    heuristic_days = 1095  # Standard reputation base
    heuristic_days -= len(host) * 2  # Long domains are slightly more suspicious
    heuristic_days -= host.count('.') * 50  # Too many subdomains
    heuristic_days -= (1 if any(k in host for k in SUSPICIOUS_KEYWORDS) else 0) * 500
    
    # Return as negative so UI can label it as "Estimated"
    return float(-abs(max(1, min(3650, heuristic_days))))


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


def _format_domain_age(days: float) -> str:
    """Convert a day count into a human-readable age string.
    Returns estimates with an (Est.) suffix for negative sentinel values.
    """
    is_estimated = False
    if days < 0:
        is_estimated = True
        days = abs(days)
    
    if days == 0:
        val = '< 1 day'
    elif days < 30:
        val = f'{int(days)} days'
    elif days < 365:
        months = int(days // 30)
        val = f'{months} month{"s" if months != 1 else ""}'
    else:
        years = int(days // 365)
        rem_months = int((days % 365) // 30)
        if rem_months > 0:
            val = f'{years} yr {rem_months} mo'
        else:
            val = f'{years} year{"s" if years != 1 else ""}'
            
    return f'{val} (Est.)' if is_estimated else val


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
            "label": "Domain Age",
            "value": _format_domain_age(features["domain_age_days"]),
            "status": "safe" if abs(features["domain_age_days"]) > 365 else "suspicious",
            "explanation": "Older domains tend to be more reputable. Newly registered domains are a common phishing indicator.",
        },
        "blacklist_flag": {
            "label": "Blacklist Flag",
            "value": bool(features["blacklist_flag"]),
            "status": "safe" if features["blacklist_flag"] == 0 else "suspicious",
            "explanation": "Known malicious domains are flagged.",
        },
    }
