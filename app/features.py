"""URL normalization and feature extraction utilities."""

from __future__ import annotations

import re
from collections import Counter
from math import log2
from urllib.parse import parse_qsl, urlencode, unquote, urlsplit

SPECIAL_CHARS = r"@?=&#%+-_:.~/"


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DEFAULT_PORT_RE = re.compile(r":(80|443)$")
_HEX_32_RE = re.compile(r"[0-9a-fA-F]{32}")
_HEX_40_RE = re.compile(r"[0-9a-fA-F]{40}")
_HEX_64_RE = re.compile(r"[0-9a-fA-F]{64}")

SUSPICIOUS_WORDS = ("login", "signin", "bank", "secure", "account", "update", "verify")
SUSPICIOUS_SHORTENER_KEYWORDS = ("bit.ly", "goo.gl", "tinyurl", "t.co", "is.gd", "ow.ly")
SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq")
SUSPICIOUS_EXTENSIONS = (".exe", ".bat", ".cmd", ".scr", ".pif")


def normalize_url(url: str, *, strip_query: bool = False) -> str:
    """Normalize URL for deduplication and stable feature extraction."""
    value = (url or "").strip()
    value = unquote(value)

    if "#" in value:
        value = value.split("#", 1)[0]

    if not _SCHEME_RE.match(value):
        value = "http://" + value

    parts = urlsplit(value)
    netloc = (parts.netloc or "").lower()
    netloc = _DEFAULT_PORT_RE.sub("", netloc)

    path = (parts.path or "/").rstrip("/") or "/"
    query = parts.query or ""
    if query and not strip_query:
        query_pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode(sorted(query_pairs), doseq=True)
    elif strip_query:
        query = ""

    rebuilt = f"{parts.scheme.lower()}://{netloc}{path}"
    if query:
        rebuilt += f"?{query}"
    return rebuilt


def redact_query(url: str) -> str:
    """Remove URL query string for privacy-friendly logging."""
    return normalize_url(url, strip_query=True)


def url_struct_features(url: str) -> dict[str, float]:
    """Extract cheap structural URL features for model input."""
    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    path = parts.path or ""
    query = parts.query or ""

    return {
        "url_len": float(len(normalized)),
        "host_len": float(len(host)),
        "path_len": float(len(path)),
        "query_len": float(len(query)),
        "dot_count": float(host.count(".")),
        "digit_count": float(sum(ch.isdigit() for ch in normalized)),
        "alpha_count": float(sum(ch.isalpha() for ch in normalized)),
        "special_count": float(sum(ch in SPECIAL_CHARS for ch in normalized)),
        "has_at": float("@" in normalized),
        "has_ip_host": float(bool(_IP_HOST_RE.match(host))),
        "path_depth": float(path.count("/")),
        "param_count": float(query.count("&") + (1 if query else 0)),
    }


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return float(-sum((count / total) * log2(count / total) for count in counts.values()))


def legacy_url_features(url: str) -> dict[str, float]:
    """兼容 url-master 的 21 维 URL 特征（无外部网络依赖版本）。"""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    host_parts = [part for part in host.split(".") if part]
    domain_core = host_parts[-2] if len(host_parts) >= 2 else (host_parts[0] if host_parts else "")
    path_tokens = re.findall(r"[a-zA-Z]+", normalized)

    suspicious_patterns = 0
    if _IP_HOST_RE.match(host):
        suspicious_patterns += 1
    suspicious_patterns += int(bool(_HEX_32_RE.search(normalized)))
    suspicious_patterns += int(bool(_HEX_40_RE.search(normalized)))
    suspicious_patterns += int(bool(_HEX_64_RE.search(normalized)))

    return {
        "url_length": float(len(normalized)),
        "domain_length": float(len(domain_core)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "fragment_length": float(len(fragment)),
        "subdomain_count": float(max(len(host_parts) - 2, 0)),
        "special_char_count": float(len(re.findall(r"[^a-zA-Z0-9]", normalized))),
        "digit_count": float(sum(char.isdigit() for char in normalized)),
        "letter_count": float(sum(char.isalpha() for char in normalized)),
        "suspicious_words_count": float(sum(1 for w in SUSPICIOUS_WORDS if w in normalized.lower())),
        "ip_in_domain": float(bool(_IP_HOST_RE.match(host))),
        "shortened_url": float(any(key in normalized.lower() for key in SUSPICIOUS_SHORTENER_KEYWORDS)),
        "suspicious_tld": float(any(normalized.lower().endswith(tld) or tld + "/" in normalized.lower() for tld in SUSPICIOUS_TLDS)),
        "domain_age_days": 0.0,
        "ssl_certificate": float(parsed.scheme == "https"),
        "redirect_count": 0.0,
        "suspicious_extension": float(any(ext in normalized.lower() for ext in SUSPICIOUS_EXTENSIONS)),
        "url_depth": float(len([x for x in path.split("/") if x])),
        "avg_word_length": float(sum(len(t) for t in path_tokens) / len(path_tokens)) if path_tokens else 0.0,
        "entropy": _entropy(normalized),
        "suspicious_patterns": float(suspicious_patterns),
    }
