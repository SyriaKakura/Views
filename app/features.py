"""URL normalization and feature extraction utilities."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, unquote, urlsplit

SPECIAL_CHARS = r"@?=&#%+-_:.~/"


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DEFAULT_PORT_RE = re.compile(r":(80|443)$")


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
