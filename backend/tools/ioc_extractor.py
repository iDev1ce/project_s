from agno.tools import tool
from collections import defaultdict
import re
from typing import Iterable

from backend.tools.document import load_document

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r'https?://[^\s<>"\'`]+', re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,24})\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)

FILELIKE_SUFFIXES = {
    "html",
    "htm",
    "php",
    "asp",
    "aspx",
    "js",
    "css",
    "json",
    "xml",
    "txt",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "zip",
    "rar",
    "7z",
    "exe",
    "dll",
    "bin",
    "dat",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "svg",
    "webp",
}

NEGATIVE_HINT_PATTERNS = (
    "contact",
    "reporting",
    "incident reporting",
    "advisory",
    "psirt",
    "support",
    "security guidance",
    "for inquiries",
    "contact email",
    "law enforcement",
    "agency",
    "public information",
    "vendor",
)

POSITIVE_HINT_PATTERNS = (
    "c2",
    "command and control",
    "beacon",
    "contacted",
    "connected to",
    "communicated with",
    "downloaded from",
    "hosted on",
    "payload",
    "phishing",
    "malicious",
    "attacker-controlled",
    "exfiltration",
    "ioc",
    "indicator",
    "infrastructure",
)


def _dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)

    return out


def _is_probably_filelike(domain: str) -> bool:
    suffix = domain.rsplit(".", 1)[-1].lower()
    return suffix in FILELIKE_SUFFIXES


def _extract_urls(text: str) -> list[str]:
    return _dedupe_preserve_order(URL_RE.findall(text))


def _extract_email_domains(text: str) -> list[str]:
    return _dedupe_preserve_order(match.group(1).lower() for match in EMAIL_RE.finditer(text))


def _extract_domains(text: str) -> list[str]:
    domains = []
    for match in DOMAIN_RE.finditer(text):
        value = match.group(0).lower().strip(".;,)")
        if _is_probably_filelike(value):
            continue
        domains.append(value)

    return _dedupe_preserve_order(domains)


def _snippet(text: str, start: int, end: int, window: int = 90) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right].replace("\n", " ")
    snippet = " ".join(snippet.split())

    return snippet


def _build_domain_candidates(text: str, domains: list[str]) -> list[dict]:
    text_lc = text.lower()
    candidates = []

    for domain in domains:
        snippets = []
        hint_counts = defaultdict(int)

        start = 0
        domain_lc = domain.lower()
        while True:
            idx = text_lc.find(domain_lc, start)
            if idx == -1:
                break

            snip = _snippet(text, idx, idx + len(domain))
            snippets.append(snip)

            snip_lc = snip.lower()

            if "@" + domain_lc in snip_lc:
                hint_counts["email_context"] += 1

            for patt in NEGATIVE_HINT_PATTERNS:
                if patt in snip_lc:
                    hint_counts["negative_context"] += 1
                    break

            for patt in POSITIVE_HINT_PATTERNS:
                if patt in snip_lc:
                    hint_counts["positive_context"] += 1
                    break

            start = idx + len(domain)

        snippets = _dedupe_preserve_order(snippets)[:3]

        candidates.append(
            {
                "value": domain,
                "snippets": snippets,
                "context_hints": {
                    "email_context": hint_counts["email_context"] > 0,
                    "negative_context": hint_counts["negative_context"] > 0,
                    "positive_context": hint_counts["positive_context"] > 0,
                },
            }
        )

    return candidates


@tool
def extract_iocs_tool(file_path: str) -> dict:

    text = load_document(file_path)
    text_lc = text.lower()

    hashes_md5 = _dedupe_preserve_order(MD5_RE.findall(text_lc))
    hashes_sha1 = _dedupe_preserve_order(SHA1_RE.findall(text_lc))
    hashes_sha256 = _dedupe_preserve_order(SHA256_RE.findall(text_lc))

    ipv4s = _dedupe_preserve_order(IPV4_RE.findall(text_lc))
    urls = _extract_urls(text)
    email_domains = _extract_email_domains(text)
    domains = _extract_domains(text)

    domains = _dedupe_preserve_order(list(domains) + list(email_domains))

    domain_candidates = _build_domain_candidates(text, domains)

    total = (
        len(hashes_md5)
        + len(hashes_sha1)
        + len(hashes_sha256)
        + len(ipv4s)
        + len(domains)
        + len(urls)
    )

    print(f"Extractor found {total} raw IOCs")

    return {
        "total_found": total,
        "md5": hashes_md5,
        "sha1": hashes_sha1,
        "sha256": hashes_sha256,
        "ipv4": ipv4s,
        "domain": domains,
        "url": urls,
        "email_domains": email_domains,
        "domain_candidates": domain_candidates,
        "raw_text": text[:20000],
    }