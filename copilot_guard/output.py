"""Checking the model's reply before an analyst sees it. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import html
import json
import re
from urllib.parse import urlsplit
from dataclasses import dataclass, field

from .normalize import detect_injection  # noqa: F401  (used by triage)

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
NEXT_STEPS = {"escalate_to_analyst", "request_more_context", "monitor", "open_incident"}
ALLOWED_LINK_HOSTS = {"attack.mitre.org", "hisn.local"}

FORBIDDEN_KEYS = ("action", "actions", "tool_call", "tool_calls", "function_call")
MAX_SUMMARY_CHARS = 600

_TENANT_REF = re.compile(r"TEN-[0-9]{3}")
_IMAGE = re.compile(r"!\[[^\]]*\]\((?:[^()]|\([^()]*\))*\)")
_LINK = re.compile(r"\[([^\]]*)\]\(((?:[^()]|\([^()]*\))*)\)")
_BARE_URL = re.compile(r"https?://[^\s<>()\[\]\"']+", re.IGNORECASE)

class Rejected(Exception):
    """Raised by parse_model_output / triage when the reply cannot be accepted. Keeps .reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class TriageResult:
    severity: str
    summary_html: str
    next_step: str
    related_alert_ids: list[str]
    flags: list[str] = field(default_factory=list)


def _load_object(raw) -> dict:
    """Step 1: one JSON object, with or without a ```json fence. Nothing else."""
    if not isinstance(raw, str):
        raise Rejected("not_json")
    text = raw.strip()
    lines = text.split("\n")
    if len(lines) >= 2 and lines[0].strip() in ("```json", "```") and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1])
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise Rejected("not_json") from None
    if not isinstance(data, dict):
        raise Rejected("not_json")
    return data


def _url_allowed(url: str) -> bool:
    """True only for http(s) URLs whose real host (as urlsplit parses it) is exactly allow-listed."""
    # A backslash, whitespace or control character is how browsers and parsers disagree
    # about where the host ends, so anything with one is simply not allowed.
    if "\\" in url or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and host in ALLOWED_LINK_HOSTS


def _clean_summary(summary: str, flags: set[str]) -> str:
    """Step 6: images out, foreign links out, then escape for HTML."""
    summary, removed = _IMAGE.subn("[image removed]", summary)
    if removed:
        flags.add("image_removed")

    def link(match: re.Match) -> str:
        if _url_allowed(match.group(2).strip()):
            return match.group(0)
        flags.add("link_removed")
        return match.group(1)                      # keep the link text, drop the URL

    def bare(match: re.Match) -> str:
        if _url_allowed(match.group(0)):
            return match.group(0)
        flags.add("link_removed")
        return "[link removed]"

    summary = _LINK.sub(link, summary)
    summary = _BARE_URL.sub(bare, summary)
    return html.escape(summary, quote=True)


def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Parse, validate and clean one model reply. See README.md for the exact seven-step order."""
    data = _load_object(raw)                                              # 1
    flags: set[str] = set()

    next_step = data.get("next_step")                                     # 2
    if any(key in data for key in FORBIDDEN_KEYS):
        raise Rejected("forbidden_action")
    if isinstance(next_step, str) and "close" in next_step.lower():
        raise Rejected("forbidden_action")

    severity = data.get("severity")                                       # 3
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise Rejected("bad_severity")
    if not isinstance(next_step, str) or next_step not in NEXT_STEPS:
        raise Rejected("bad_next_step")
    summary = data.get("summary")
    if not isinstance(summary, str):
        raise Rejected("bad_summary")
    summary = summary.strip()
    if not summary or len(summary) > MAX_SUMMARY_CHARS:
        raise Rejected("bad_summary")
    related = data.get("related_alert_ids", [])
    if not isinstance(related, list) or not all(isinstance(x, str) for x in related):
        raise Rejected("bad_related_alert_ids")

    if any(ref != tenant_id for ref in _TENANT_REF.findall(summary)):    # 4
        raise Rejected("cross_tenant_reference")

    seen: set[str] = set()                                                # 5
    kept: list[str] = []
    dropped = False
    for alert_id in related:
        if alert_id in seen:
            continue
        seen.add(alert_id)
        if alert_id in known_alert_ids:
            kept.append(alert_id)
        else:
            dropped = True
    if dropped:
        flags.add("unknown_alert_id")

    summary_html = _clean_summary(summary, flags)                         # 6

    return TriageResult(severity=severity, summary_html=summary_html, next_step=next_step,
                        related_alert_ids=kept, flags=sorted(flags))      # 7


def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Run detect_injection over every string in `alert`, then parse_model_output; if any signal
    fired, add flags and never let the result end up quieter than it would otherwise be."""
    raise NotImplementedError
