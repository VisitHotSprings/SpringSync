"""Display times (v0.9.1, Reid): everything a person reads (web pages for users, admins and auditors,
alert/issue text, alert mail) is in Central time, America/Chicago, with the zone label (CST/CDT).

Storage stays UTC ISO 8601 (DB, audit hash chain, logs), and backup folder names stay UTC
(`pull.STAMP_FMT`), so nothing here is ever parsed back or written to disk names."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

DISPLAY_TZ = ZoneInfo("America/Chicago")
DISPLAY_FMT = "%Y-%m-%d %H:%M %Z"
# ISO 8601 date-times WITH an offset or Z (what D.iso() writes); plain dates are left alone
ISO_RE = re.compile(r"\b\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d{1,6})?)?(?:Z|[+-]\d\d:\d\d)")


def _parse(v) -> datetime | None:
    if isinstance(v, datetime):
        d = v
    else:
        try:
            d = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)   # naive values in the DB are UTC


def display_time(v, empty: str = "never") -> str:
    """UTC ISO string or datetime -> '2026-10-21 23:28 CDT'. Unparseable text is returned unchanged."""
    if v is None or v == "":
        return empty
    d = _parse(v)
    return d.astimezone(DISPLAY_TZ).strftime(DISPLAY_FMT) if d else str(v)


def localize_text(text) -> str:
    """Rewrite every embedded UTC ISO timestamp in free text (alert summaries, run details, audit
    details shown on a page) to Central time. Display only; the stored text is unchanged."""
    if not text:
        return "" if text is None else text
    return ISO_RE.sub(lambda m: display_time(m.group(0)), str(text))
