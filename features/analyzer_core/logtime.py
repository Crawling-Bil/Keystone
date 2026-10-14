"""How long a device log covers.

A ``show logging`` / ``display logbuffer`` capture lists messages with a time stamp each; the first and
the last one say what period the buffer covers. This module reads those two stamps and returns a
sentence an engineer can use at a glance ("1 day 17 hours 59 minutes"), so the Logs tab of the Router
and the Switch Analyzer can show a *Duration* next to the *Window*.

Cisco IOS prints ``Feb 25 11:18:26.118`` (no year unless ``service timestamps log datetime year`` is
set), Huawei VRP ``Oct 12 2026 10:00:00+07:00``, ArubaOS-Switch ``10/12/26 10:00:00`` and some
platforms an ISO date. Uptime-style stamps (``3d02h``) carry no date and are not read.

Stamps without a year are compared in the same (leap) year. When the last stamp is *earlier* than the
first one the log either crosses New Year (December to January: one year is added) or is out of order
(the clock was set while the log was running, a normal thing after a reload before NTP): the second
case is reported as "not calculated" and never as a guess.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

_MONTHS = {name: number for number, name in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_TIME = r"(?P<h>\d{1,2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:[.,](?P<f>\d+))?"
_PATTERNS = (
    re.compile(rf"(?P<year>\d{{4}})\s+(?P<mon>[A-Za-z]{{3}})\s+(?P<day>\d{{1,2}})\s+{_TIME}"),                       # NX-OS: 2026 Oct 12 10:00:00
    re.compile(rf"(?P<mon>[A-Za-z]{{3}})[a-z]*\s+(?P<day>\d{{1,2}})(?:,?\s+(?P<year>\d{{4}}))?\s+{_TIME}"),   # Feb 25 11:18:26.118 / Oct 12 2026 10:00:00
    re.compile(rf"(?P<year>\d{{4}})-(?P<mon>\d{{2}})-(?P<day>\d{{2}})[T ]{_TIME}"),                              # 2026-10-12T10:00:00
    re.compile(rf"(?P<mon>\d{{1,2}})/(?P<day>\d{{1,2}})/(?P<year>\d{{2,4}})\s+{_TIME}"),                         # 10/12/26 10:00:00
)
_NO_YEAR = 2000   # a leap year, so "Feb 29" is valid


def parse_stamp(text: str) -> tuple[datetime, bool] | None:
    """``(datetime, has_year)`` for the first time stamp in ``text``, or ``None``."""
    for pattern in _PATTERNS:
        match = pattern.search(text or "")
        if not match:
            continue
        parts = match.groupdict()
        month = parts["mon"]
        number = int(month) if month.isdigit() else _MONTHS.get(month.lower()[:3])
        if not number:
            continue
        year = parts.get("year")
        has_year = bool(year)
        value = int(year) if year else _NO_YEAR
        if year and len(year) == 2:
            value += 2000
        try:
            stamp = datetime(value, number, int(parts["day"]), int(parts["h"]), int(parts["mi"]), int(parts["s"]))
        except ValueError:
            continue
        return stamp, has_year
    return None


def humanize(seconds: int) -> str:
    """``93784`` -> ``1 day 2 hours 3 minutes``; under one hour the seconds are shown too."""
    seconds = max(0, int(seconds))
    if seconds == 0:
        return "under a second"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours or days:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes or hours or days:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if not days and not hours:
        parts.append(f"{secs} second{'s' if secs != 1 else ''}")
    return " ".join(parts)


def log_window(first: str, last: str) -> dict[str, Any]:
    """The period between the first and the last stamp of a log (oldest first).

    ``{"seconds": int | None, "text": str, "assumed": str, "reliable": bool}``; ``text`` is empty when the
    stamps cannot be read at all (uptime-style stamps, or no stamp), and ``assumed`` explains an assumption
    (a year taken from New Year crossing).
    """
    a, b = parse_stamp(first), parse_stamp(last)
    if not a or not b:
        return {"seconds": None, "text": "", "assumed": "", "reliable": False}
    (start, start_year), (end, end_year) = a, b
    assumed = ""
    if start_year != end_year:
        # one stamp with a year and one without cannot be compared
        return {"seconds": None, "text": "", "assumed": "", "reliable": False}
    delta = end - start
    if delta < timedelta(0):
        if not start_year and start.month >= 10 and end.month <= 3:
            delta = end.replace(year=end.year + 1) - start      # the same calendar, one year later (no 29 February lies between December and March)
            assumed = "the log crosses New Year; the time stamps carry no year"
        else:
            return {"seconds": None, "text": "not calculated: the time stamps are not in order (the clock was changed while the log was running)", "assumed": "", "reliable": False}
    seconds = int(delta.total_seconds())
    return {"seconds": seconds, "text": humanize(seconds), "assumed": assumed, "reliable": True}
