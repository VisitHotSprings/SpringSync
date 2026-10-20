"""Scheduling math (SPEC §9.1). Pure functions + a small throttle governor."""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("America/Chicago")
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
MAX_BACKOFF_MIN = 240


def assign_offsets(user_ids: list[str], interval_min: int) -> dict[str, int]:
    """Round-robin: spread N users evenly across the interval (minutes)."""
    n = len(user_ids)
    return {u: (i * interval_min) // n for i, u in enumerate(user_ids)} if n else {}


def period_minutes(interval_min: int, backoff_factor: int) -> int:
    return min(interval_min * max(1, backoff_factor), max(MAX_BACKOFF_MIN, interval_min))


def next_slot(now: datetime, interval_min: int, offset_min: int, backoff_factor: int = 1) -> datetime:
    """Next start strictly after `now` on the grid EPOCH + offset + k*period."""
    period = period_minutes(interval_min, backoff_factor) * 60
    base = EPOCH + timedelta(minutes=offset_min % max(interval_min, 1))
    k = int((now - base).total_seconds() // period) + 1
    return base + timedelta(seconds=k * period)


def in_window(now: datetime, window: tuple[time, time] | None) -> bool:
    if window is None:
        return True
    t = now.astimezone(LOCAL_TZ).time()
    start, end = window
    return start <= t < end if start < end else (t >= start or t < end)  # overnight window


def seconds_until_window_end(now: datetime, window: tuple[time, time] | None) -> int | None:
    """Seconds from `now` until the window closes (America/Chicago wall clock, DST-aware).
    None if there is no window or `now` is outside it."""
    if window is None or not in_window(now, window):
        return None
    local = now.astimezone(LOCAL_TZ)
    end = datetime.combine(local.date(), window[1], tzinfo=LOCAL_TZ)
    if end <= local:
        end = datetime.combine(local.date() + timedelta(days=1), window[1], tzinfo=LOCAL_TZ)
    return max(1, int((end.astimezone(now.tzinfo) - now).total_seconds()))


def weekly_check_due(now: datetime, last_check: datetime | None, weekday: int, hhmm: str) -> bool:
    local = now.astimezone(LOCAL_TZ)
    if local.weekday() != weekday or local.time() < time.fromisoformat(hhmm):
        return False
    return last_check is None or (now - last_check) > timedelta(days=6)


class ThrottleGovernor:
    """>=2 throttled runs within 10 min -> halve max_concurrent for 15 min (SPEC §9.1)."""

    def __init__(self) -> None:
        self._events: deque[datetime] = deque()
        self._until: datetime | None = None
        self._lock = threading.Lock()

    def record(self, now: datetime) -> None:
        with self._lock:
            self._events.append(now)
            while self._events and now - self._events[0] > timedelta(minutes=10):
                self._events.popleft()
            if len(self._events) >= 2:
                self._until = now + timedelta(minutes=15)

    def max_concurrent(self, now: datetime, configured: int) -> int:
        with self._lock:
            if self._until and now < self._until:
                return max(1, configured // 2)
        return configured


def next_backoff(current: int, throttled: bool) -> int:
    """Double the user's interval after a throttled run (cap 4 h); reset after a clean one."""
    return min(current * 2, 16) if throttled else 1
