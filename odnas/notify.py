"""Alerts (SPEC §10.2). v0.1 default: admin page only (an open `issues` row).

Outbound email is deliberately NOT implemented: SPEC §14.5 is open (outbound
communication to people goes through Gidget; confirm whether the product may send
system alerts directly). The Notifier interface is the seam: a future
SmtpNotifier or GidgetNotifier plugs in here without touching callers.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from odnas.db import DB

log = logging.getLogger("odnas.alerts")


@dataclass(frozen=True)
class Alert:
    type: str
    severity: str           # low|medium|high|critical
    summary: str            # no filenames, no secrets
    user_id: str | None = None
    notify_user: bool = False


class Notifier(Protocol):
    def send(self, alert: Alert, recipients: list[str]) -> None: ...


class NullNotifier:
    """Admin-page only."""
    def send(self, alert: Alert, recipients: list[str]) -> None:
        return None


class StubEmailNotifier:
    """Records what WOULD be emailed (recipient count only) and sends nothing."""
    def __init__(self) -> None:
        self.outbox: list[tuple[Alert, int]] = []

    def send(self, alert: Alert, recipients: list[str]) -> None:
        self.outbox.append((alert, len(recipients)))
        log.info("email delivery disabled (SPEC 14.5 open): would notify %d recipient(s) about %s/%s",
                 len(recipients), alert.type, alert.severity)


class Alerter:
    def __init__(self, db: DB, notifier: Notifier | None = None):
        self.db, self.notifier = db, notifier or NullNotifier()

    def raise_(self, alert: Alert, recipients: list[str] | None = None) -> bool:
        new = self.db.open_issue(alert.user_id, alert.type, alert.severity, alert.summary)
        if new:
            self.db.audit("system", "issue_opened", alert.user_id or "", {"type": alert.type, "severity": alert.severity})
            self.notifier.send(alert, recipients or [])
        return new

    def resolve(self, user_id: str | None, *types: str) -> None:
        self.db.close_issues(user_id, *types)
