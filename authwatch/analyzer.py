from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from .parser import Event, Kind

LEVELS = ("critical", "high", "medium")


@dataclass(frozen=True)
class Alert:
    level: str
    ip: str
    title: str
    detail: str


@dataclass
class Source:
    ip: str
    attempts: list[datetime] = field(default_factory=list)
    invalid: list[datetime] = field(default_factory=list)
    logins: list[Event] = field(default_factory=list)
    users: Counter = field(default_factory=Counter)
    first: datetime | None = None
    last: datetime | None = None

    @property
    def failures(self) -> list[datetime]:
        return self.attempts or self.invalid

    def failures_before(self, moment: datetime) -> int:
        return sum(1 for t in self.failures if t <= moment)


@dataclass
class Analysis:
    events: int
    sources: dict[str, Source]
    alerts: list[Alert]
    period: tuple[datetime, datetime] | None

    @property
    def failed(self) -> int:
        return sum(len(s.failures) for s in self.sources.values())

    @property
    def accepted(self) -> int:
        return sum(len(s.logins) for s in self.sources.values())

    def top(self, limit: int = 10) -> list[Source]:
        ranked = sorted(self.sources.values(), key=lambda s: len(s.failures), reverse=True)
        return [s for s in ranked if s.failures][:limit]

    def hostile(self) -> list[str]:
        return sorted({a.ip for a in self.alerts if a.level in {"critical", "high"}})


def max_burst(times: list[datetime], window: timedelta) -> int:
    best = start = 0
    for end, moment in enumerate(times):
        while moment - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def _collect(events: list[Event]) -> dict[str, Source]:
    sources: dict[str, Source] = {}
    for event in events:
        src = sources.setdefault(event.ip, Source(event.ip))
        src.first = src.first or event.time
        src.last = event.time
        if event.kind is Kind.ACCEPTED:
            src.logins.append(event)
            continue
        src.users[event.user] += 1
        (src.attempts if event.kind is Kind.FAILED else src.invalid).append(event.time)
    return sources


def analyze(
    events: Iterable[Event],
    threshold: int = 10,
    window: timedelta = timedelta(minutes=10),
    usernames: int = 5,
) -> Analysis:
    ordered = sorted(events, key=lambda e: e.time)
    sources = _collect(ordered)
    minutes = int(window.total_seconds() // 60)
    alerts: list[Alert] = []

    for src in sources.values():
        burst = max_burst(src.failures, window)
        if burst >= threshold:
            alerts.append(Alert("high", src.ip, "brute force", f"{burst} failed logins within {minutes} min"))
        if len(src.users) >= usernames:
            sample = ", ".join(user for user, _ in src.users.most_common(4))
            alerts.append(Alert("medium", src.ip, "user enumeration",
                                f"{len(src.users)} usernames tried ({sample}, ...)"))
        for login in src.logins:
            before = src.failures_before(login.time)
            if before >= threshold:
                alerts.append(Alert("critical", src.ip, "login after brute force",
                                    f"'{login.user}' logged in via {login.method} after {before} failures"))
            elif login.user == "root":
                alerts.append(Alert("medium", src.ip, "root login", f"direct root login via {login.method}"))

    alerts.sort(key=lambda a: (LEVELS.index(a.level), a.ip))
    period = (ordered[0].time, ordered[-1].time) if ordered else None
    return Analysis(len(ordered), sources, alerts, period)
