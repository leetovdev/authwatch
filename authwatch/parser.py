from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Iterable, Iterator


class Kind(str, Enum):
    FAILED = "failed"
    INVALID = "invalid"
    ACCEPTED = "accepted"


@dataclass(frozen=True)
class Event:
    time: datetime
    kind: Kind
    user: str
    ip: str
    method: str = ""


ISO_STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
SYSLOG_STAMP = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")
ADDRESS = r"(?P<ip>[0-9a-fA-F:.]+)"
METHOD = r"(?P<method>password|publickey|keyboard-interactive/pam)"
PATTERNS = (
    (Kind.FAILED, re.compile(rf"Failed {METHOD} for (?:invalid user )?(?P<user>\S*) from {ADDRESS}")),
    (Kind.ACCEPTED, re.compile(rf"Accepted {METHOD} for (?P<user>\S+) from {ADDRESS}")),
    (Kind.INVALID, re.compile(rf"Invalid user (?P<user>\S*) from {ADDRESS}")),
)


def _stamp(line: str, year: int) -> datetime | None:
    if match := ISO_STAMP.match(line):
        return datetime.fromisoformat(match.group(1))
    if match := SYSLOG_STAMP.match(line):
        return datetime.strptime(f"{year} {' '.join(match.group(1).split())}", "%Y %b %d %H:%M:%S")
    return None


def parse_line(line: str, year: int) -> Event | None:
    if "sshd" not in line:
        return None
    for kind, pattern in PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        time = _stamp(line, year)
        if time is None:
            return None
        fields = match.groupdict()
        return Event(time, kind, fields["user"] or "?", fields["ip"], fields.get("method") or "")
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Event]:
    previous = None
    for line in lines:
        event = parse_line(line, year)
        if event is None:
            continue
        if previous and event.time < previous - timedelta(days=300):
            year += 1
            event = replace(event, time=event.time.replace(year=year))
        previous = event.time
        yield event
