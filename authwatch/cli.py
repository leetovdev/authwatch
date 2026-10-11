from __future__ import annotations

import argparse
import gzip
import json
import sys
from contextlib import ExitStack
from datetime import datetime, timedelta
from itertools import chain
from pathlib import Path
from typing import TextIO

from . import __version__
from .analyzer import analyze
from .parser import parse_lines
from .report import render, to_dict
from .term import paint


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authwatch",
        description="Detect SSH brute force, user enumeration and suspicious logins in auth logs.",
    )
    parser.add_argument("logs", nargs="*", default=["-"], metavar="LOG",
                        help="auth.log, secure, *.gz or - for stdin (default)")
    parser.add_argument("-t", "--threshold", type=int, default=10, help="failures per window to flag (default 10)")
    parser.add_argument("-w", "--window", type=int, default=10, metavar="MIN", help="window in minutes (default 10)")
    parser.add_argument("-u", "--usernames", type=int, default=5, help="distinct usernames to flag (default 5)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    parser.add_argument("--top", type=int, default=10, help="sources to show (default 10)")
    parser.add_argument("--json", type=Path, metavar="FILE", help="save results as JSON")
    parser.add_argument("--blocklist", type=Path, metavar="FILE", help="write IPs with high/critical alerts")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _open(name: str, stack: ExitStack) -> TextIO:
    if name == "-":
        return sys.stdin
    path = Path(name)
    if path.suffix == ".gz":
        return stack.enter_context(gzip.open(path, "rt", encoding="utf-8", errors="replace"))
    return stack.enter_context(path.open(encoding="utf-8", errors="replace"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    with ExitStack() as stack:
        try:
            streams = [_open(name, stack) for name in args.logs]
        except OSError as err:
            print(paint(f"[x] {err.filename}: {err.strerror}", "red"), file=sys.stderr)
            return 1
        events = list(parse_lines(chain.from_iterable(streams), args.year))

    result = analyze(events, args.threshold, timedelta(minutes=args.window), args.usernames)
    print(render(result, args.top))

    if args.json:
        args.json.write_text(json.dumps(to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")
        print(paint(f"  saved {args.json}", "gray"))
    if args.blocklist:
        hostile = result.hostile()
        args.blocklist.write_text("".join(f"{ip}\n" for ip in hostile), encoding="utf-8")
        print(paint(f"  {len(hostile)} addresses written to {args.blocklist}", "gray"))

    return 2 if any(a.level == "critical" for a in result.alerts) else 1 if result.alerts else 0
