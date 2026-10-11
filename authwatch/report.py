from __future__ import annotations

from .analyzer import Analysis
from .term import paint

LEVEL_STYLE = {
    "critical": ("[x]", ("red", "bold")),
    "high": ("[!]", ("red",)),
    "medium": ("[!]", ("yellow",)),
}


def _when(moment) -> str:
    return moment.strftime("%b %d %H:%M") if moment else "-"


def render(analysis: Analysis, limit: int = 10) -> str:
    lines = ["", f"  {paint('authwatch', 'bold')}"]
    if analysis.period:
        start, end = analysis.period
        lines.append(paint(f"  {start:%Y-%m-%d %H:%M} -> {end:%Y-%m-%d %H:%M}", "gray"))
    lines += [
        "",
        f"  events    {analysis.events}",
        f"  sources   {len(analysis.sources)}",
        f"  failed    {paint(str(analysis.failed), 'red') if analysis.failed else 0}",
        f"  accepted  {analysis.accepted}",
        "",
    ]

    if analysis.alerts:
        lines.append(paint(f"  alerts ({len(analysis.alerts)})", "bold"))
        for alert in analysis.alerts:
            mark, style = LEVEL_STYLE[alert.level]
            lines.append(f"  {paint(mark, *style)} {alert.ip:<16} {alert.title:<24} {paint(alert.detail, 'gray')}")
    else:
        lines.append(f"  {paint('[+]', 'green')} no suspicious activity")

    top = analysis.top(limit)
    if top:
        lines += ["", paint("  top sources", "bold"),
                  paint(f"  {'ip':<16} {'fails':>6} {'users':>6}  {'first seen':<13} {'last seen':<13}", "gray")]
        for src in top:
            lines.append(f"  {src.ip:<16} {len(src.failures):>6} {len(src.users):>6}  "
                         f"{_when(src.first):<13} {_when(src.last):<13}")
    lines.append("")
    return "\n".join(line.rstrip() for line in lines)


def to_dict(analysis: Analysis) -> dict:
    return {
        "period": [t.isoformat() for t in analysis.period] if analysis.period else None,
        "events": analysis.events,
        "failed": analysis.failed,
        "accepted": analysis.accepted,
        "alerts": [vars(a) for a in analysis.alerts],
        "sources": [
            {
                "ip": s.ip,
                "failures": len(s.failures),
                "logins": [{"user": e.user, "method": e.method, "time": e.time.isoformat()} for e in s.logins],
                "users": dict(s.users.most_common()),
                "first": s.first.isoformat() if s.first else None,
                "last": s.last.isoformat() if s.last else None,
            }
            for s in analysis.sources.values()
        ],
    }
