import unittest
from datetime import datetime, timedelta
from pathlib import Path

from authwatch.analyzer import analyze, max_burst
from authwatch.parser import Event, Kind, parse_line, parse_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"


def failures(ip, count, start, step=10, user="root"):
    return [Event(start + timedelta(seconds=i * step), Kind.FAILED, user, ip, "password") for i in range(count)]


class ParserTest(unittest.TestCase):
    def test_failed_password(self):
        event = parse_line("Oct 11 02:11:03 vps sshd[1]: Failed password for root from 203.0.113.45 port 4 ssh2", 2026)
        self.assertEqual((event.kind, event.user, event.ip), (Kind.FAILED, "root", "203.0.113.45"))
        self.assertEqual(event.time, datetime(2026, 10, 11, 2, 11, 3))

    def test_failed_invalid_user(self):
        event = parse_line("Oct  1 09:00:00 vps sshd[1]: Failed password for invalid user oracle from 198.51.100.7 port 2 ssh2", 2026)
        self.assertEqual((event.user, event.time.day), ("oracle", 1))

    def test_accepted_publickey(self):
        event = parse_line("Oct 11 08:02:41 vps sshd[1]: Accepted publickey for deploy from 192.0.2.10 port 5 ssh2: ED25519 SHA256:x", 2026)
        self.assertEqual((event.kind, event.method), (Kind.ACCEPTED, "publickey"))

    def test_iso_timestamp_and_ipv6(self):
        event = parse_line("2026-10-11T02:11:03.512+03:00 vps sshd-session[9]: Invalid user test from 2001:db8::1 port 22", 2026)
        self.assertEqual((event.kind, event.ip), (Kind.INVALID, "2001:db8::1"))
        self.assertEqual(event.time, datetime(2026, 10, 11, 2, 11, 3))

    def test_ignores_other_services(self):
        self.assertIsNone(parse_line("Oct 11 00:04:00 vps CRON[1]: Failed password for root from 1.2.3.4", 2026))
        self.assertIsNone(parse_line("Oct 11 00:04:00 vps sshd[1]: Connection closed by 192.0.2.1 port 1", 2026))

    def test_year_rollover(self):
        lines = [
            "Dec 31 23:59:00 vps sshd[1]: Invalid user a from 192.0.2.1 port 1",
            "Jan  1 00:01:00 vps sshd[1]: Invalid user b from 192.0.2.1 port 1",
        ]
        first, second = parse_lines(lines, 2025)
        self.assertEqual((first.time.year, second.time.year), (2025, 2026))


class BurstTest(unittest.TestCase):
    def test_sliding_window(self):
        start = datetime(2026, 1, 1)
        times = [start + timedelta(minutes=m) for m in (0, 1, 2, 30, 31, 32, 33)]
        self.assertEqual(max_burst(times, timedelta(minutes=5)), 4)

    def test_empty(self):
        self.assertEqual(max_burst([], timedelta(minutes=5)), 0)


class AnalyzerTest(unittest.TestCase):
    start = datetime(2026, 10, 11, 2, 0)

    def test_brute_force(self):
        result = analyze(failures("203.0.113.1", 12, self.start))
        self.assertEqual([(a.level, a.title) for a in result.alerts], [("high", "brute force")])
        self.assertEqual(result.hostile(), ["203.0.113.1"])

    def test_slow_attempts_are_not_brute_force(self):
        result = analyze(failures("203.0.113.1", 12, self.start, step=600))
        self.assertEqual(result.alerts, [])

    def test_success_after_brute_force_is_critical(self):
        events = failures("203.0.113.9", 10, self.start, user="deploy")
        events.append(Event(self.start + timedelta(minutes=5), Kind.ACCEPTED, "deploy", "203.0.113.9", "password"))
        self.assertEqual(analyze(events).alerts[0].level, "critical")

    def test_enumeration(self):
        events = [Event(self.start + timedelta(minutes=i * 20), Kind.INVALID, user, "198.51.100.2")
                  for i, user in enumerate(["a", "b", "c", "d", "e"])]
        [alert] = analyze(events).alerts
        self.assertEqual(alert.title, "user enumeration")

    def test_invalid_and_failed_are_not_double_counted(self):
        events = failures("203.0.113.1", 3, self.start, user="test")
        events += [Event(e.time, Kind.INVALID, "test", e.ip) for e in events]
        self.assertEqual(analyze(events).failed, 3)


class SampleTest(unittest.TestCase):
    def test_sample_log(self):
        with SAMPLE.open(encoding="utf-8") as fh:
            result = analyze(parse_lines(fh, 2026))
        titles = {(a.ip, a.title) for a in result.alerts}
        self.assertIn(("203.0.113.77", "login after brute force"), titles)
        self.assertIn(("203.0.113.45", "brute force"), titles)
        self.assertIn(("198.51.100.23", "user enumeration"), titles)
        self.assertIn(("192.0.2.55", "root login"), titles)
        self.assertNotIn("192.0.2.10", {a.ip for a in result.alerts})


if __name__ == "__main__":
    unittest.main()
