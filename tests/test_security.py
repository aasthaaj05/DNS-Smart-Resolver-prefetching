"""
Run with: python -m pytest tests/test_security.py -v
"""

import pytest
from unittest.mock import MagicMock, patch
from security.checker import SecurityChecker
from security.risk_scorer import RiskScorer
from security.lame_detector import LameDetector
from core.resolver import NSRecord

def make_ns(name, ip="1.2.3.4"):
    return NSRecord(nameserver=name, ip=ip)

def make_resolver(ns_records=None, responsive=True):
    r = MagicMock()
    r.resolve_ns.return_value = ns_records or []
    r.is_responsive.return_value = responsive
    return r

class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_clean_domain_is_low(self):
        ns = [make_ns("ns1.example.com", "1.1.1.1"),
              make_ns("ns2.example.com", "2.2.2.2")]
        report = self.scorer.score("example.com", ns, [], False)
        assert report.risk_level == "Low"
        assert report.score == 0

    def test_lame_ns_is_high(self):
        ns = [make_ns("ns1.example.com", "1.1.1.1")]
        report = self.scorer.score("example.com", ns, ["ns1.example.com"], False)
        assert report.risk_level == "High"
        assert report.score >= 3

    def test_cyclic_is_high(self):
        ns = [make_ns("ns1.example.com", "1.1.1.1"),
              make_ns("ns2.example.com", "2.2.2.2")]
        report = self.scorer.score("example.com", ns, [], True)
        assert report.risk_level == "High"

    def test_shared_ip_is_medium(self):
        ns = [make_ns("ns1.example.com", "1.1.1.1"),
              make_ns("ns2.example.com", "1.1.1.1")]  # same IP!
        report = self.scorer.score("example.com", ns, [], False)
        assert report.risk_level == "Medium"
        assert report.shared_ip is True

    def test_single_ns_adds_point(self):
        ns = [make_ns("ns1.example.com", "1.1.1.1")]
        report = self.scorer.score("example.com", ns, [], False)
        assert report.score >= 1

    def test_unresolvable_ip_adds_point(self):
        ns = [make_ns("ns1.example.com", None),   # no IP
              make_ns("ns2.example.com", "1.1.1.1")]
        report = self.scorer.score("example.com", ns, [], False)
        assert report.score >= 1

class TestLameDetector:
    def test_responsive_ns_not_lame(self):
        resolver = make_resolver(responsive=True)
        detector = LameDetector(resolver)
        ns = [make_ns("ns1.example.com", "1.1.1.1")]
        lame = detector.find_lame_nameservers("example.com", ns)
        assert lame == []

    def test_unresponsive_ns_is_lame(self):
        resolver = make_resolver(responsive=False)
        detector = LameDetector(resolver)
        ns = [make_ns("ns1.example.com", "1.1.1.1")]
        lame = detector.find_lame_nameservers("example.com", ns)
        assert "ns1.example.com" in lame

    def test_no_ip_ns_is_lame(self):
        resolver = make_resolver(responsive=True)
        detector = LameDetector(resolver)
        ns = [make_ns("ns1.example.com", None)]  # no IP resolved
        lame = detector.find_lame_nameservers("example.com", ns)
        assert "ns1.example.com" in lame

    def test_cyclic_detection(self):
        resolver = make_resolver()
        detector = LameDetector(resolver)
        # All NS are in-bailiwick AND have no resolvable IP = true deadlock
        ns = [make_ns("ns1.example.com", None),
              make_ns("ns2.example.com", None)]
        assert detector.detect_cycle("example.com", ns) is True

    def test_inbailiwick_with_ip_not_cyclic(self):
        resolver = make_resolver()
        detector = LameDetector(resolver)
        # ns1.google.com serving google.com is normal (glue record exists)
        ns = [make_ns("ns1.example.com", "1.1.1.1"),
              make_ns("ns2.example.com", "2.2.2.2")]
        assert detector.detect_cycle("example.com", ns) is False

    def test_no_cycle_external_ns(self):
        resolver = make_resolver()
        detector = LameDetector(resolver)
        # ns1.cloudflare.com is NOT a subdomain of example.com
        ns = [make_ns("ns1.cloudflare.com", "1.1.1.1")]
        assert detector.detect_cycle("example.com", ns) is False

class TestSecurityChecker:
    def test_check_clean_domain(self):
        resolver = make_resolver(
            ns_records=[
                make_ns("ns1.google.com", "216.239.32.10"),
                make_ns("ns2.google.com", "216.239.34.10"),
            ],
            responsive=True,
        )
        checker = SecurityChecker(resolver)
        report = checker.check("google.com")
        assert report is not None
        assert report.risk_level == "Low"

    def test_no_ns_returns_none(self):
        resolver = make_resolver(ns_records=[])
        checker = SecurityChecker(resolver)
        report = checker.check("broken.com")
        assert report is None

    def test_result_is_cached(self):
        resolver = make_resolver(
            ns_records=[make_ns("ns1.example.com", "1.1.1.1")],
            responsive=True,
        )
        checker = SecurityChecker(resolver)
        checker.check("example.com")
        checker.check("example.com")   # second call should use cache
        # resolve_ns should only have been called once
        assert resolver.resolve_ns.call_count == 1

    def test_trailing_dot_normalised(self):
        resolver = make_resolver(
            ns_records=[make_ns("ns1.example.com", "1.1.1.1")],
            responsive=True,
        )
        checker = SecurityChecker(resolver)
        r1 = checker.check("example.com.")
        r2 = checker.check("example.com")
        # Both should return the same cached report
        assert r1 is r2