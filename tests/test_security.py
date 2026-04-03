"""
Run with: python -m pytest tests/test_security.py -v
"""

import pytest
from unittest.mock import MagicMock, patch
from security.checker import SecurityChecker
from security.risk_scorer import RiskScorer
from security.lame_detector import LameDetector
from security.blocklist import MaliciousDomainDetector
from security.rate_limiter import RateLimiter
from core.resolver import NSRecord

def make_ns(name, ip="1.2.3.4"):
    return NSRecord(nameserver=name, ip=ip)

def make_resolver(ns_records=None, responsive=True):
    r = MagicMock()
    r.resolve_ns.return_value = ns_records or []
    r.is_responsive.return_value = responsive
    return r

# FIX: helper that patches MaliciousDomainDetector so SecurityChecker tests
# never trigger a real blocklist download or network call.
def make_clean_mal_detector():
    from security.blocklist import DetectionResult
    mock = MagicMock()
    mock.check.return_value = DetectionResult(
        domain="", is_malicious=False, reason="",
        detection_type="clean", confidence="High"
    )
    return mock


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
        # FIX: patch MaliciousDomainDetector so tests don't hit the network
        checker._malicious_detector = make_clean_mal_detector()
        report = checker.check("google.com")
        assert report is not None
        assert report.risk_level == "Low"

    def test_no_ns_returns_none(self):
        resolver = make_resolver(ns_records=[])
        checker = SecurityChecker(resolver)
        checker._malicious_detector = make_clean_mal_detector()
        report = checker.check("broken.com")
        assert report is None

    def test_result_is_cached(self):
        resolver = make_resolver(
            ns_records=[make_ns("ns1.example.com", "1.1.1.1")],
            responsive=True,
        )
        checker = SecurityChecker(resolver)
        checker._malicious_detector = make_clean_mal_detector()
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
        checker._malicious_detector = make_clean_mal_detector()
        r1 = checker.check("example.com.")
        r2 = checker.check("example.com")
        # Both should return the same cached report
        assert r1 is r2

    def test_malicious_domain_blocked(self):
        """Malicious domain detection should short-circuit NS lookup."""
        from security.blocklist import DetectionResult
        resolver = make_resolver(
            ns_records=[make_ns("ns1.example.com", "1.1.1.1")],
        )
        checker = SecurityChecker(resolver)
        mal = MagicMock()
        mal.check.return_value = DetectionResult(
            domain="evil.com", is_malicious=True,
            reason="On blocklist", detection_type="blocklist", confidence="High"
        )
        checker._malicious_detector = mal
        report = checker.check("evil.com")
        assert report.malicious_domain is True
        assert report.risk_level == "High"
        # NS lookup must NOT have been called — no upstream traffic for known-bad domains
        resolver.resolve_ns.assert_not_called()

    def test_rate_limited_client_blocked(self):
        """Exhausted rate limiter should return a rate_limited report."""
        resolver = make_resolver(
            ns_records=[make_ns("ns1.example.com", "1.1.1.1")],
        )
        checker = SecurityChecker(resolver)
        checker._malicious_detector = make_clean_mal_detector()
        # Replace rate limiter with one that always rejects
        rl = MagicMock()
        rl.allow.return_value = False
        checker._rate_limiter = rl
        report = checker.check("example.com", client_ip="10.0.0.1")
        assert report.rate_limited is True
        resolver.resolve_ns.assert_not_called()


class TestMaliciousDomainDetector:
    def setup_method(self):
        self.detector = MaliciousDomainDetector()

    @patch('urllib.request.urlopen')
    def test_blocklist_refresh(self, mock_urlopen):
        # Mock the response
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"""
0.0.0.0 malware.com
0.0.0.0 evil.net
"""
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        self.detector._refresh_blocklist()
        assert self.detector.blocklist_size() == 2
        assert "malware.com" in self.detector._blocklist

    def test_blocklist_check(self):
        # Manually add to blocklist
        self.detector._blocklist.add("bad.com")
        result = self.detector._check_blocklist("bad.com")
        assert result.is_malicious is True
        assert result.detection_type == "blocklist"

    def test_homoglyph_detection(self):
        result = self.detector._check_homoglyph("paypa1.com")
        assert result.is_malicious is True
        assert "Homoglyph" in result.reason

    def test_homoglyph_clean(self):
        result = self.detector._check_homoglyph("paypal.com")
        assert result.is_malicious is False

    def test_heuristics_high_entropy(self):
        # High entropy subdomain
        domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.malware.com"
        result = self.detector._check_heuristics(domain)
        assert result.is_malicious is True
        assert "heuristic" in result.detection_type

    def test_heuristics_long_subdomain(self):
        domain = "verylongsubdomainthatshouldtriggerheuristiccheck.malware.com"
        result = self.detector._check_heuristics(domain)
        assert result.is_malicious is True

    def test_heuristics_many_labels(self):
        domain = "a.b.c.d.e.f.g.malware.com"
        result = self.detector._check_heuristics(domain)
        assert result.is_malicious is True

    def test_heuristics_high_digit_ratio(self):
        domain = "1234567890.com"
        result = self.detector._check_heuristics(domain)
        assert result.is_malicious is True

    def test_clean_domain(self):
        result = self.detector.check("google.com")
        assert result.is_malicious is False
        assert result.detection_type == "clean"

    def test_shannon_entropy_calculation(self):
        # Test the entropy function
        low_entropy = "aaa"  # repetitive, low entropy
        high_entropy = "abc123def456"  # mixed, higher entropy
        assert self.detector._shannon_entropy(low_entropy) < self.detector._shannon_entropy(high_entropy)

    def test_levenshtein_distance(self):
        assert self.detector._levenshtein("kitten", "sitten") == 1
        assert self.detector._levenshtein("kitten", "kittens") == 1
        assert self.detector._levenshtein("kitten", "kitten") == 0


class TestRateLimiter:
    def setup_method(self):
        self.limiter = RateLimiter(
            bucket_size=10,    # small for testing
            refill_rate=2,     # 2 tokens/second
            block_duration=5,  # 5s block
        )

    def test_whitelist_always_allowed(self):
        assert self.limiter.allow("127.0.0.1") is True
        assert self.limiter.allow("::1") is True

    def test_normal_ip_burst_allowed(self):
        ip = "192.168.1.1"
        # Should allow up to bucket_size queries instantly
        for _ in range(10):
            assert self.limiter.allow(ip) is True

    def test_rate_limit_after_burst(self):
        ip = "192.168.1.1"
        # Exhaust bucket
        for _ in range(10):
            self.limiter.allow(ip)
        # Next should be rejected
        assert self.limiter.allow(ip) is False

    def test_refill_over_time(self):
        import time
        ip = "192.168.1.1"
        # Exhaust bucket
        for _ in range(10):
            self.limiter.allow(ip)
        assert self.limiter.allow(ip) is False

        # Wait for refill (2 tokens/second, wait 3 seconds for 6 tokens)
        time.sleep(3)
        # Should allow 6 queries now
        allowed = 0
        for _ in range(10):
            if self.limiter.allow(ip):
                allowed += 1
        assert allowed == 6

    def test_temp_block_after_abuse(self):
        ip = "192.168.1.1"
        # Simulate repeated rate limiting
        for _ in range(5):  # ABUSE_THRESHOLD
            for _ in range(10):
                self.limiter.allow(ip)  # exhaust
            self.limiter.allow(ip)      # reject
        # Next reject should trigger block
        self.limiter.allow(ip)  # this should block
        assert self.limiter.is_blocked(ip) is True

    def test_unblock_works(self):
        import time
        ip = "192.168.1.1"
        # Manually set blocked
        from security.rate_limiter import BucketState
        self.limiter._buckets[ip] = BucketState(
            tokens=10, last_refill=time.time(), blocked_until=time.time() + 10
        )
        assert self.limiter.is_blocked(ip) is True
        assert self.limiter.unblock(ip) is True
        assert self.limiter.is_blocked(ip) is False

    def test_stats(self):
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        # Allow some
        for _ in range(5):
            self.limiter.allow(ip1)
        # Reject some
        for _ in range(10):
            self.limiter.allow(ip2)  # exhaust
        self.limiter.allow(ip2)      # reject

        stats = self.limiter.stats()
        assert stats["total_allowed"] == 15
        assert stats["total_rejected"] == 1
        # FIX: removed duplicate `assert stats["total_rejected"] == 1` line
        assert stats["active_ips"] >= 2
        assert stats["bucket_size"] == 10
        assert stats["refill_rate"] == 2

    def test_sweep_inactive(self):
        import time
        ip = "192.168.1.1"
        self.limiter.allow(ip)
        assert ip in self.limiter._buckets
        # Manually set last_refill to old time
        self.limiter._buckets[ip].last_refill = time.time() - 700  # >10 min
        self.limiter._sweep_inactive()
        assert ip not in self.limiter._buckets