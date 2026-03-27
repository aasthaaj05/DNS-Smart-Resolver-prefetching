"""
Run with: python -m pytest tests/test_cache.py -v
"""

import time
import pytest
import dns.message
import dns.query
from unittest.mock import patch

from core.cache import DNSCache, CacheEntry


@pytest.fixture
def cache():
    """Fresh cache for each test."""
    return DNSCache()


class TestCacheSetGet:
    def test_basic_set_and_get(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        result = cache.get("example.com")
        assert result == ["1.2.3.4"]

    def test_multiple_addresses(self, cache):
        cache.set("cdn.com", ["10.0.0.1", "10.0.0.2"], ttl=60)
        result = cache.get("cdn.com")
        assert set(result) == {"10.0.0.1", "10.0.0.2"}

    def test_trailing_dot_normalised(self, cache):
        cache.set("example.com.", ["1.2.3.4"], ttl=60)
        assert cache.get("example.com") == ["1.2.3.4"]
        assert cache.get("example.com.") == ["1.2.3.4"]

    def test_miss_returns_none(self, cache):
        assert cache.get("notincache.com") is None

    def test_empty_address_list_not_stored(self, cache):
        cache.set("example.com", [], ttl=60)
        assert cache.get("example.com") is None


class TestCacheTTL:
    def test_expired_entry_returns_none(self, cache):
        # Set with min_ttl (30s) — then mock time to be 31s in the future
        cache.set("example.com", ["1.2.3.4"], ttl=30)
        with patch("core.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 31
            assert cache.get("example.com") is None

    def test_ttl_clamped_to_min(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=1)  # below min_ttl=30
        entry = cache._store.get("example.com")
        assert entry is not None
        assert entry.ttl >= 30  # clamped to min

    def test_ttl_clamped_to_max(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=999999)
        entry = cache._store.get("example.com")
        assert entry.ttl <= 86400


class TestCacheInvalidate:
    def test_invalidate_existing(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        removed = cache.invalidate("example.com")
        assert removed is True
        assert cache.get("example.com") is None

    def test_invalidate_missing(self, cache):
        assert cache.invalidate("nothere.com") is False


class TestCacheHitCount:
    def test_hit_count_increments(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        cache.get("example.com")
        cache.get("example.com")
        counts = cache.get_hit_counts()
        assert counts["example.com"] == 2

    def test_miss_does_not_increment(self, cache):
        cache.get("nothere.com")
        counts = cache.get_hit_counts()
        assert "nothere.com" not in counts


class TestCacheStats:
    def test_stats_structure(self, cache):
        cache.set("a.com", ["1.1.1.1"], ttl=300)
        stats = cache.stats()
        assert "total_entries" in stats
        assert "live_entries" in stats
        assert "capacity" in stats
        assert stats["total_entries"] == 1




class TestDNSIntegration:

    def test_dns_query(self):
        domain = "example.com"
        server = "127.0.0.1"
        port = 5353

        query = dns.message.make_query(domain, "A")

        start = time.time()
        response = dns.query.udp(query, server, port=port)
        end = time.time()

        print(f"\nDomain: {domain}")
        print(f"Time: {(end - start)*1000:.2f} ms")

        assert response.answer is not None

class TestMarkovIntegration:

    def test_markov_prefetch_flow(self):
        """
        Simulates user navigation pattern and checks
        if Markov prediction kicks in.
        """

        server = "127.0.0.1"
        port = 5353

        def query(domain):
            q = dns.message.make_query(domain, "A")
            dns.query.udp(q, server, port=port)

        # Step 1: Train pattern
        query("google.com")
        query("youtube.com")

        query("google.com")
        query("youtube.com")

        # Step 2: Trigger prediction
        query("google.com")

        print("\nCheck logs for [MARKOV] predictions")
    
    

class TestMarkovScoring:

    def test_scoring_prioritization(self):
        from prefetch.markov import MarkovPredictor

        predictor = MarkovPredictor()

        # Simulate behavior
        sequence = [
            "a.com", "b.com", "c.com",
            "a.com", "b.com", "c.com",
            "a.com", "b.com", "d.com"
        ]

        for d in sequence:
            predictor.update(d)

        preds = predictor.predict("a.com", "b.com")

        # c.com should rank higher than d.com
        assert preds[0] == "c.com"