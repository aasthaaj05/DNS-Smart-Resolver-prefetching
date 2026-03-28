"""
Unit + integration tests for the DNS cache.

Run unit tests only (no live proxy needed):
    python -m pytest tests/test_cache.py -v -m "not integration"

Run everything (requires proxy running on 127.0.0.1:5353):
    python -m pytest tests/test_cache.py -v
"""

import time
import pytest
import dns.message
import dns.query
from unittest.mock import patch

from scipy import stats

from core.cache import DNSCache, CacheEntry

@pytest.fixture
def cache():
    """Fresh DNSCache for each test."""
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

class TestCacheGetWithTTL:
    def test_returns_addresses_and_positive_ttl(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        addresses, remaining = cache.get_with_ttl("example.com")
        assert addresses == ["1.2.3.4"]
        # remaining TTL must be positive and ≤ clamped effective TTL
        assert 0 < remaining <= 300

    def test_miss_returns_none_and_zero(self, cache):
        addresses, remaining = cache.get_with_ttl("notincache.com")
        assert addresses is None
        assert remaining == 0

    def test_remaining_ttl_less_than_original(self, cache):
        """
        FIX VERIFICATION: proxy.py used to hard-code ttl=60 on every cache hit.
        get_with_ttl() must return a TTL that reflects actual time left, not a
        fixed constant — so a 300 s entry should report remaining > 60.
        """
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        _, remaining = cache.get_with_ttl("example.com")
        # With a brand-new 300 s entry the remaining should be well above 60
        assert remaining > 60, (
            "Cache hit is returning a fixed TTL instead of the real remaining value"
        )

    def test_expired_entry_returns_none_and_zero(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        # Patch time.time inside the cache module so is_expired sees the future
        with patch("core.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 400
            addresses, remaining = cache.get_with_ttl("example.com")
        assert addresses is None
        assert remaining == 0

class TestCacheTTL:
    def test_expired_entry_returns_none(self, cache):
        """
        FIX: patch core.cache.time so both DNSCache._sweep_expired and
        CacheEntry.is_expired (which also calls time.time()) see the mocked
        value.  Patching only `time` in the module namespace covers every
        call-site inside cache.py in one go.
        """
        cache.set("example.com", ["1.2.3.4"], ttl=30)
        with patch("core.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 31
            assert cache.get("example.com") is None

    def test_ttl_clamped_to_min(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=1)   # below min_ttl=30
        entry = cache._store.get("example.com")
        assert entry is not None
        assert entry.ttl >= 30  # clamped to min

    def test_ttl_clamped_to_max(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=999_999)
        entry = cache._store.get("example.com")
        assert entry.ttl <= 86_400

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

    def test_get_with_ttl_also_increments_hit_count(self, cache):
        cache.set("example.com", ["1.2.3.4"], ttl=300)
        cache.get_with_ttl("example.com")
        cache.get_with_ttl("example.com")
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

    def test_sweep_removes_expired(self, cache):
        """
        FIX VERIFICATION: _sweep_expired must not raise NameError when the
        log / return path runs outside the lock.  Previously `expired_keys`
        was referenced after the `with` block — now everything stays inside.
        """
        cache.set("a.com", ["1.1.1.1"], ttl=300)
        with patch("core.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 400
            removed = cache._sweep_expired()
        assert removed == 1
        assert cache.get("a.com") is None

    def test_sweep_on_empty_cache_returns_zero(self, cache):
        """Sweep on an empty store must not raise NameError."""
        removed = cache._sweep_expired()
        assert removed == 0


# Markov scoring (pure-unit, no network) 

class TestMarkovScoring:
    def test_scoring_prioritization(self):
        from prefetch.markov import MarkovPredictor

        predictor = MarkovPredictor()
        sequence = [
            "a.com", "b.com", "c.com",
            "a.com", "b.com", "c.com",
            "a.com", "b.com", "d.com",
        ]
        for d in sequence:
            predictor.update(d)

        preds = predictor.predict("a.com", "b.com")
        # c.com seen twice, d.com once — c.com must rank first
        assert preds[0] == "c.com"


# ── Integration tests (require a live proxy on 127.0.0.1:5353) ───────────────
#
# FIX: these tests are now marked @pytest.mark.integration so they are skipped
# in normal CI runs (`pytest -m "not integration"`).  Running them without the
# proxy up would previously cause the entire test suite to fail with a
# connection error, masking unrelated unit-test failures.

@pytest.mark.integration
class TestDNSIntegration:
    def test_dns_query(self):
        domain = "youtube.com"
        server = "127.0.0.1"
        port = 5353

        query = dns.message.make_query(domain, "A")

        start = time.time()
        response = dns.query.udp(query, server, port=port, timeout=3)
        elapsed_ms = (time.time() - start) * 1000

        print(f"\nDomain: {domain}")
        print(f"Time: {elapsed_ms:.2f} ms")

        assert response.answer is not None


@pytest.mark.integration
class TestMarkovIntegration:
    def test_markov_prefetch_flow(self):
        """
        Simulates a user navigation pattern and checks that the Markov
        predictor fires.  Requires the proxy to be running on port 5353.
        """
        server = "127.0.0.1"
        port = 5353

        def query(domain: str) -> None:
            q = dns.message.make_query(domain, "A")
            dns.query.udp(q, server, port=port, timeout=3)

        # Train the Markov model
        query("google.com")
        query("youtube.com")
        query("google.com")
        query("youtube.com")

        # Trigger prediction
        query("google.com")

        print("\nCheck logs for [MARKOV] predictions")
    
    

class TestMarkovScoring:

    def test_scoring_prioritization(self):
        from prefetch.markov import MarkovPredictor

        predictor = MarkovPredictor()

        sequence = [
            "a.com", "b.com", "c.com",
            "a.com", "b.com", "c.com",
            "a.com", "b.com", "d.com"
        ]

        for d in sequence:
            predictor.update(d)

        # NEW API — no args, predictor uses its own history
        # history ends with [..., "a.com", "b.com", "d.com"]
        # so we need to simulate "a.com" → "b.com" being the last two
        # Feed one more trigger to set up the right context
        predictor.update("a.com")
        predictor.update("b.com")

        preds = predictor.predict(top_k=3)  # ← fixed

        print(f"\nPredictions: {preds}")
        assert len(preds) > 0, "No predictions returned"
        assert preds[0] == "c.com", f"Expected c.com first, got {preds}"

class TestCacheMissTiming:

    def test_cache_miss_timing(self):
        """
        Measures DNS resolution time for NEW (uncached) domains
        to observe true cache miss latency.
        """

        server = "127.0.0.1"
        port = 5353

        # Use UNIQUE domains each time to force cache miss
        test_domains = [
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        "reddit.com",
        "cloudflare.com",
        "amazon.com",
        "twitter.com",
        "linkedin.com",
        "netflix.com",
        "discord.com",
        ]

        times = []

        for domain in test_domains:
            query = dns.message.make_query(domain, "A")

            start = time.perf_counter()
            response = dns.query.udp(query, server, port=port)
            end = time.perf_counter()

            elapsed = (end - start) * 1000  # ms
            times.append(elapsed)

            print(f"\n[CACHE MISS] {domain}")
            print(f"Time: {elapsed:.2f} ms")

            assert response is not None

        avg_time = sum(times) / len(times)

        print("\n--- CACHE MISS STATS ---")
        print(f"Average: {avg_time:.2f} ms")
        print(f"Min: {min(times):.2f} ms")
        print(f"Max: {max(times):.2f} ms")


    def test_hit_rate_above_90_percent(self, cache):
    # Load up the cache with some domains
        domains = [f"domain{i}.com" for i in range(20)]
        for domain in domains:
            cache.set(domain, ["1.2.3.4"], ttl=300)

    # Simulate realistic traffic — mostly repeated lookups (hits)
        for _ in range(9):                    # 9 rounds of hits
            for domain in domains:
                cache.get(domain)             # 180 hits total

        cache.get("notcached.com")            # 1 miss

        stats = cache.stats()
        print(f"\nHit rate: {stats['hit_rate_pct']}%")
        assert stats["hit_rate_pct"] >= 90.0, (
            f"Cache hit rate {stats['hit_rate_pct']}% is below 90%"
        )
