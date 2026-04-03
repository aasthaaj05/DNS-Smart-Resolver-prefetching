"""
Rate Limiter — per-IP query rate limiting with token bucket algorithm.

Prevents:
    - DNS amplification attacks (attacker uses your resolver to flood targets)
    - Brute-force enumeration (scanning thousands of subdomains)
    - Resource exhaustion (single client overwhelming the resolver)

Algorithm: Token Bucket
    - Each IP gets a bucket of tokens (default: 60)
    - Each query consumes 1 token
    - Tokens refill at a fixed rate (default: 10/second)
    - When bucket is empty, queries are rejected until refill

This allows short bursts (e.g. page load triggers 20 DNS queries at once)
while still preventing sustained abuse.

Public interface:
    limiter = RateLimiter()
    if not limiter.allow(client_ip):
        return REJECTED
    stats = limiter.stats()
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Token bucket configuration
DEFAULT_BUCKET_SIZE    = 60    # max burst — allows a full page load
DEFAULT_REFILL_RATE    = 10    # tokens per second — sustained query rate
DEFAULT_BLOCK_DURATION = 30    # seconds to block IP after sustained abuse
ABUSE_THRESHOLD        = 5     # times rate limited before temp block

# ── IPs that are always allowed regardless of rate
WHITELIST = {
    "127.0.0.1",   # localhost
    "::1",         # IPv6 localhost
}


@dataclass
class BucketState:
    tokens: float
    last_refill: float
    times_limited: int = 0
    blocked_until: float = 0.0


class RateLimiter:
    """
    Per-IP token bucket rate limiter.
    Thread-safe — all bucket state is protected by a single lock.
    Automatically cleans up inactive IPs every 5 minutes.
    """

    def __init__(
        self,
        bucket_size: int = DEFAULT_BUCKET_SIZE,
        refill_rate: float = DEFAULT_REFILL_RATE,
        block_duration: int = DEFAULT_BLOCK_DURATION,
        
    ):
        self._bucket_size = bucket_size
        self._refill_rate = refill_rate
        self._block_duration = block_duration
        self._total_whitelisted = 0

        self._buckets: dict[str, BucketState] = {}
        self._lock = threading.Lock()

        # Counters for stats
        self._total_allowed = 0
        self._total_rejected = 0
        self._total_blocked = 0

        # Background cleanup — remove inactive IPs to prevent memory growth
        self._sweeper = threading.Thread(
            target=self._sweep_loop, daemon=True
        )
        self._sweeper.start()

        logger.info(
            "Rate limiter started (bucket=%d, refill=%d/s, block=%ds)",
            bucket_size, refill_rate, block_duration,
        )

    # ─────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────

    def allow(self, client_ip: str) -> bool:
        """
        Check if a query from client_ip should be allowed.
        Returns True if allowed, False if rate limited.

        Token bucket algorithm:
            1. Refill tokens based on time elapsed since last query
            2. If tokens >= 1: consume 1 token, allow query
            3. If tokens < 1: reject query, increment abuse counter
            4. If abuse counter >= ABUSE_THRESHOLD: temp block IP
        """
        # Whitelisted IPs always pass
        if client_ip in WHITELIST:
            with self._lock:
                self._total_allowed += 1
                self._total_whitelisted += 1
            return True

        now = time.time()

        with self._lock:
            bucket = self._get_or_create_bucket(client_ip, now)

            # Check if IP is temporarily blocked
            if now < bucket.blocked_until:
                self._total_blocked += 1
                logger.warning(
                    "BLOCKED query from %s (blocked for %.0fs more)",
                    client_ip, bucket.blocked_until - now
                )
                return False

            # Refill tokens based on elapsed time
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                self._bucket_size,
                bucket.tokens + elapsed * self._refill_rate
            )
            bucket.last_refill = now

            # Allow or reject based on token availability
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                self._total_allowed += 1
                return True
            else:
                # Rate limited
                bucket.times_limited += 1
                self._total_rejected += 1

                logger.warning(
                    "Rate limit exceeded for %s (times_limited=%d)",
                    client_ip, bucket.times_limited
                )

                # Escalate to temp block after repeated abuse
                if bucket.times_limited >= ABUSE_THRESHOLD:
                    bucket.blocked_until = now + self._block_duration
                    bucket.times_limited = 0  # reset counter after block
                    logger.warning(
                        "IP %s temporarily blocked for %ds "
                        "(repeated rate limit violations)",
                        client_ip, self._block_duration
                    )

                return False

    def stats(self) -> dict:
        """Return rate limiter health metrics."""
        with self._lock:
            total = self._total_allowed + self._total_rejected
            blocked_ips = sum(
                1 for b in self._buckets.values()
                if time.time() < b.blocked_until
            )
            return {
                "total_allowed":    self._total_allowed,
                "total_rejected":   self._total_rejected,
                "total_blocked":    self._total_blocked,
                "rejection_rate":   round(
                    self._total_rejected / total * 100, 1
                ) if total > 0 else 0.0,
                "active_ips":       len(self._buckets),
                "currently_blocked_ips": blocked_ips,
                "bucket_size":      self._bucket_size,
                "refill_rate":      self._refill_rate,
                "total_whitelisted": self._total_whitelisted,
                "active_ips":       len(self._buckets),
            }

    def unblock(self, client_ip: str) -> bool:
        """Manually unblock an IP. Returns True if it was blocked."""
        with self._lock:
            if client_ip in self._buckets:
                self._buckets[client_ip].blocked_until = 0.0
                self._buckets[client_ip].times_limited = 0
                logger.info("Manually unblocked %s", client_ip)
                return True
            return False

    def is_blocked(self, client_ip: str) -> bool:
        """Check if an IP is currently in a temp block."""
        with self._lock:
            bucket = self._buckets.get(client_ip)
            if bucket is None:
                return False
            return time.time() < bucket.blocked_until

    # ─────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────

    def _get_or_create_bucket(self, client_ip: str, now: float) -> BucketState:
        """Get existing bucket or create a full one for new IPs."""
        if client_ip not in self._buckets:
            self._buckets[client_ip] = BucketState(
                tokens=self._bucket_size,
                last_refill=now,
            )
        return self._buckets[client_ip]

    def _sweep_loop(self) -> None:
        """Remove inactive IPs every 5 minutes to prevent memory growth."""
        while True:
            time.sleep(300)
            self._sweep_inactive()

    def _sweep_inactive(self) -> None:
        """
        Remove bucket entries for IPs that have been inactive for > 10 minutes.
        An inactive IP will get a fresh full bucket when they next query —
        which is the correct behaviour.
        """
        now = time.time()
        cutoff = now - 600  # 10 minutes inactive

        with self._lock:
            inactive = [
                ip for ip, bucket in self._buckets.items()
                if bucket.last_refill < cutoff
                and now >= bucket.blocked_until
            ]
            for ip in inactive:
                del self._buckets[ip]

        if inactive:
            logger.debug(
                "Rate limiter sweep: removed %d inactive IP buckets",
                len(inactive)
            )