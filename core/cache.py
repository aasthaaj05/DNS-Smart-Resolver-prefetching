"""
Adaptive TTL-aware DNS cache.

Public interface:
    cache = DNSCache()
    cache.set(domain, ip_list, ttl)
    result = cache.get(domain)      # returns list[str] or None
    cache.invalidate(domain)
    stats = cache.stats()
"""

import time
import threading
from typing import List, Optional, Dict
from dataclasses import dataclass, field

from utils.logger import get_logger
from utils.config import config

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    domain: str
    addresses: List[str]          # one or more resolved IPs
    ttl: int                      # effective TTL (seconds)
    created_at: float = field(default_factory=time.time)
    hit_count: int = 0            # for adaptive scoring

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def remaining_ttl(self) -> int:
        return max(0, int(self.expires_at - time.time()))
    
    @property
    def is_negative(self) -> bool:
        return self.addresses is None


class DNSCache:
    """
    Thread-safe in-memory DNS cache with:
    - Configurable min/max TTL clamping
    - LRU-style eviction when max_entries is reached
    - Hit-count tracking (used by prefetch module for prioritisation)
    - Background expiry sweeper
    """

    def __init__(self):
        self._store: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self._cfg = config.cache
        self._hits = 0        # add this
        self._misses = 0 

        # Start background expiry sweeper (runs every 60 seconds)
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True)
        self._sweeper.start()

        logger.info(
            "DNS cache initialised (max_entries=%d, min_ttl=%ds, max_ttl=%ds)",
            self._cfg.max_entries,
            self._cfg.min_ttl,
            self._cfg.max_ttl,
        )

    #Public interface

    def get(self, domain: str) -> Optional[List[str]]:
        """
        Return cached IP list for domain, or None on miss/expiry.
        Increments hit_count on a successful hit.
        """
        domain = domain.rstrip(".")
        with self._lock:
            entry = self._store.get(domain)
            if entry is None:
     
                self._misses += 1
            
                logger.debug("Cache MISS: %s", domain)
                return None
            if entry.is_expired:
                self._misses += 1
                logger.debug("Cache EXPIRED: %s (ttl was %ds)", domain, entry.ttl)
                del self._store[domain]
                return None
            self._hits += 1
            entry.hit_count += 1
            logger.debug(
                "Cache HIT: %s -> %s (remaining %ds, hits=%d)",
                domain, entry.addresses, entry.remaining_ttl, entry.hit_count,
            )
            return list(entry.addresses)

    def set(self, domain: str, addresses: List[str], ttl: Optional[int] = None) -> None:
        """
        Store a resolved entry.
        TTL is clamped to [min_ttl, max_ttl].
        Evicts the oldest entry if capacity is exceeded.

        """

        if addresses is not None and not addresses:
            logger.warning("Empty address list for %s", domain)
            return
        
        domain = domain.rstrip(".")
        if not addresses:
            logger.warning("Attempted to cache empty address list for %s", domain)
            return

        effective_ttl = self._clamp_ttl(ttl if ttl is not None else self._cfg.default_ttl)

        with self._lock:
            if len(self._store) >= self._cfg.max_entries and domain not in self._store:
                self._evict_oldest()

            self._store[domain] = CacheEntry(
                domain=domain,
                addresses=addresses,
                ttl=effective_ttl,
            )
            logger.debug("Cache SET: %s -> %s (ttl=%ds)", domain, addresses, effective_ttl)

    def invalidate(self, domain: str) -> bool:
        """Remove a single entry. Returns True if it existed."""
        domain = domain.rstrip(".")
        with self._lock:
            if domain in self._store:
                del self._store[domain]
                logger.debug("Cache INVALIDATED: %s", domain)
                return True
            return False

    def get_hit_counts(self) -> Dict[str, int]:
        """
        Returns {domain: hit_count} for all live entries.
        Used by prefetch module to prioritise popular domains.
        """
        with self._lock:
            return {d: e.hit_count for d, e in self._store.items() if not e.is_expired}

    def stats(self) -> dict:
        """Return a snapshot of cache health metrics."""
        with self._lock:
            total = len(self._store)
            expired = sum(1 for e in self._store.values() if e.is_expired)
            total_requests = self._hits + self._misses
            return {
                "total_entries": total,
                "live_entries": total - expired,
                "expired_entries": expired,
                "capacity": self._cfg.max_entries,
                "utilisation_pct": round(total / self._cfg.max_entries * 100, 1),
                "hits": self._hits,                          # add this
                "misses": self._misses,                      # add this
                "hit_rate_pct": round(                       # add this
                    self._hits / total_requests * 100, 1
                ) if total_requests > 0 else 0.0,
            }

    def _clamp_ttl(self, ttl: int) -> int:
        return max(self._cfg.min_ttl, min(ttl, self._cfg.max_ttl))

    def _evict_oldest(self) -> None:
        """Remove the entry with the earliest created_at (called under lock)."""
        if not self._store:
            return
        oldest = min(self._store, key=lambda d: self._store[d].created_at)
        del self._store[oldest]
        logger.debug("Cache EVICT (capacity): %s", oldest)

    def _sweep_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        with self._lock:
            expired_keys = [d for d, e in self._store.items() if e.is_expired]
            for key in expired_keys:
                del self._store[key]
        if expired_keys:
            logger.debug("Cache sweep: removed %d expired entries", len(expired_keys))
        return len(expired_keys)

    def _sweep_loop(self) -> None:
        """Background daemon thread — sweeps expired entries every 60s."""
        while True:
            time.sleep(60)
            self._sweep_expired()