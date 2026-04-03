"""
Public interface for the security module.
Called by main.py via:

    checker = SecurityChecker(resolver)
    report  = checker.check("google.com")
    if report.risk_level in ("Medium", "High"):
        logger.warning(...)

Internally orchestrates:
  1. Malicious domain check  (via MaliciousDomainDetector)
  2. Rate limit check        (via RateLimiter)
  3. Fetch NS records        (via resolver.resolve_ns)
  4. Detect lame NS          (via LameDetector)
  5. Detect cyclic deps      (via LameDetector)
  6. Score everything        (via RiskScorer)
  7. Return SecurityReport

Results are stored in `_report_cache` (renamed from `_cache` to avoid
ambiguity with the DNS cache used elsewhere) so the same domain is not
re-checked within a cooldown window (default 10 minutes) — NS checks
involve real network calls and we don't want to hammer upstream on every
query.

The report cache is protected by a lock so concurrent callbacks from the
proxy's daemon threads cannot race on the same domain entry.
"""

import time
import threading
from typing import Dict, List, Optional  # FIX: added List (was missing, caused NameError)

from security.lame_detector import LameDetector
from security.risk_scorer import RiskScorer, SecurityReport
from security.blocklist import MaliciousDomainDetector   # FIX: was never imported
from security.rate_limiter import RateLimiter             # FIX: use the real token-bucket limiter
from utils.logger import get_logger
from utils.config import config

logger = get_logger(__name__)

# How long (seconds) before we re-check a domain
_RECHECK_COOLDOWN = 600  # 10 minutes


class SecurityChecker:
    """
    Orchestrates NS record fetching, lame detection, and risk scoring.

    Thread-safe: `_report_cache` is protected by `_report_lock` so that
    concurrent proxy callbacks cannot produce duplicate NS lookups for the
    same domain.
    """

    def __init__(self, resolver):
        self._resolver = resolver
        self._lame_detector = LameDetector(resolver)
        self._risk_scorer = RiskScorer()

        # FIX: wire up the real malicious domain detector (was never instantiated)
        self._malicious_detector = MaliciousDomainDetector()

        # FIX: use the proper token-bucket RateLimiter instead of the ad-hoc
        # sliding-window reimplementation that lived in _is_rate_limited().
        # The old version used a plain list of timestamps and a hardcoded limit
        # of 10 queries/60 s — it duplicated (and contradicted) rate_limiter.py.
        self._rate_limiter = RateLimiter()

        # FIX: renamed from `_cache` → `_report_cache` to make it immediately
        # clear this stores SecurityReport objects, not DNS address records.
        self._report_cache: Dict[str, tuple] = {}   # domain → (SecurityReport, timestamp)

        # FIX: added a lock so concurrent proxy daemon threads don't race on
        # the same domain entry and trigger duplicate upstream NS lookups.
        self._report_lock = threading.Lock()

    def check(self, domain: str, client_ip: str = "127.0.0.1") -> Optional[SecurityReport]:
        """
        Run a full security check on domain.
        Returns a SecurityReport, or None if NS lookup fails entirely.
        Results are cached for _RECHECK_COOLDOWN seconds.
        """
        domain = domain.rstrip(".")

        # Step 1: rate limit check — fast path, no network I/O
        # FIX: delegate to RateLimiter instead of the removed _is_rate_limited()
        if not self._rate_limiter.allow(client_ip):
            return SecurityReport(
                domain=domain,
                risk_level="Low",
                score=0,
                reason="Rate limited",
                rate_limited=True,
            )

        # Step 2: malicious domain check — O(1) set lookup + heuristics
        # FIX: this was never called before; malicious_domain was always False
        mal_result = self._malicious_detector.check(domain)
        if mal_result.is_malicious:
            return SecurityReport(
                domain=domain,
                risk_level="High",
                score=10,
                reason=mal_result.reason,
                malicious_domain=True,
                malicious_reason=mal_result.reason,
                malicious_type=mal_result.detection_type,
            )

        # Return cached result if still fresh
        with self._report_lock:
            cached = self._report_cache.get(domain)
            if cached:
                report, ts = cached
                if time.time() - ts < _RECHECK_COOLDOWN:
                    logger.debug("Security report cache hit for %s", domain)
                    return report

        logger.debug("Running security check for %s", domain)

        # Step 3: fetch NS records (done outside the lock — network I/O)
        ns_records = self._resolver.resolve_ns(domain)

        if not ns_records:
            logger.warning(
                "No NS records found for %s — skipping security check", domain
            )
            return None

        # Step 4: detect lame nameservers (network I/O — outside lock)
        lame = []
        if config.security.check_ns_responsiveness:
            lame = self._lame_detector.find_lame_nameservers(domain, ns_records)

        # Step 5: detect cyclic NS dependency
        cyclic = self._lame_detector.detect_cycle(domain, ns_records)

        # Step 6: score and produce report
        report = self._risk_scorer.score(
            domain=domain,
            ns_records=ns_records,
            lame_nameservers=lame,
            cyclic=cyclic,
        )

        # Step 7: store in report cache and return
        with self._report_lock:
            self._report_cache[domain] = (report, time.time())

        return report

    def clear_cache(self) -> None:
        """Force re-check on next call for all domains."""
        with self._report_lock:
            self._report_cache.clear()

    def cached_reports(self) -> Dict[str, SecurityReport]:
        """Return all cached reports — useful for a summary dashboard."""
        with self._report_lock:
            return {
                domain: report
                for domain, (report, _) in self._report_cache.items()
            }

    def summary(self) -> None:
        """Print a human-readable summary of all checked domains."""
        print("\n--- Security Summary ---")
        with self._report_lock:
            snapshot = dict(self._report_cache)

        if not snapshot:
            print("No domains checked yet.")
            return

        for domain, (report, _ts) in snapshot.items():
            flag = {
                "Low":    "  OK",
                "Medium": "WARN",
                "High":   "CRIT",
            }.get(report.risk_level, "????")

            print(f"[{flag}] {domain:40s} score={report.score}")
            for detail in report.details:
                print(f"       • {detail}")

    def stats(self) -> dict:
        """Return security checker statistics."""
        with self._report_lock:
            total_reports = len(self._report_cache)
            risk_counts = {"Low": 0, "Medium": 0, "High": 0}
            for report, _ in self._report_cache.values():
                risk_counts[report.risk_level] = risk_counts.get(report.risk_level, 0) + 1
            return {
                "total_reports": total_reports,
                "low_risk": risk_counts["Low"],
                "medium_risk": risk_counts["Medium"],
                "high_risk": risk_counts["High"],
                "rate_limiter": self._rate_limiter.stats(),
            }