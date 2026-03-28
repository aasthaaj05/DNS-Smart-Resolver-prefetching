"""
Public interface for the security module.
Called by main.py via:

    checker = SecurityChecker(resolver)
    report  = checker.check("google.com")
    if report.risk_level in ("Medium", "High"):
        logger.warning(...)

Internally orchestrates:
  1. Fetch NS records       (via resolver.resolve_ns)
  2. Detect lame NS         (via LameDetector)
  3. Detect cyclic deps     (via LameDetector)
  4. Score everything       (via RiskScorer)
  5. Return SecurityReport

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
from typing import Dict, Optional

from security.lame_detector import LameDetector
from security.risk_scorer import RiskScorer, SecurityReport
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

        # FIX: renamed from `_cache` → `_report_cache` to make it immediately
        # clear this stores SecurityReport objects, not DNS address records.
        # The old name was easily confused with the DNSCache instance in main.py.
        self._report_cache: Dict[str, tuple] = {}   # domain → (SecurityReport, timestamp)

        # FIX: added a lock so concurrent proxy daemon threads don't race on
        # the same domain entry and trigger duplicate upstream NS lookups.
        self._report_lock = threading.Lock()

    def check(self, domain: str) -> Optional[SecurityReport]:
        """
        Run a full security check on domain.
        Returns a SecurityReport, or None if NS lookup fails entirely.
        Results are cached for _RECHECK_COOLDOWN seconds.
        """
        domain = domain.rstrip(".")

        # Return cached result if still fresh
        with self._report_lock:
            cached = self._report_cache.get(domain)
            if cached:
                report, ts = cached
                if time.time() - ts < _RECHECK_COOLDOWN:
                    logger.debug("Security report cache hit for %s", domain)
                    return report

        logger.debug("Running security check for %s", domain)

        # Step 1: fetch NS records (done outside the lock — network I/O)
        ns_records = self._resolver.resolve_ns(domain)

        if not ns_records:
            logger.warning(
                "No NS records found for %s — skipping security check", domain
            )
            return None

        # Step 2: detect lame nameservers (network I/O — outside lock)
        lame = []
        if config.security.check_ns_responsiveness:
            lame = self._lame_detector.find_lame_nameservers(domain, ns_records)

        # Step 3: detect cyclic NS dependency
        cyclic = self._lame_detector.detect_cycle(domain, ns_records)

        # Step 4: score and produce report
        report = self._risk_scorer.score(
            domain=domain,
            ns_records=ns_records,
            lame_nameservers=lame,
            cyclic=cyclic,
        )

        # Step 5: store in report cache and return
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