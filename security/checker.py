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

Results are cached in-memory so the same domain is not re-checked
within a cooldown window (default 10 minutes) — NS checks involve
real network calls and we don't want to hammer upstream on every query.
"""

import time
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
    Thread-safe: each check is self-contained and the result cache is
    only written once per domain per cooldown window.
    """

    def __init__(self, resolver):
        self._resolver = resolver
        self._lame_detector = LameDetector(resolver)
        self._risk_scorer = RiskScorer()
        self._cache: Dict[str, tuple] = {}   # domain → (report, timestamp)

    def check(self, domain: str) -> Optional[SecurityReport]:
        """
        Run a full security check on domain.
        Returns a SecurityReport, or None if NS lookup fails entirely.
        Results are cached for _RECHECK_COOLDOWN seconds.
        """
        domain = domain.rstrip(".")

        # Return cached result if still fresh
        cached = self._cache.get(domain)
        if cached:
            report, ts = cached
            if time.time() - ts < _RECHECK_COOLDOWN:
                logger.debug("Security cache hit for %s", domain)
                return report

        logger.debug("Running security check for %s", domain)

        # Step 1: fetch NS records
        ns_records = self._resolver.resolve_ns(domain)

        if not ns_records:
            logger.warning(
                "No NS records found for %s — skipping security check", domain
            )
            return None

        # Step 2: detect lame nameservers
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

        # Step 5: cache and return
        self._cache[domain] = (report, time.time())
        return report

    def clear_cache(self) -> None:
        """Force re-check on next call for all domains."""
        self._cache.clear()

    def cached_reports(self) -> Dict[str, SecurityReport]:
        """Return all cached reports — useful for a summary dashboard."""
        return {domain: report for domain, (report, _) in self._cache.items()}

    def summary(self) -> None:
        """Print a human-readable summary of all checked domains."""
        print("\n--- Security Summary ---")
        if not self._cache:
            print("No domains checked yet.")
            return

        for domain, (report, ts) in self._cache.items():
            flag = {
                "Low":    "  OK",
                "Medium": "WARN",
                "High":   "CRIT",
            }.get(report.risk_level, "????")

            print(f"[{flag}] {domain:40s} score={report.score}")
            for detail in report.details:
                print(f"       • {detail}")