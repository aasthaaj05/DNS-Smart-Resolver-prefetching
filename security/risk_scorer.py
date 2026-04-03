"""
Takes the raw findings from checker.py and produces a human-readable
risk level (Low / Medium / High) with a plain-English reason.

Scoring rules (additive):
  +3  any lame nameserver detected
  +3  cyclic NS dependency detected
  +2  all nameservers share the same IP  (false redundancy)
  +1  fewer than 2 nameservers           (single point of failure)
  +1  any nameserver IP could not be resolved

  0      → Low
  1–2    → Medium
  3+     → High

New fields in SecurityReport:
  - rate_limited      : True if query was blocked by rate limiter
  - malicious_domain  : True if blocked by malicious detector
  - malicious_reason  : human-readable reason for malicious block
  - malicious_type    : "blocklist" | "homoglyph" | "heuristic"
"""

from dataclasses import dataclass, field
from typing import List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SecurityReport:
    domain: str
    risk_level: str                  # "Low" | "Medium" | "High"
    score: int
    reason: str                      # one-line summary for log warning
    details: List[str] = field(default_factory=list)
    lame_nameservers: List[str] = field(default_factory=list)
    shared_ip: bool = False
    cyclic: bool = False
    ns_count: int = 0

    # New fields — set by checker.py before NS check runs
    rate_limited: bool = False
    malicious_domain: bool = False
    malicious_reason: Optional[str] = None
    malicious_type: Optional[str] = None   # "blocklist"|"homoglyph"|"heuristic"


class RiskScorer:

    def score(
        self,
        domain: str,
        ns_records,
        lame_nameservers: List[str],
        cyclic: bool,
    ) -> SecurityReport:
        """
        Produce a SecurityReport given the raw NS findings.
        Called by checker.py after it gathers all the evidence.
        """
        points = 0
        details = []
        ns_count = len(ns_records)

        # Rule 1: lame delegations
        if lame_nameservers:
            points += 3
            details.append(
                f"Lame nameservers: {', '.join(lame_nameservers)}"
            )

        # Rule 2: cyclic dependency
        if cyclic:
            points += 3
            details.append("Cyclic NS dependency detected")

        # Rule 3: all NS share same IP (false redundancy)
        ips = [ns.ip for ns in ns_records if ns.ip is not None]
        shared_ip = len(ips) >= 2 and len(set(ips)) == 1
        if shared_ip:
            points += 2
            details.append(
                f"All {len(ips)} nameservers share the same IP ({ips[0]})"
            )

        # Rule 4: only one nameserver
        if ns_count < 2:
            points += 1
            details.append(
                f"Only {ns_count} nameserver(s) — no redundancy"
            )

        # Rule 5: unresolvable NS IPs
        unresolvable = [ns.nameserver for ns in ns_records if ns.ip is None]
        if unresolvable:
            points += 1
            details.append(
                f"Cannot resolve IP for: {', '.join(unresolvable)}"
            )

        if points == 0:
            risk_level = "Low"
        elif points <= 2:
            risk_level = "Medium"
        else:
            risk_level = "High"

        reason = details[0] if details else "No issues found"

        report = SecurityReport(
            domain=domain,
            risk_level=risk_level,
            score=points,
            reason=reason,
            details=details,
            lame_nameservers=lame_nameservers,
            shared_ip=shared_ip,
            cyclic=cyclic,
            ns_count=ns_count,
        )

        logger.info(
            "NS security report for %s: %s (score=%d) — %s",
            domain, risk_level, points,
            "; ".join(details) if details else "clean",
        )

        return report