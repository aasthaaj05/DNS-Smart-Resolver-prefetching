"""
Detects two classic DNS misconfigurations:

1. Lame delegation — a nameserver is listed for a domain but does not
   actually answer authoritatively for it. This causes resolution failures
   and is a known hijacking vector.

2. Cyclic NS dependency — ALL nameservers are in-bailiwick (subdomains of
   the domain) AND none have resolvable IPs, creating a genuine bootstrap
   deadlock. Note: in-bailiwick NS WITH glue records (e.g. ns1.google.com
   for google.com) is completely normal and is NOT flagged as cyclic.
"""

from typing import List
from utils.logger import get_logger

logger = get_logger(__name__)


class LameDetector:

    def __init__(self, resolver):
        self._resolver = resolver

    def find_lame_nameservers(self, domain: str, ns_records) -> List[str]:
        """
        For each nameserver, check if it actually responds to a SOA query
        for the domain. Returns list of nameserver names that are lame.

        A nameserver is lame if:
          - Its IP could not be resolved, OR
          - It does not respond to a SOA query for the domain
        """
        lame = []

        for ns in ns_records:
            if ns.ip is None:
                logger.debug(
                    "NS %s for %s has no resolvable IP — marking lame",
                    ns.nameserver, domain,
                )
                lame.append(ns.nameserver)
                continue

            responsive = self._resolver.is_responsive(ns.ip, domain)
            if not responsive:
                logger.debug(
                    "NS %s (%s) did not answer SOA for %s — marking lame",
                    ns.nameserver, ns.ip, domain,
                )
                lame.append(ns.nameserver)

        return lame

    def detect_cycle(self, domain: str, ns_records) -> bool:
        """
        Detect a TRUE cyclic NS dependency.

        In-bailiwick NS (e.g. ns1.google.com serving google.com) is completely
        normal when glue records exist — Google, Facebook, and most large domains
        do this. A real cycle only occurs when ALL nameservers are in-bailiwick
        AND none have a resolvable IP, meaning the resolver cannot bootstrap the
        NS address lookup without already knowing it.

        Returns True only in that genuine deadlock case.
        """
        base = domain.lower().rstrip(".")

        in_bailiwick = [
            ns for ns in ns_records
            if ns.nameserver.lower().rstrip(".").endswith("." + base)
            or ns.nameserver.lower().rstrip(".") == base
        ]

        if not in_bailiwick:
            return False

        # Only a real cycle if every NS is in-bailiwick AND none are resolvable
        all_in_bailiwick = len(in_bailiwick) == len(ns_records)
        all_unresolvable = all(ns.ip is None for ns in in_bailiwick)

        if all_in_bailiwick and all_unresolvable:
            logger.debug(
                "True cyclic NS for %s: all NS in-bailiwick, none resolvable", base
            )
            return True

        return False