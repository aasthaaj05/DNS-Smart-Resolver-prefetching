"""
core/resolver.py
Sends DNS queries to upstream servers (e.g. 8.8.8.8) using dnspython.
Returns structured results that proxy.py and security/ can both use.

Public interface:
    resolver = DNSResolver()
    result = resolver.resolve(domain, record_type="A")   # -> ResolveResult
    result = resolver.resolve_ns(domain)                 # -> list[NSRecord]
"""

import time
from typing import List, Optional
from dataclasses import dataclass, field

import dns.resolver
import dns.rdatatype
import dns.exception

from utils.logger import get_logger
from utils.config import config

logger = get_logger(__name__)


@dataclass
class ResolveResult:
    """Returned by DNSResolver.resolve() for A/AAAA queries."""
    domain: str
    addresses: List[str]          # resolved IP addresses
    ttl: int                      # TTL from the DNS response
    record_type: str              # "A" or "AAAA"
    upstream: str                 # which upstream server answered
    latency_ms: float             # round-trip time
    success: bool = True
    error: Optional[str] = None


@dataclass
class NSRecord:
    """A single nameserver record with its resolved IP (if available)."""
    nameserver: str               # e.g. ns1.example.com
    ip: Optional[str] = None      # resolved IP of the nameserver
    responsive: Optional[bool] = None  # True if it answered a SOA query


class DNSResolver:
    """
    Wraps dnspython to query upstream DNS servers.
    Tries each configured upstream in order; fails over on timeout.
    """

    def __init__(self):
        self._cfg = config.dns
        self._upstream_list = self._cfg.upstream_servers
        self._timeout = self._cfg.query_timeout
        logger.info(
            "DNSResolver ready (upstreams=%s, timeout=%ds)",
            self._upstream_list, self._timeout,
        )

    # ── Public interface ────────────────────────────────────────────────────

    def resolve(self, domain: str, record_type: str = "A") -> ResolveResult:
        """
        Query upstream DNS for A or AAAA records.
        Tries each upstream in order; returns the first successful result.
        On total failure returns a ResolveResult with success=False.
        """
        domain = domain.rstrip(".")
        rdtype = dns.rdatatype.from_text(record_type)

        for upstream in self._upstream_list:
            result = self._query(domain, rdtype, record_type, upstream)
            if result.success:
                return result
            logger.warning("Upstream %s failed for %s: %s", upstream, domain, result.error)

        # All upstreams failed
        return ResolveResult(
            domain=domain,
            addresses=[],
            ttl=0,
            record_type=record_type,
            upstream="none",
            latency_ms=0,
            success=False,
            error="All upstream servers failed",
        )

    def resolve_ns(self, domain: str) -> List[NSRecord]:
        """
        Fetch NS records for a domain and attempt to resolve each nameserver's IP.
        Used by security/checker.py.
        Returns an empty list if NS lookup fails.
        """
        domain = domain.rstrip(".")
        ns_records: List[NSRecord] = []

        for upstream in self._upstream_list:
            try:
                res = self._make_resolver(upstream)
                answer = res.resolve(domain, "NS")
                for rdata in answer:
                    ns_name = str(rdata.target).rstrip(".")
                    ip = self._resolve_ns_ip(ns_name, upstream)
                    ns_records.append(NSRecord(nameserver=ns_name, ip=ip))
                logger.debug("NS for %s: %s", domain, [r.nameserver for r in ns_records])
                return ns_records
            except dns.exception.DNSException as e:
                logger.debug("NS lookup failed via %s for %s: %s", upstream, domain, e)

        return ns_records

    def is_responsive(self, nameserver_ip: str, domain: str) -> bool:
        """
        Check if a nameserver responds to a SOA query.
        Used by security/checker.py to detect lame delegations.
        """
        try:
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = [nameserver_ip]
            res.timeout = self._timeout
            res.lifetime = self._timeout
            res.resolve(domain, "SOA")
            return True
        except dns.exception.DNSException:
            return False

    # ── Internals ───────────────────────────────────────────────────────────

    def _query(
        self,
        domain: str,
        rdtype,
        record_type: str,
        upstream: str,
    ) -> ResolveResult:
        try:
            res = self._make_resolver(upstream)
            t0 = time.perf_counter()
            answer = res.resolve(domain, rdtype)
            latency_ms = (time.perf_counter() - t0) * 1000

            addresses = [str(rdata) for rdata in answer]
            ttl = answer.rrset.ttl if answer.rrset else config.cache.default_ttl

            logger.info(
                "Resolved %s (%s) -> %s via %s (%.1fms, ttl=%ds)",
                domain, record_type, addresses, upstream, latency_ms, ttl,
            )
            return ResolveResult(
                domain=domain,
                addresses=addresses,
                ttl=ttl,
                record_type=record_type,
                upstream=upstream,
                latency_ms=latency_ms,
            )

        except dns.resolver.NXDOMAIN:
            return self._fail(domain, record_type, upstream, "NXDOMAIN")
        except dns.resolver.NoAnswer:
            return self._fail(domain, record_type, upstream, "NoAnswer")
        except dns.resolver.Timeout:
            return self._fail(domain, record_type, upstream, "Timeout")
        except dns.exception.DNSException as e:
            return self._fail(domain, record_type, upstream, str(e))

    def _resolve_ns_ip(self, ns_name: str, upstream: str) -> Optional[str]:
        """Resolve a nameserver hostname to its IP address."""
        try:
            res = self._make_resolver(upstream)
            answer = res.resolve(ns_name, "A")
            return str(answer[0])
        except dns.exception.DNSException:
            return None

    def _make_resolver(self, upstream: str) -> dns.resolver.Resolver:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [upstream]
        res.port = self._cfg.upstream_port
        res.timeout = self._timeout
        res.lifetime = self._timeout
        return res

    @staticmethod
    def _fail(domain, record_type, upstream, error) -> ResolveResult:
        return ResolveResult(
            domain=domain, addresses=[], ttl=0,
            record_type=record_type, upstream=upstream,
            latency_ms=0, success=False, error=error,
        )