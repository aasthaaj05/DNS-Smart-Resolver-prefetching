"""
UDP DNS proxy — the entry point for all DNS queries on this machine.

Flow for each incoming query:
  1. Receive raw UDP DNS packet from the OS
  2. Parse domain name from the query
  3. Check cache  →  hit: return cached response with real remaining TTL
  4.              →  miss: call resolver, cache result, return response
  5. Fire background tasks (prefetch, security) via callbacks
     (callbacks are registered by main.py so proxy.py stays decoupled)
"""

import socket
import threading
from typing import Callable, List, Optional

import dns.message
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.rdataclass
import dns.rcode
import dns.flags

from core.cache import DNSCache
from core.resolver import DNSResolver
from utils.logger import get_logger
from utils.config import config

logger = get_logger(__name__)

# DNS UDP buffer size.
# FIX: raised from 512 (legacy limit) to 4096 to handle EDNS0 extensions,
# which are used by virtually all modern resolvers and can push responses
# well past the original 512-byte ceiling.
_UDP_BUFFER = 4096

# Type alias for background task callbacks registered by main.py
OnResolvedCallback = Callable[[str, List[str], str], None]


class DNSProxy:
    """
    Listens on UDP 127.0.0.1:53 and proxies DNS queries.
    Cache-first, then upstream resolver.
    Background callbacks run in daemon threads — they never block responses.
    """

    def __init__(self, cache: DNSCache, resolver: DNSResolver):
        self._cache = cache
        self._resolver = resolver
        self._cfg = config.dns
        self._callbacks: List[OnResolvedCallback] = []
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._security_checker = None

    # Lifecycle

    def register_callback(self, cb: OnResolvedCallback) -> None:
        """
        Register a function to call after a domain is resolved.
        Signature: cb(domain: str, addresses: list[str]) -> None
        Called in a daemon thread — must be thread-safe.
        """
        self._callbacks.append(cb)
        logger.debug("Callback registered: %s", cb.__name__)

    def start(self) -> None:
        """Start the proxy (blocking). Call this from main.py."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self._cfg.listen_host, self._cfg.listen_port))
        except PermissionError:
            logger.error(
                "Cannot bind to %s:%d — try running with sudo (port 53 requires root)",
                self._cfg.listen_host, self._cfg.listen_port,
            )
            raise

        self._running = True
        logger.info(
            "DNS proxy listening on %s:%d",
            self._cfg.listen_host, self._cfg.listen_port,
        )

        while self._running:
            try:
                # FIX: use _UDP_BUFFER (4096) instead of the legacy 512-byte cap
                data, addr = self._sock.recvfrom(_UDP_BUFFER)
                t = threading.Thread(
                    target=self._handle_query,
                    args=(data, addr),
                    daemon=True,
                )
                t.start()
            except OSError:
                if self._running:
                    logger.error("Socket error in proxy receive loop", exc_info=True)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
        logger.info("DNS proxy stopped")

    # Query handling
    def _handle_query(self, data: bytes, addr: tuple) -> None:
        """Parse an incoming DNS query, resolve it, send UDP response."""
        try:
            request = dns.message.from_wire(data)
        except Exception as e:
            logger.warning("Malformed DNS query from %s: %s", addr, e)
            return

        if not request.question:
            return

        question = request.question[0]
        domain = str(question.name).rstrip(".")
        record_type = dns.rdatatype.to_text(question.rdtype)

        logger.debug("Query from %s: %s (%s)", addr, domain, record_type)
        client_ip = addr[0]

        # Only handle A/AAAA — pass anything else straight upstream
        if record_type not in ("A", "AAAA"):
            response = self._forward_raw(request, record_type, domain)
        else:
            response = self._resolve_with_cache(request, domain, record_type, client_ip)

        if response and self._sock:
            try:
                self._sock.sendto(response.to_wire(), addr)
            except OSError as e:
                logger.warning("Failed to send response to %s: %s", addr, e)

    def _resolve_with_cache(
        self,
        request: dns.message.Message,
        domain: str,
        record_type: str,
        client_ip: str,
    ) -> Optional[dns.message.Message]:
        """Cache-first resolution. Fires background callbacks on miss."""

        # FIX: `hasattr` check removed — `_security_checker` is always present
        # on the instance (set to None in __init__), so hasattr is always True
        # and the guard was misleading. A simple truthiness check is correct.
        if self._security_checker:
            report = self._security_checker.check(domain, client_ip=client_ip)
            if report and (report.malicious_domain or report.rate_limited):
                reason = "malicious domain" if report.malicious_domain else "rate limited"
                logger.warning("Blocked %s: %s from %s", reason, domain, client_ip)
                return self._build_nxdomain(request)

        # FIX: use get_with_ttl() so the response carries the real remaining
        # TTL rather than the old hardcoded ttl=60 fallback. Clients now get
        # accurate expiry information and won't re-query 60 s earlier than
        # necessary for entries with a longer TTL.
        cached_addresses, remaining_ttl = self._cache.get_with_ttl(domain)
        if cached_addresses is not None:
            logger.debug("Serving %s from cache (remaining TTL %ds)", domain, remaining_ttl)
            return self._build_response(
                request, domain, cached_addresses, record_type, ttl=remaining_ttl
            )

        # Cache miss — query upstream
        result = self._resolver.resolve(domain, record_type)

        if result.success:
            self._cache.set(domain, result.addresses, result.ttl)
            self._fire_callbacks(domain, result.addresses, client_ip)
            return self._build_response(
                request, domain, result.addresses, record_type, result.ttl
            )
        else:
            logger.warning("Resolution failed for %s: %s", domain, result.error)
            return self._build_nxdomain(request)

    def _forward_raw(
        self,
        request: dns.message.Message,
        record_type: str,
        domain: str,
    ) -> Optional[dns.message.Message]:
        """
        For non-A/AAAA queries (MX, TXT, etc.) just ask upstream and relay.
        We don't cache these — keep it simple.
        """
        result = self._resolver.resolve(domain, record_type)
        if result.success and result.addresses:
            return self._build_response(
                request, domain, result.addresses, record_type, result.ttl
            )
        return self._build_nxdomain(request)

    # Response builders

    @staticmethod
    def _build_response(
        request: dns.message.Message,
        domain: str,
        addresses: List[str],
        record_type: str,
        ttl: int,
    ) -> dns.message.Message:
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA
        response.flags |= dns.flags.QR

        rdtype = dns.rdatatype.from_text(record_type)
        rrset = response.find_rrset(
            response.answer,
            dns.name.from_text(domain + "."),
            dns.rdataclass.IN,
            rdtype,
            create=True,
        )
        rrset.ttl = ttl

        for addr in addresses:
            rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, addr)
            rrset.add(rdata)

        return response

    @staticmethod
    def _build_nxdomain(request: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    # Callbacks

    def _fire_callbacks(self, domain: str, addresses: List[str], client_ip: str) -> None:
        """Run each registered callback in its own daemon thread."""
        for cb in self._callbacks:
            t = threading.Thread(
                target=self._safe_call,
                args=(cb, domain, addresses, client_ip),
                daemon=True,
            )
            t.start()

    @staticmethod
    def _safe_call(cb: OnResolvedCallback, domain: str, addresses: List[str], client_ip: str) -> None:
        try:
            cb(domain, addresses, client_ip)
        except Exception:
            logger.error("Callback %s raised an exception", cb.__name__, exc_info=True)