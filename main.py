"""
    sudo python main.py --port 5353  # unprivileged port for testing
"""

import argparse
import signal
import sys
import threading

from core.cache import DNSCache
from core.resolver import DNSResolver
from core.proxy import DNSProxy
from utils.logger import get_logger
from utils.config import config



logger = get_logger(__name__)



# ── Stub imports (filled in by Persons 2 & 3) ──────────────────────────────
# Person 2 will replace these stubs:
try:
    from prefetch.prefetcher import PrefetchEngine
    PREFETCH_AVAILABLE = True
except ImportError:
    PREFETCH_AVAILABLE = False
    logger.warning("prefetch module not yet available — running without prefetch")

print("PREFETCH_AVAILABLE =", PREFETCH_AVAILABLE)

# Person 3 will replace these stubs:
try:
    from security.checker import SecurityChecker
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    logger.warning("security module not yet available — running without security checks")
# ──────────────────────────────────────────────────────────────────────────


def build_prefetch_callback(cache: DNSCache, prefetch_engine=None):
    """
    Returns a callback function for proxy.register_callback().
    When a domain resolves, fetches its HTML and pre-resolves dependencies.
    """
    def on_resolved(domain: str, addresses: list) -> None:
        if not PREFETCH_AVAILABLE or prefetch_engine is None:
            print("Prefetch engine instance:", prefetch_engine)
            return
        try:
            # Person 2: prefetch_engine.run(domain) should:
            #   1. Fetch HTML from http(s)://domain
            #   2. Extract dependency domains
            #   3. Resolve each and store in cache
            prefetch_engine.run(domain)
        except Exception:
            logger.error("Prefetch failed for %s", domain, exc_info=True)

    on_resolved.__name__ = "prefetch_callback"
    return on_resolved


def build_security_callback(resolver: DNSResolver, security_checker=None):
    """
    Returns a callback function for proxy.register_callback().
    Runs a background NS robustness check after each new resolution.
    """
    def on_resolved(domain: str, addresses: list) -> None:
        if not SECURITY_AVAILABLE or security_checker is None:
            return
        try:
            # Person 3: security_checker.check(domain) should:
            #   1. Fetch NS records via resolver
            #   2. Score risk (same-IP NS, lame delegation, etc.)
            #   3. Log a warning if risk is Medium or High
            report = security_checker.check(domain)
            if report and report.risk_level in ("Medium", "High"):
                logger.warning(
                    "Security risk for %s: %s (%s)",
                    domain, report.risk_level, report.reason,
                )
        except Exception:
            logger.error("Security check failed for %s", domain, exc_info=True)

    on_resolved.__name__ = "security_callback"
    return on_resolved


def parse_args():
    parser = argparse.ArgumentParser(description="Smart DNS Resolver")
    parser.add_argument(
        "--port", type=int,
        default=config.dns.listen_port,
        help="UDP port to listen on (default: 53, use 5353 for testing without root)",
    )
    parser.add_argument(
        "--host", type=str,
        default=config.dns.listen_host,
        help="Host/IP to bind (default: 127.0.0.1)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Override config with CLI args if provided
    config.dns.listen_host = args.host
    config.dns.listen_port = args.port

    logger.info("=== Smart DNS Resolver starting ===")
    logger.info("Config: upstream=%s, cache_max=%d",
                config.dns.upstream_servers, config.cache.max_entries)

    # core components 
    cache    = DNSCache()
    resolver = DNSResolver()
    proxy    = DNSProxy(cache, resolver)

    # ── Instantiate optional modules (stubs until Persons 2 & 3 are ready) ─
    prefetch_engine   = PrefetchEngine(cache, resolver) if PREFETCH_AVAILABLE else None
    security_checker  = SecurityChecker(resolver)       if SECURITY_AVAILABLE else None

    # ── Wire background callbacks into the proxy ────────────────────────────
    proxy.register_callback(build_prefetch_callback(cache, prefetch_engine))
    print("Prefetch callback registered")
    proxy.register_callback(build_security_callback(resolver, security_checker))

    # ── Graceful shutdown on Ctrl-C / SIGTERM ──────────────────────────────
    def shutdown(sig, frame):
        logger.info("Shutdown signal received — stopping proxy...")
        proxy.stop()
        logger.info("Cache stats at shutdown: %s", cache.stats())
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    #Print cache stats every 60s in background 
    def stats_reporter():
        import time
        while True:
            time.sleep(60)
            logger.info("Cache stats: %s", cache.stats())

    t = threading.Thread(target=stats_reporter, daemon=True)
    t.start()

    # Start proxy (blocking) 
    try:
        proxy.start()
    except PermissionError:
        logger.error(
            "Permission denied. Run with sudo, or use --port 5353 for testing."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()