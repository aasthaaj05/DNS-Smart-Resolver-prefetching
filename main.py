"""
    sudo python main.py --port 5353  # unprivileged port for testing
"""

import argparse
import signal
import sys
import threading
import time

from core.cache import DNSCache
from core.resolver import DNSResolver
from core.proxy import DNSProxy
from utils.logger import get_logger
from utils.config import config
from graph.graph_builder import DependencyGraph

logger = get_logger(__name__)

# ── Optional modules — graceful fallback if not yet implemented ──────────────
try:
    from prefetch.prefetcher import PrefetchEngine
    PREFETCH_AVAILABLE = True
    logger.info("Prefetch module loaded (with Markov predictor)")
except ImportError:
    PREFETCH_AVAILABLE = False
    logger.warning("prefetch module not available — running without prefetch")

try:
    from security.checker import SecurityChecker
    SECURITY_AVAILABLE = True
    logger.info("Security module loaded")
except ImportError:
    SECURITY_AVAILABLE = False
    logger.warning("security module not available — running without security checks")
# ─────────────────────────────────────────────────────────────────────────────


def build_prefetch_callback(prefetch_engine=None):
    """
    Returns a callback for proxy.register_callback().
    Called after every successful DNS resolution.

    FIX: added client_ip param to match updated proxy callback signature.
    FIX: moved on_resolved definition outside the early-return guard so
         it is always returned — previously the function returned None
         when prefetch was unavailable, causing proxy to call None().
    """
    def on_resolved(domain: str, addresses: list,
                    client_ip: str = "127.0.0.1") -> None:
        if not PREFETCH_AVAILABLE or prefetch_engine is None:
            return
        try:
            prefetch_engine.run(domain)
        except Exception:
            logger.error("Prefetch failed for %s", domain, exc_info=True)

    on_resolved.__name__ = "prefetch_callback"
    return on_resolved


def build_security_callback(security_checker=None):
    """
    Returns a callback for proxy.register_callback().
    Runs background NS integrity + malicious domain check after each resolution.

    FIX: was referencing undefined variables `checker` and `client_ip` —
         now correctly uses the `security_checker` closure and the
         `client_ip` parameter passed through from proxy.
    FIX: added client_ip param to match updated proxy callback signature.
    """
    def on_resolved(domain: str, addresses: list,
                    client_ip: str = "127.0.0.1") -> None:
        if not SECURITY_AVAILABLE or security_checker is None:
            return
        try:
            report = security_checker.check(domain, client_ip=client_ip)
            if report is None:
                return
            if report.rate_limited:
                logger.warning(
                    "[SECURITY] Rate limited: %s from %s", domain, client_ip
                )
            elif report.malicious_domain:
                logger.warning(
                    "[SECURITY] Malicious domain blocked: %s — %s [%s]",
                    domain, report.malicious_reason, report.malicious_type,
                )
            elif report.risk_level in ("Medium", "High"):
                logger.warning(
                    "[SECURITY] NS risk for %s: %s (score=%d) — %s",
                    domain, report.risk_level, report.score, report.reason,
                )
            else:
                logger.debug("[SECURITY] %s — clean (score=%d)", domain, report.score)
        except Exception:
            logger.error(
                "Security check failed for %s", domain, exc_info=True
            )

    on_resolved.__name__ = "security_callback"
    return on_resolved

def build_graph_callback(graph):
    def on_resolved(domain, addresses):
        try:
            graph.build_from_domain(domain)

            deps = graph.get_dependencies(domain)

            print(f"\n[GRAPH] {domain}")
            print(f"Dependencies: {deps}")
            print(f"Dependency count: {graph.get_dependency_count(domain)}")
            print(f"Max depth: {graph.get_max_depth(domain)}")

        except Exception:
            logger.error("Graph build failed for %s", domain, exc_info=True)

    on_resolved.__name__ = "graph_callback"
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

    config.dns.listen_host = args.host
    config.dns.listen_port = args.port

    logger.info("=== Smart DNS Resolver starting ===")
    logger.info(
        "Config: upstream=%s, port=%d, cache_max=%d",
        config.dns.upstream_servers,
        config.dns.listen_port,
        config.cache.max_entries,
    )

    # ── Core components ──────────────────────────────────────────────────────
    cache    = DNSCache()
    resolver = DNSResolver()
    graph = DependencyGraph()
    proxy    = DNSProxy(cache, resolver)

    # ── Optional modules ─────────────────────────────────────────────────────
    prefetch_engine  = PrefetchEngine(cache, resolver) if PREFETCH_AVAILABLE else None
    security_checker = SecurityChecker(resolver)       if SECURITY_AVAILABLE else None

    # ── Register callbacks with proxy ────────────────────────────────────────
    # FIX: both callbacks are always registered (they guard internally)
    # so proxy never calls None even if modules are unavailable.
    proxy.register_callback(build_prefetch_callback(prefetch_engine))
    proxy.register_callback(build_security_callback(security_checker))

    # ── Background stats reporter (every 60s) ────────────────────────────────
    def stats_reporter():
        while True:
            time.sleep(60)
            logger.info("Cache stats: %s", cache.stats())
            graph.print_summary()
            if security_checker:
                logger.info("Security stats: %s", security_checker.stats())

    threading.Thread(target=stats_reporter, daemon=True).start()

    # ── Graceful shutdown ────────────────────────────────────────────────────
    # FIX: shutdown logic was BEFORE signal.signal() registration — it ran
    # immediately on startup instead of on Ctrl-C. Moved inside the handler.
    def shutdown(sig, frame):
        logger.info("Shutdown signal received — stopping...")

        if prefetch_engine:
            try:
                prefetch_engine.predictor.save()
                logger.info("Markov model saved on shutdown")
            except Exception:
                logger.error("Failed to save Markov model", exc_info=True)

        logger.info("Cache stats at shutdown: %s", cache.stats())

        if security_checker:
            security_checker.summary()

        proxy.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start proxy (blocking) ───────────────────────────────────────────────
    try:
        proxy.start()
    except PermissionError:
        logger.error(
            "Permission denied — run with sudo or use --port 5353 for testing."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()