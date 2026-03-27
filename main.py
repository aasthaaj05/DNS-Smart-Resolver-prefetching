"""
Wires all four modules together and starts the proxy.

Usage:
    python main.py --port 5353   # no sudo needed for testing
    sudo python main.py          # port 53, full deployment
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


# Module availability checks 
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

def build_prefetch_callback(prefetch_engine):
    """
    Fires PrefetchEngine.run(domain) in background after each resolution.
    PrefetchEngine (Person 2):
      - Fetches HTML, extracts dependency domains
      - Scores + ranks them (CDN boost, Markov boost)
      - Parallel-resolves top-N into cache
      - Updates Markov transition model
    """
    def on_resolved(domain: str, addresses: list) -> None:
        if prefetch_engine is None:
            return
        try:
            prefetch_engine.run(domain)
        except Exception:
            logger.error("Prefetch failed for %s", domain, exc_info=True)

    on_resolved.__name__ = "prefetch_callback"
    return on_resolved


def build_graph_callback(graph: DependencyGraph):
    """
    Fires DependencyGraph.build_from_domain(domain) after each resolution.
    DependencyGraph (Person 2):
      - Extracts HTML deps and stores in adjacency list
      - Tracks dependency counts and max chain depth
    """
    def on_resolved(domain: str, addresses: list) -> None:
        try:
            graph.build_from_domain(domain)
            deps  = graph.get_dependencies(domain)
            count = graph.get_dependency_count(domain)
            depth = graph.get_max_depth(domain)
            logger.info(
                "[GRAPH] %s → %d deps, max depth %d: %s",
                domain, count, depth, deps[:5],  # log first 5 to keep it readable
            )
        except Exception:
            logger.error("Graph build failed for %s", domain, exc_info=True)

    on_resolved.__name__ = "graph_callback"
    return on_resolved


def build_security_callback(security_checker):
    """
    Fires SecurityChecker.check(domain) after each resolution.
    SecurityChecker (Person 3 — you):
      - Fetches NS records
      - Detects lame delegations, cyclic deps, shared-IP nameservers
      - Scores Low / Medium / High risk
      - Logs a warning for Medium/High
    """
    def on_resolved(domain: str, addresses: list) -> None:
        if security_checker is None:
            return
        try:
            report = security_checker.check(domain)
            if report and report.risk_level in ("Medium", "High"):
                logger.warning(
                    "[SECURITY] %s risk for %s (score=%d): %s",
                    report.risk_level, domain, report.score, report.reason,
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
    config.dns.listen_host = args.host
    config.dns.listen_port = args.port

    logger.info("=== Smart DNS Resolver starting ===")
    logger.info(
        "Config: upstream=%s, port=%d, cache_max=%d",
        config.dns.upstream_servers,
        config.dns.listen_port,
        config.cache.max_entries,
    )

    cache    = DNSCache()
    resolver = DNSResolver()
    proxy    = DNSProxy(cache, resolver)
    graph           = DependencyGraph()
    prefetch_engine = PrefetchEngine(cache, resolver) if PREFETCH_AVAILABLE else None

    security_checker = SecurityChecker(resolver) if SECURITY_AVAILABLE else None

    # Register callbacks (order matters: prefetch → graph → security) 
    # prefetch first so dependencies are resolved before graph tries to map them
    proxy.register_callback(build_prefetch_callback(prefetch_engine))
    proxy.register_callback(build_graph_callback(graph))
    proxy.register_callback(build_security_callback(security_checker))

    logger.info(
        "Callbacks registered — prefetch=%s, graph=on, security=%s",
        "on" if PREFETCH_AVAILABLE else "off",
        "on" if SECURITY_AVAILABLE else "off",
    )

    # shutdown
    def shutdown(sig, frame):
        logger.info("Shutdown signal received — stopping...")
        proxy.stop()

        # Save Markov model on exit so it persists across sessions
        if prefetch_engine is not None:
            try:
                prefetch_engine.predictor.save()
                logger.info("Markov model saved")
            except Exception:
                logger.warning("Could not save Markov model", exc_info=True)

        logger.info("Cache stats at shutdown: %s", cache.stats())

        if security_checker is not None:
            security_checker.summary()

        graph.print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Periodic stats reporter (every 60s) 
    def stats_reporter():
        while True:
            time.sleep(60)
            logger.info("Cache stats: %s", cache.stats())
            graph.print_summary()
            if security_checker is not None:
                security_checker.summary()

    threading.Thread(target=stats_reporter, daemon=True).start()

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