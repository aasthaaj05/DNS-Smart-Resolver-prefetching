"""
Prefetch Engine — background DNS prefetcher using Markov prediction.

Flow:
    1. proxy.py fires run(domain) after every resolved query
    2. run() updates Markov model synchronously (preserves true query order)
    3. _prefetch_task() runs async — predicts next domains + resolves them
    4. _resolve_and_cache() uses get_with_ttl() to skip only if TTL > 60s
    5. Both A and AAAA records are resolved for dual-stack support

Fixes over previous version:
    - predictor.update() moved to run() — fixes race condition on query order
    - cache.get_with_ttl() replaces cache.get() — proactive refresh before expiry
    - resolver.resolve() called for both A and AAAA record types
    - _score_domains() signature fixed (accepts markov_scores dict)
    - preds variable renamed correctly (was undefined bug)
    - duplicate dot-check removed from _is_valid_domain()
    - dependencies extracted only once, not twice
"""

from concurrent.futures import ThreadPoolExecutor
from utils.logger import get_logger

from prefetch.extractor import HTMLDependencyExtractor
from prefetch.markov import MarkovPredictor

logger = get_logger(__name__)


class PrefetchEngine:
    def __init__(self, cache, resolver):
        self.cache = cache
        self.resolver = resolver
        self.extractor = HTMLDependencyExtractor()
        self.predictor = MarkovPredictor()

        # Thread pool for prefetch coordination (non-blocking)
        self.pool = ThreadPoolExecutor(max_workers=5)

        # Separate pool for parallel DNS resolution
        self.resolve_pool = ThreadPoolExecutor(max_workers=10)

        # Load previously learned Markov transitions
        self.predictor.load()

    # ─────────────────────────────────────────────────────────────
    # Public entry point — called by proxy.py callback
    # ─────────────────────────────────────────────────────────────

    def run(self, domain: str) -> None:
        """
        Called synchronously from proxy.py after every resolved query.

        FIX: predictor.update() is called HERE (synchronously) rather than
        inside the async task. This preserves the true query arrival order
        in the Markov history — if two queries arrive simultaneously and
        both went into the thread pool, their update() order would be
        non-deterministic. Calling it here ensures history always reflects
        the real sequence.
        """
        self.predictor.update(domain)

        # Persist every 10 domain visits
        if len(self.predictor.history) % 10 == 0:
            self.predictor.save()

        # Submit async prefetch task — does not block proxy response
        self.pool.submit(self._prefetch_task, domain)

    # ─────────────────────────────────────────────────────────────
    # Async prefetch task
    # ─────────────────────────────────────────────────────────────

    def _prefetch_task(self, domain: str) -> None:
        """
        Runs in thread pool. Predicts next domains and resolves them
        in the background so they are warm in cache before requested.

        Note: predictor.update() already called in run() — do NOT call
        it again here to avoid double-counting the domain visit.
        """
        logger.info(f"[PREFETCH] Running for {domain}")

        # ── Step 1: Markov predictions
        markov_preds = []
        markov_scores = {}

        if len(self.predictor.history) >= 2:
            # FIX: was 'preds' (undefined) — now correctly 'scored'
            scored = self.predictor.predict(top_k=3, return_scores=True)
            for d, score in scored:
                if score > 0.3:
                    markov_preds.append(d)
                    markov_scores[d] = score

            markov_preds = markov_preds[:3]
            logger.info(f"[MARKOV] Predictions: {markov_preds}")

        # ── Step 2: HTML dependency extraction (only if Markov has predictions)
        # FIX: extracted once here, not twice as before
        dependencies = []
        if markov_preds:
            dependencies = list(self.extractor.extract_domains(domain))[:5]

        # ── Step 3: Score HTML dependencies using precomputed markov_scores
        # FIX: _score_domains() now receives markov_scores dict — no repeated predict() call
        ranked_html = self._score_domains(dependencies, markov_scores)

        # ── Step 4: Merge Markov predictions + HTML deps, deduplicated
        all_targets = markov_preds + [
            d for d in ranked_html if d not in markov_preds
        ]

        logger.info(f"[PREFETCH] Final targets: {all_targets}")

        # ── Step 5: Resolve all targets in parallel (fire-and-forget)
        for d in all_targets:
            if self._is_valid_domain(d):
                self.resolve_pool.submit(self._resolve_and_cache, d)

    # ─────────────────────────────────────────────────────────────
    # Resolution + caching
    # ─────────────────────────────────────────────────────────────

    def _resolve_and_cache(self, domain: str) -> None:
        """
        Resolve a domain and cache the result.

        FIX 1: Uses cache.get_with_ttl() instead of cache.get().
            - If TTL > 60s remaining: skip (still fresh enough)
            - If TTL < 60s remaining: re-resolve now so it's warm before expiry
            - If not cached: resolve fresh
        This is the stale-while-revalidate pattern used by Unbound and Cloudflare.

        FIX 2: Resolves both A and AAAA records for dual-stack IPv4/IPv6 support.
        """
        # Check cache with real TTL
        addresses, remaining_ttl = self.cache.get_with_ttl(domain)
        if addresses and remaining_ttl > 60:
            # Still fresh — skip prefetch
            return

        if addresses and remaining_ttl <= 60:
            logger.info(f"[PREFETCH] TTL low ({remaining_ttl}s), refreshing {domain}")
        else:
            logger.info(f"[PREFETCH] Cache miss, resolving {domain}")

        # FIX: resolve both A and AAAA for dual-stack support
        for record_type in ("A", "AAAA"):
            try:
                result = self.resolver.resolve(domain, record_type)
                if result.success and result.addresses:
                    self.cache.set(domain, result.addresses, result.ttl)
                    logger.info(
                        f"[CACHE] Stored {domain} ({record_type}) "
                        f"-> {result.addresses} (ttl={result.ttl}s)"
                    )
            except Exception:
                logger.error(
                    f"[PREFETCH] Failed to resolve {domain} ({record_type})",
                    exc_info=True,
                )

    # ─────────────────────────────────────────────────────────────
    # Domain scoring
    # ─────────────────────────────────────────────────────────────

    def _score_domains(self, domains: list, markov_scores: dict) -> list:
        """
        Score HTML dependency domains for prefetch priority.

        FIX: accepts precomputed markov_scores dict instead of calling
        predictor.predict() again — avoids redundant prediction call
        that was previously made inside the scoring loop.

        Scoring factors:
            +3  CDN / static asset domain
            +1  Short domain name (< 15 chars, likely important)
            +5* Markov boost — weighted by actual prediction score
        """
        scored = []

        for d in domains:
            score = 0

            # CDN / static asset boost
            if any(x in d for x in ["cdn", "static", "assets", "img"]):
                score += 3

            # Short domain = likely important
            if len(d) < 15:
                score += 1

            # Markov boost — use precomputed scores, no extra predict() call
            if d in markov_scores:
                score += 5 * markov_scores[d]

            scored.append((d, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [d for d, _ in scored]

    # ─────────────────────────────────────────────────────────────
    # Domain validation
    # ─────────────────────────────────────────────────────────────

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Basic sanity check before attempting DNS resolution.

        FIX: removed duplicate dot-check that appeared twice in original.
        """
        if not domain:
            return False

        # Must contain a dot
        if "." not in domain:
            return False

        # Reject purely numeric strings
        if domain.isdigit():
            return False

        # Reject Android package-style strings (com.example.app)
        if domain.startswith("com.") or domain.startswith("org."):
            return False

        # Reject excessively long strings (likely garbage)
        if len(domain) > 50:
            return False

        return True