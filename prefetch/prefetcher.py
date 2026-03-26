from concurrent.futures import ThreadPoolExecutor, as_completed
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

        # 🔥 LIMIT THREADS (prevents slowdown)
        self.pool = ThreadPoolExecutor(max_workers=5)

        # 🔥 Separate pool for DNS resolution (parallel lookups)
        self.resolve_pool = ThreadPoolExecutor(max_workers=10)

        # Load Markov learning
        self.predictor.load()

    # ─────────────────────────────
    def run(self, domain: str):
        # Submit prefetch job (non-blocking)
        self.pool.submit(self._prefetch_task, domain)

    # ─────────────────────────────
    def _prefetch_task(self, domain: str):

        logger.info(f"[PREFETCH] Running for {domain}")

        # 🔥 Step 1: Learn navigation pattern
        self.predictor.update(domain)

        # 🔥 Step 2: Extract dependencies (HTML)
        dependencies = list(self.extractor.extract_domains(domain))

        # 🔥 Step 3: Score + rank
        ranked_html = self._score_domains(dependencies)

        # 🔥 LIMIT (CRITICAL for performance)
        ranked_html = ranked_html[:5]

        logger.info(f"[PREFETCH] Ranked HTML deps: {ranked_html}")

        # 🔥 Step 4: Markov prediction
        markov_preds = []
        if len(self.predictor.history) >= 2:
            prev = self.predictor.history[-2]
            curr = self.predictor.history[-1]

            markov_preds = self.predictor.predict(prev, curr)
            markov_preds = markov_preds[:3]

            logger.info(f"[MARKOV] Predictions: {markov_preds}")

        # 🔥 Step 5: Merge + deduplicate
        all_targets = list(set(ranked_html + markov_preds))

        # 🔥 Step 6: Parallel resolve (BIG SPEED BOOST)
        futures = []
        
        for d in all_targets:
            if not self._is_valid_domain(d):
                logger.debug(f"[FILTER] Skipped invalid domain: {d}")
                continue

            futures.append(
                self.resolve_pool.submit(self._resolve_and_cache, d)
            )

        # Optional: wait for completion (or skip for ultra async)
        for f in as_completed(futures):
            pass

    # ─────────────────────────────
    def _resolve_and_cache(self, domain: str):

        # 🔥 Skip if already cached
        if self.cache.get(domain):
            return

        try:
            result = self.resolver.resolve(domain)

            if result.success and result.addresses:
                self.cache.set(domain, result.addresses, result.ttl)
                logger.info(f"[CACHE] Stored {domain}")

        except Exception:
            logger.error(
                f"[PREFETCH] Failed to resolve {domain}",
                exc_info=True
            )

    # ─────────────────────────────
    def _score_domains(self, domains):
        scored = []

        for d in domains:
            score = 0

            # 🔥 CDN / static boost
            if any(x in d for x in ["cdn", "static", "assets", "img"]):
                score += 3

            # 🔥 Short domain = likely important
            if len(d) < 15:
                score += 1

            # 🔥 Markov boost
            if len(self.predictor.history) >= 2:
                prev = self.predictor.history[-2]
                curr = self.predictor.history[-1]

                preds = self.predictor.predict(prev, curr)
                if d in preds:
                    score += 5

            scored.append((d, score))

        # Sort descending
        scored.sort(key=lambda x: x[1], reverse=True)

        return [d for d, _ in scored]
    
    def _is_valid_domain(self, domain: str) -> bool:
        if not domain:
            return False

    #  Must contain dot (basic domain check)
        if "." not in domain:
            return False

        # Reject numeric garbage
        if domain.isdigit():
            return False

    #  Must contain dot (basic domain check)
        if "." not in domain:
            return False

        # Reject android / package style
        if domain.startswith("com.") or domain.startswith("org."):
            return False

    # Reject too long junk
        if len(domain) > 50:
            return False

        return True