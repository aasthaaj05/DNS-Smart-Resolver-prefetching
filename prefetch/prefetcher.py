import threading
from prefetch.extractor import HTMLDependencyExtractor


class PrefetchEngine:
    def __init__(self, cache, resolver):
        self.cache = cache
        self.resolver = resolver
        self.extractor = HTMLDependencyExtractor()

    def run(self, domain: str):
        thread = threading.Thread(
            target=self._prefetch_task,
            args=(domain,),
            daemon=True
        )
        thread.start()

    def _prefetch_task(self, domain: str):
        dependencies = self.extractor.extract_domains(domain)

        for dep in dependencies:
            try:
                # Resolve dependency
                result = self.resolver.resolve(dep)

                if result and result.addresses:
                    # Store in cache
                    self.cache.set(dep, result.addresses, result.ttl)

            except Exception:
                pass