import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


class HTMLDependencyExtractor:
    def __init__(self, timeout=1):  # reduced timeout
        self.timeout = timeout

    def fetch_html(self, domain: str) -> str:
        try:
            url = f"http://{domain}"
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            return response.text
        except Exception:
            try:
            # Fallback to HTTP
                url = f"http://{domain}"
                response = requests.get(url, timeout=self.timeout)
                return response.text
            except Exception:
                return ""

    def extract_domains(self, domain: str) -> set:
        html = self.fetch_html(domain)
        if not html:
          return set()

        soup = BeautifulSoup(html, "html.parser")
        domains = set()

        for tag, attr in [("script", "src"), ("link", "href"), ("img", "src")]:
            for item in soup.find_all(tag, **{attr: True}):
                full_url = urljoin(f"http://{domain}", item[attr])
                d = self._get_domain(full_url)
                if d and d != domain:
                    domains.add(d)

        return domains

    def _get_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc
        except Exception:
            return None