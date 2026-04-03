"""
Malicious Domain Detector

Three-layer detection:
    1. Blocklist    — known malicious domains (Steven Black's hosts list)
    2. Homoglyph    — typosquatting detection (paypa1.com, g00gle.com)
    3. Heuristics   — entropy, length, subdomain depth (DNS tunneling signals)

Public interface:
    detector = MaliciousDomainDetector()
    result = detector.check("paypa1.com")
    if result.is_malicious:
        logger.warning(result.reason)
"""

import re
import math
import time
import threading
import urllib.request
from dataclasses import dataclass
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Blocklist source (Steven Black — maintained daily, free)
BLOCKLIST_URL = (
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
)
BLOCKLIST_REFRESH_HOURS = 24  # re-download every 24 hours

# ── Popular legitimate domains to protect against homoglyph attacks
# These are the domains attackers most commonly spoof
PROTECTED_DOMAINS = {
    "google", "youtube", "facebook", "twitter", "instagram",
    "paypal", "apple", "microsoft", "amazon", "netflix",
    "linkedin", "github", "stackoverflow", "wikipedia",
    "whatsapp", "telegram", "zoom", "dropbox", "gmail",
    "outlook", "yahoo", "bing", "reddit", "twitch",
}

# ── Homoglyph map — characters attackers substitute for legitimate ones
# Key = lookalike character, Value = real character it imitates
HOMOGLYPH_MAP = {
    "0": "o", "1": "i", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "rn": "m", "vv": "w", "cl": "d", "nn": "m",
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u",
    "ý": "y", "ÿ": "y",
    "ñ": "n", "ç": "c", "ß": "ss",
}

# ── Heuristic thresholds
MAX_SAFE_ENTROPY       = 3.2   # bits — above this = random-looking
MAX_SAFE_SUBDOMAIN_LEN = 25    # chars — above this = likely tunneling
MAX_SAFE_LABEL_COUNT   = 5     # dot-separated parts
MIN_SUSPICIOUS_LEN     = 35    # total domain length
MAX_DIGIT_RATIO        = 0.40  # >40% digits = suspicious


@dataclass
class DetectionResult:
    domain: str
    is_malicious: bool
    reason: str
    detection_type: str   # "blocklist" | "homoglyph" | "heuristic" | "clean"
    confidence: str       # "High" | "Medium" | "Low"


class MaliciousDomainDetector:
    """
    Three-layer malicious domain detector.
    Thread-safe — blocklist is protected by a lock during refresh.
    """

    def __init__(self):
        self._blocklist: set = set()
        self._blocklist_lock = threading.Lock()
        self._last_refresh: float = 0.0

        # Load blocklist on startup in background — don't block resolver start
        t = threading.Thread(target=self._refresh_blocklist, daemon=True)
        t.start()

    # ─────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────

    def check(self, domain: str) -> DetectionResult:
        """
        Run all three detection layers on the domain.
        Returns on first positive detection — fastest check first.
        """
        domain = domain.lower().rstrip(".")

        # Auto-refresh blocklist every 24 hours
        if time.time() - self._last_refresh > BLOCKLIST_REFRESH_HOURS * 3600:
            t = threading.Thread(target=self._refresh_blocklist, daemon=True)
            t.start()

        # Layer 1 — blocklist (fastest, O(1) set lookup)
        result = self._check_blocklist(domain)
        if result.is_malicious:
            return result

        # Layer 2 — homoglyph (typosquatting)
        result = self._check_homoglyph(domain)
        if result.is_malicious:
            return result

        # Layer 3 — heuristics (entropy, length, structure)
        result = self._check_heuristics(domain)
        if result.is_malicious:
            return result

        return DetectionResult(
            domain=domain,
            is_malicious=False,
            reason="No issues detected",
            detection_type="clean",
            confidence="High",
        )

    def blocklist_size(self) -> int:
        with self._blocklist_lock:
            return len(self._blocklist)

    # ─────────────────────────────────────────────────────────────
    # Layer 1 — Blocklist
    # ─────────────────────────────────────────────────────────────

    def _check_blocklist(self, domain: str) -> DetectionResult:
        """
        Check domain and all parent domains against blocklist.
        e.g. evil.sub.malware.com → also checks sub.malware.com, malware.com
        """
        with self._blocklist_lock:
            # Check exact match and all parent domains
            parts = domain.split(".")
            for i in range(len(parts) - 1):
                candidate = ".".join(parts[i:])
                if candidate in self._blocklist:
                    return DetectionResult(
                        domain=domain,
                        is_malicious=True,
                        reason=f"Domain {candidate} is on malicious blocklist",
                        detection_type="blocklist",
                        confidence="High",
                    )

        return DetectionResult(
            domain=domain, is_malicious=False,
            reason="", detection_type="blocklist", confidence="High"
        )

    def _refresh_blocklist(self) -> None:
        """
        Download and parse Steven Black's hosts blocklist.
        Format: "0.0.0.0 malicious-domain.com"
        Runs in a daemon thread — never blocks the resolver.
        """
        logger.info("Refreshing malicious domain blocklist...")
        new_blocklist = set()

        try:
            req = urllib.request.Request(
                BLOCKLIST_URL,
                headers={"User-Agent": "DNS-Smart-Resolver/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("0.0.0.0"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] != "0.0.0.0":
                            new_blocklist.add(parts[1].lower())

            with self._blocklist_lock:
                self._blocklist = new_blocklist
                self._last_refresh = time.time()

            logger.info(
                "Blocklist refreshed: %d malicious domains loaded",
                len(new_blocklist)
            )

        except Exception as e:
            logger.warning("Blocklist refresh failed: %s — using existing list", e)

    # ─────────────────────────────────────────────────────────────
    # Layer 2 — Homoglyph Detection
    # ─────────────────────────────────────────────────────────────

    def _check_homoglyph(self, domain: str) -> DetectionResult:
        """
        Detect typosquatting by normalising the domain through the
        homoglyph map and checking if the result matches a protected domain.

        Examples caught:
            paypa1.com    → paypal.com  (1 → l)
            g00gle.com    → google.com  (00 → oo)
            arnazon.com   → amazon.com  (rn → m)
            microsofт.com → microsoft   (Cyrillic т → t)
        """
        # Extract the registrable domain (second-level domain)
        parts = domain.split(".")
        if len(parts) < 2:
            return DetectionResult(
                domain=domain, is_malicious=False,
                reason="", detection_type="homoglyph", confidence="Low"
            )

        sld = parts[-2]  # second-level domain e.g. "paypa1" from "paypa1.com"

        # Normalise through homoglyph map
        normalised = sld
        for fake, real in HOMOGLYPH_MAP.items():
            normalised = normalised.replace(fake, real)

        # If normalised form matches a protected domain but original doesn't
        if normalised in PROTECTED_DOMAINS and sld not in PROTECTED_DOMAINS:
            return DetectionResult(
                domain=domain,
                is_malicious=True,
                reason=(
                    f"Homoglyph attack detected: '{sld}' resembles "
                    f"'{normalised}' after character substitution"
                ),
                detection_type="homoglyph",
                confidence="High",
            )

        # Check edit distance for near-misses (1 char off)
        for protected in PROTECTED_DOMAINS:
            if (
                sld != protected
                and len(sld) >= len(protected) - 1
                and self._levenshtein(sld, protected) == 1
            ):
                return DetectionResult(
                    domain=domain,
                    is_malicious=True,
                    reason=(
                        f"Typosquatting detected: '{sld}' is 1 character "
                        f"away from '{protected}'"
                    ),
                    detection_type="homoglyph",
                    confidence="Medium",
                )

        return DetectionResult(
            domain=domain, is_malicious=False,
            reason="", detection_type="homoglyph", confidence="High"
        )

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        """Compute edit distance between two strings."""
        if len(a) < len(b):
            return MaliciousDomainDetector._levenshtein(b, a)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(
                    prev[j + 1] + 1,   # deletion
                    curr[j] + 1,       # insertion
                    prev[j] + (ca != cb)  # substitution
                ))
            prev = curr
        return prev[-1]

    # ─────────────────────────────────────────────────────────────
    # Layer 3 — Heuristic Detection (DNS Tunneling + Random Domains)
    # ─────────────────────────────────────────────────────────────

    def _check_heuristics(self, domain: str) -> DetectionResult:
        """
        Detect suspicious domain patterns using four heuristics:

        1. Shannon entropy  — random-looking subdomains used in DNS tunneling
                              encode data as high-entropy strings
        2. Subdomain length — tunneling tools pack data into long subdomains
                              e.g. aGVsbG8gd29ybGQ.attacker.com
        3. Label count      — legitimate domains rarely exceed 4-5 levels
        4. Digit ratio      — DGA (domain generation algorithm) domains often
                              contain many digits: a1b2c3d4e5f6.com
        """
        parts = domain.split(".")
        subdomain_parts = parts[:-2] if len(parts) > 2 else []

        reasons = []
        score = 0

        # Heuristic 1: Shannon entropy of the longest subdomain label
        if subdomain_parts:
            longest_sub = max(subdomain_parts, key=len)
            entropy = self._shannon_entropy(longest_sub)

            # Entropy threshold depends on label length —
            # longer labels can achieve higher entropy legitimately
            threshold = MAX_SAFE_ENTROPY if len(longest_sub) >= 20 else 2.8

            if entropy > threshold and len(longest_sub) >= 8:
                score += 2
                reasons.append(
                    f"High entropy subdomain '{longest_sub[:20]}' "
                    f"(entropy={entropy:.2f}) — possible DNS tunneling"
                )

            # Heuristic 2: subdomain label length
            if len(longest_sub) > MAX_SAFE_SUBDOMAIN_LEN:
                score += 2
                reasons.append(
                    f"Unusually long subdomain label ({len(longest_sub)} chars) "
                    f"— possible DNS data exfiltration"
                )

        # Heuristic 3: excessive label count (deep nesting)
        if len(parts) > MAX_SAFE_LABEL_COUNT:
            score += 1
            reasons.append(
                f"Excessive subdomain depth ({len(parts)} levels) "
                f"— tunneling tools often use many levels"
            )

        # Heuristic 4: digit ratio in second-level domain (DGA detection)
        if len(parts) >= 2:
            sld = parts[-2]
            if len(sld) > 0:
                digit_ratio = sum(c.isdigit() for c in sld) / len(sld)
                if digit_ratio > MAX_DIGIT_RATIO and len(sld) > 8:
                    score += 1
                    reasons.append(
                        f"High digit ratio in domain name "
                        f"({digit_ratio:.0%} digits) — possible DGA domain"
                    )

        # Heuristic 5: total domain length
        if len(domain) > MIN_SUSPICIOUS_LEN and not subdomain_parts:
            score += 1
            reasons.append(
                f"Unusually long domain name ({len(domain)} chars)"
            )

        if score >= 3:
            confidence = "High"
        elif score >= 2:
            confidence = "Medium"
        elif score >= 1:
            confidence = "Low"
        else:
            return DetectionResult(
                domain=domain, is_malicious=False,
                reason="", detection_type="heuristic", confidence="High"
            )

        return DetectionResult(
            domain=domain,
            is_malicious=True,
            reason="; ".join(reasons) if len(reasons) > 1 else reasons[0] if reasons else "",
            detection_type="heuristic",
            confidence=confidence,
        )

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """
        Calculate Shannon entropy of a string.
        High entropy (> 3.8 bits) indicates random or encoded content.
        Normal English words have entropy around 2.5-3.5 bits.
        Base64-encoded data has entropy around 4.5-5.5 bits.
        """
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )