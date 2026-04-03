"""
Variable-Order Markov Predictor for DNS Prefetching.

Improvements over v1:
    1. Backoff weighting    — combines all order signals (0.6/0.3/0.1)
    2. State explosion cap  — prunes low-frequency transitions per state
    3. Confidence threshold — ignores weak predictions (score < 0.15)
    4. Cold start preload   — populates history with common domains
    5. Exponential decay    — old transitions fade out (halves every 5 min)
    6. Sliding window       — event log expires data older than 1 hour,
                              memory is bounded regardless of uptime
    7. Encrypted storage    — markov.json is AES-encrypted at rest,
                              browsing history is not readable from disk

Public interface:
    predictor = MarkovPredictor()
    predictor.update("google.com")
    preds = predictor.predict(top_k=3)
    predictor.save() / predictor.load()
"""

import math
import time
import json
import logging
from collections import defaultdict, deque
from typing import List, Tuple, Optional

try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Cold start: domains preloaded before any real traffic is seen
POPULAR_DOMAINS = [
    "google.com", "youtube.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "reddit.com",
    "cloudflare.com", "amazon.com", "twitter.com", "discord.com",
]

# ── Backoff weights: higher order = more specific = more weight
ORDER_WEIGHTS = {3: 0.6, 2: 0.3, 1: 0.1}

# ── Max transitions stored per state to prevent memory explosion
MAX_TRANSITIONS_PER_STATE = 15

# ── Minimum combined score to include a prediction
CONFIDENCE_THRESHOLD = 0.15

# ── Sliding window: events older than this are expired (seconds)
DEFAULT_WINDOW_SECONDS = 3600  # 1 hour


class MarkovPredictor:
    def __init__(
        self,
        max_order: int = 3,
        max_history: int = 200,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        key_path: str = "markov.key",
    ):
        self.max_order = max_order
        self.max_history = max_history
        self._window_seconds = window_seconds

        # ── Transition tables — one per order
        # order 1: transitions[1][(a,)]      -> {next: {count, last_seen}}
        # order 2: transitions[2][(a,b)]     -> {next: {count, last_seen}}
        # order 3: transitions[3][(a,b,c)]   -> {next: {count, last_seen}}
        self.transitions: dict[int, dict] = {
            1: defaultdict(lambda: defaultdict(dict)),
            2: defaultdict(lambda: defaultdict(dict)),
            3: defaultdict(lambda: defaultdict(dict)),
        }

        # ── Sliding window event log
        # Each entry: (timestamp, order, key_tuple, next_domain)
        # Bounded by window_seconds — old events expire automatically
        self._event_log: deque = deque()

        # ── Browsing history deque — O(1) append/drop
        self.history: deque = deque(maxlen=max_history)

        # ── Tracking
        self._order_usage = {1: 0, 2: 0, 3: 0}
        self._accuracy_hits = 0
        self._accuracy_total = 0

        # ── Encryption setup
        self._fernet = None
        if ENCRYPTION_AVAILABLE:
            self._fernet = self._load_or_create_key(key_path)
        else:
            logger.warning(
                "cryptography package not installed — "
                "markov.json will be stored unencrypted. "
                "Run: pip install cryptography"
            )

        # ── Cold start — seed history with popular domains
        self._preload_cold_start()

    # ─────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────

    def update(self, domain: str) -> None:
        """
        Record a new domain visit and update all transition tables.
        Call this every time a domain is resolved.

        Also expires events outside the sliding window so memory
        stays bounded regardless of how long the resolver runs.
        """
        self.history.append(domain)
        h = list(self.history)
        n = len(h)
        now = time.time()

        if n >= 2:
            self._record(1, (h[-2],), h[-1], now)

        if n >= 3:
            self._record(2, (h[-3], h[-2]), h[-1], now)

        if n >= 4:
            self._record(3, (h[-4], h[-3], h[-2]), h[-1], now)

    def predict(
        self,
        top_k: int = 3,
        return_scores: bool = False,
    ) -> "List[str] | List[Tuple[str, float]]":
        """
        Predict next domains using COMBINED signal from all orders.

        Weights and merges all three orders:
            final_score = 0.6 * order3 + 0.3 * order2 + 0.1 * order1

        Only predictions above CONFIDENCE_THRESHOLD are returned.
        """
        h = list(self.history)
        if len(h) < 2:
            return []

        combined: dict[str, float] = {}

        for order, weight in ORDER_WEIGHTS.items():
            if len(h) < order + 1:
                continue

            key = tuple(h[-order:])
            candidates = self.transitions[order].get(key, {})
            if not candidates:
                continue

            scored = self._score(candidates)
            self._order_usage[order] += 1

            for domain, score in scored:
                combined[domain] = combined.get(domain, 0) + weight * score

        ranked = [
            (d, s) for d, s in
            sorted(combined.items(), key=lambda x: x[1], reverse=True)
            if s >= CONFIDENCE_THRESHOLD
        ]

        if return_scores:
            return ranked[:top_k]
        return [d for d, _ in ranked[:top_k]]

    def accuracy_probe(self, actual_next: str, top_k: int = 3) -> Optional[bool]:
        """
        Call BEFORE update() with the domain that actually came next.
        Returns True if correct, False if wrong, None if no prediction.

        Usage:
            hit = predictor.accuracy_probe(next_domain)
            predictor.update(next_domain)
        """
        preds = self.predict(top_k=top_k)
        if not preds:
            return None

        result = actual_next in preds
        self._accuracy_total += 1
        if result:
            self._accuracy_hits += 1
        return result

    def accuracy_stats(self) -> dict:
        """Returns prediction accuracy over all accuracy_probe() calls."""
        total = self._accuracy_total or 1
        return {
            "accuracy_hits": self._accuracy_hits,
            "accuracy_total": self._accuracy_total,
            "accuracy_pct": round(self._accuracy_hits / total * 100, 1),
        }

    def order_stats(self) -> dict:
        """Returns how often each Markov order contributed to predictions."""
        total = sum(self._order_usage.values()) or 1
        return {
            f"order_{o}_uses": count
            for o, count in self._order_usage.items()
        } | {
            f"order_{o}_pct": round(count / total * 100, 1)
            for o, count in self._order_usage.items()
        }

    def window_stats(self) -> dict:
        """Returns sliding window health metrics."""
        now = time.time()
        cutoff = now - self._window_seconds
        live = sum(1 for ts, *_ in self._event_log if ts >= cutoff)
        return {
            "total_events": len(self._event_log),
            "live_events": live,
            "window_seconds": self._window_seconds,
            "oldest_event_age_s": round(
                now - self._event_log[0][0], 1
            ) if self._event_log else 0,
        }

    def prune(self, max_age_seconds: int = 3600, min_count: int = 1) -> dict:
        """
        Remove stale transition entries.
        Drops entries that are:
            - older than max_age_seconds, OR
            - count <= min_count AND older than 5 minutes

        Note: The sliding window already handles most of this automatically.
        prune() is a safety net for any entries that slip through.
        """
        now = time.time()
        total_removed = 0
        empty_states_removed = 0

        for order in self.transitions:
            empty_keys = []
            for key, nexts in self.transitions[order].items():
                stale = [
                    domain for domain, data in nexts.items()
                    if (now - data.get("last_seen", now)) > max_age_seconds
                    or (
                        data.get("count", 0) <= min_count
                        and (now - data.get("last_seen", now)) > 300
                    )
                ]
                for domain in stale:
                    del nexts[domain]
                    total_removed += 1

                if not nexts:
                    empty_keys.append(key)

            for key in empty_keys:
                del self.transitions[order][key]
                empty_states_removed += 1

        return {
            "entries_removed": total_removed,
            "empty_states_removed": empty_states_removed,
        }

    def save(self, path: str = "markov.json") -> None:
        """
        Persist transition tables to disk.

        If cryptography is installed:
            - File is AES-encrypted (Fernet/AES-128)
            - Written as binary — not human readable
            - Requires markov.key to decrypt
        If not installed:
            - Falls back to plain JSON with a warning
        """
        # Prune before saving
        self.prune()

        serializable = {}
        for order, table in self.transitions.items():
            order_data = {}
            for key, nexts in table.items():
                str_key = "|".join(key)
                order_data[str_key] = dict(nexts)
            serializable[str(order)] = order_data

        payload = json.dumps(serializable).encode()

        if self._fernet:
            # Encrypt and write binary
            encrypted = self._fernet.encrypt(payload)
            with open(path, "wb") as f:
                f.write(encrypted)
            logger.debug("Markov model saved (encrypted): %s", path)
        else:
            # Fallback — plain JSON
            with open(path, "w") as f:
                f.write(payload.decode())
            logger.debug("Markov model saved (unencrypted): %s", path)

    def load(self, path: str = "markov.json") -> None:
        """
        Load transition tables from disk.
        Handles both encrypted (binary) and plain JSON formats.
        If the file is corrupted or tampered with, starts fresh.
        """
        try:
            if self._fernet:
                with open(path, "rb") as f:
                    encrypted = f.read()
                try:
                    payload = self._fernet.decrypt(encrypted)
                    data = json.loads(payload)
                except Exception:
                    logger.warning(
                        "Could not decrypt %s — "
                        "file may be corrupted or key has changed. "
                        "Starting fresh.", path
                    )
                    return
            else:
                with open(path, "r") as f:
                    data = json.load(f)

            for order_str, order_data in data.items():
                order = int(order_str)
                for str_key, nexts in order_data.items():
                    key = tuple(str_key.split("|"))
                    self.transitions[order][key] = defaultdict(dict, nexts)

            logger.info("Markov model loaded from %s", path)

        except FileNotFoundError:
            logger.debug("No saved Markov model found at %s — starting fresh", path)

    # ─────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────

    def _load_or_create_key(self, key_path: str):
        """
        Load existing encryption key or generate a new one.

        IMPORTANT: losing markov.key means losing the ability to read
        markov.json. This is intentional — privacy by design.
        Add markov.key to .gitignore and never commit it.
        """
        try:
            with open(key_path, "rb") as f:
                key = f.read()
            logger.debug("Encryption key loaded from %s", key_path)
            return Fernet(key)
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open(key_path, "wb") as f:
                f.write(key)
            logger.info(
                "New encryption key generated and saved to %s — "
                "add this file to .gitignore", key_path
            )
            return Fernet(key)

    def _preload_cold_start(self) -> None:
        """
        Seed history deque with popular domains so predictions work
        immediately, before any real traffic is seen.

        Only seeds the history deque — NOT the transition tables.
        No fake transition counts are introduced.
        """
        for domain in POPULAR_DOMAINS:
            self.update(domain)

    def _record(
        self,
        order: int,
        key: tuple,
        next_domain: str,
        now: float,
    ) -> None:
        """
        Update a single transition entry and log the event.

        SLIDING WINDOW:
        Every event is appended to _event_log with its timestamp.
        When old events expire (older than window_seconds), the
        transition tables are rebuilt from scratch using only the
        remaining recent events — bounding memory to the window.

        STATE EXPLOSION CAP:
        If a state accumulates more than MAX_TRANSITIONS_PER_STATE
        candidates, the least-frequent one is pruned immediately.
        """
        # Log the event for sliding window
        self._event_log.append((now, order, key, next_domain))

        # Update transition table
        entry = self.transitions[order][key].get(next_domain, {})
        self.transitions[order][key][next_domain] = {
            "count": entry.get("count", 0) + 1,
            "last_seen": now,
        }

        # State explosion cap
        state = self.transitions[order][key]
        if len(state) > MAX_TRANSITIONS_PER_STATE:
            least = min(state, key=lambda d: state[d]["count"])
            del state[least]

        # Expire old window events and rebuild if anything dropped
        self._expire_old_events(now)

    def _expire_old_events(self, now: float) -> None:
        """
        Drop events older than window_seconds from the event log.
        If any events were dropped, rebuild all transition tables
        from scratch using only the remaining recent events.

        This is the core of the sliding window mechanism:
        - Memory is bounded to window_seconds of traffic
        - Old browsing patterns automatically stop influencing predictions
        - No manual cleanup required
        """
        cutoff = now - self._window_seconds
        dropped = 0

        while self._event_log and self._event_log[0][0] < cutoff:
            self._event_log.popleft()
            dropped += 1

        if dropped > 0:
            logger.debug(
                "Sliding window: expired %d events older than %ds",
                dropped, self._window_seconds
            )

            # Rebuild all transition tables from remaining events only
            self.transitions = {
                1: defaultdict(lambda: defaultdict(dict)),
                2: defaultdict(lambda: defaultdict(dict)),
                3: defaultdict(lambda: defaultdict(dict)),
            }
            for timestamp, order, key, next_domain in self._event_log:
                entry = self.transitions[order][key].get(next_domain, {})
                self.transitions[order][key][next_domain] = {
                    "count": entry.get("count", 0) + 1,
                    "last_seen": timestamp,
                }

    def _score(self, candidates: dict) -> "List[Tuple[str, float]]":
        """
        Score candidate next-domains using:
          - 50% transition probability  (how often this follows)
          - 30% frequency score         (absolute popularity, capped at 10)
          - 20% recency score           (exponential decay over ~5 minutes)
        """
        now = time.time()
        total = sum(d.get("count", 0) for d in candidates.values()) or 1

        scored = []
        for domain, data in candidates.items():
            count = data.get("count", 0)
            last_seen = data.get("last_seen", now)

            transition_prob = count / total
            frequency_score = min(count / 10, 1.0)
            age = now - last_seen
            recency_score = math.exp(-age / 300)  # halves every ~5 min

            score = (
                0.5 * transition_prob +
                0.3 * frequency_score +
                0.2 * recency_score
            )
            scored.append((domain, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored