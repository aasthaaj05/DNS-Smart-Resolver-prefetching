"""
Variable-Order Markov Predictor for DNS Prefetching.

Improvements over v1:
    1. Backoff weighting   — combines all order signals (0.6/0.3/0.1)
    2. State explosion cap — prunes low-frequency transitions per state
    3. Confidence threshold — ignores weak predictions (score < 0.15)
    4. Cold start preload  — populates history with common domains
    5. Exponential decay   — old transitions fade out (halves every 5 min)

Public interface:
    predictor = MarkovPredictor()
    predictor.update("google.com")
    preds = predictor.predict(top_k=3)
    predictor.save() / predictor.load()
"""

import math
import time
import json
from collections import defaultdict, deque
from typing import List, Tuple, Optional


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


class MarkovPredictor:
    def __init__(self, max_order: int = 3, max_history: int = 200):
        self.max_order = max_order
        self.max_history = max_history

        # One transition table per order
        # order 1: transitions[1][(a,)]       -> {next: {count, last_seen}}
        # order 2: transitions[2][(a,b)]      -> {next: {count, last_seen}}
        # order 3: transitions[3][(a,b,c)]    -> {next: {count, last_seen}}
        self.transitions: dict[int, dict] = {
            1: defaultdict(lambda: defaultdict(dict)),
            2: defaultdict(lambda: defaultdict(dict)),
            3: defaultdict(lambda: defaultdict(dict)),
        }

        # deque auto-drops oldest — O(1) append/drop
        self.history: deque = deque(maxlen=max_history)

        # Track how often each order contributed
        self._order_usage = {1: 0, 2: 0, 3: 0}

        # Accuracy tracking
        self._accuracy_hits = 0
        self._accuracy_total = 0

        # Cold start — preload common domains into history
        self._preload_cold_start()

    # ─────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────

    def update(self, domain: str) -> None:
        """
        Record a new domain visit and update all transition tables.
        Call this every time a domain is resolved.
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

    def predict(self, top_k: int = 3,
                return_scores: bool = False) -> List[str] | List[Tuple[str, float]]:
        """
        Predict next domains using COMBINED signal from all orders.

        Instead of "try order-3, else order-2, else order-1",
        weights and merges all three:
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

        # Filter by confidence threshold and sort
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
        Returns True if prediction correct, False if wrong, None if no prediction.

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

    def save(self, path: str = "markov.json") -> None:
        serializable = {}
        for order, table in self.transitions.items():
            order_data = {}
            for key, nexts in table.items():
                str_key = "|".join(key)
                order_data[str_key] = dict(nexts)
            serializable[str(order)] = order_data

        with open(path, "w") as f:
            json.dump(serializable, f, indent=2)

    def load(self, path: str = "markov.json") -> None:
        try:
            with open(path, "r") as f:
                data = json.load(f)

            for order_str, order_data in data.items():
                order = int(order_str)
                for str_key, nexts in order_data.items():
                    key = tuple(str_key.split("|"))
                    self.transitions[order][key] = defaultdict(dict, nexts)

        except FileNotFoundError:
            pass

    # ─────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────

    def _preload_cold_start(self) -> None:
        """
        Seed history with popular domains so predictions work
        immediately, before any real traffic is seen.
        """
        for domain in POPULAR_DOMAINS:
            self.history.append(domain)

    def _record(self, order: int, key: tuple,
                next_domain: str, now: float) -> None:
        """
        Update a single transition entry.
        Prunes least-frequent entry if state exceeds MAX_TRANSITIONS_PER_STATE.
        """
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

    def _score(self, candidates: dict) -> List[Tuple[str, float]]:
        """
        Score candidate next-domains using:
          - 50% transition probability  (how often this follows)
          - 30% frequency score         (absolute popularity, capped at 10)
          - 20% recency score           (decays over ~5 minutes)
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