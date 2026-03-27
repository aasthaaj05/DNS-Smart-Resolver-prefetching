import time
import json
from collections import defaultdict


class MarkovPredictor:
    def __init__(self):
        # (prev, current) -> {next: {count, last_seen}}
        self.transitions = defaultdict(lambda: defaultdict(dict))
        self.history = []

    # ─────────────────────────────
    # Learn sequence
    # ─────────────────────────────
    def update(self, domain: str):
        self.history.append(domain)

        if len(self.history) >= 3:
            prev = self.history[-3]
            current = self.history[-2]
            next_domain = self.history[-1]

            entry = self.transitions[(prev, current)].get(next_domain, {})

            self.transitions[(prev, current)][next_domain] = {
                "count": entry.get("count", 0) + 1,
                "last_seen": time.time()
            }

    # ─────────────────────────────
    # Predict next domains
    # ─────────────────────────────
    def predict(self, prev: str, current: str, top_k=3):
        next_domains = self.transitions.get((prev, current), {})
        now = time.time()

        scored = []

        # Total transitions for probability
        total_transitions = sum(
            data.get("count", 0) for data in next_domains.values()
        ) or 1

        for domain, data in next_domains.items():
            count = data.get("count", 0)
            last_seen = data.get("last_seen", now)

            # 1️⃣ Transition probability (Markov)
            transition_prob = count / total_transitions

            # 2️⃣ Frequency score (normalized)
            frequency_score = min(count / 10, 1.0)  # cap at 1

            # 3️⃣ Recency score (time decay)
            age = now - last_seen
            recency_score = 1 / (1 + age / 300)  # 5 min decay

            # 🎯 Final weighted score
            score = (
                0.5 * transition_prob +
                0.3 * frequency_score +
                0.2 * recency_score
            )

            scored.append((domain, score))

        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)

        return [d for d, _ in scored[:top_k]]

    # ─────────────────────────────
    # Persistence
    # ─────────────────────────────
    def save(self, path="markov.json"):
        serializable = {}

        for (prev, curr), nexts in self.transitions.items():
            key = f"{prev}|{curr}"
            serializable[key] = nexts

        with open(path, "w") as f:
            json.dump(serializable, f)

    def load(self, path="markov.json"):
        try:
            with open(path, "r") as f:
                data = json.load(f)

            for key, nexts in data.items():
                prev, curr = key.split("|")
                self.transitions[(prev, curr)] = defaultdict(dict, nexts)

        except FileNotFoundError:
            pass