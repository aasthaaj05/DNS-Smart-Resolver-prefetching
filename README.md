# Smart DNS Resolver with Prefetching and Dependency Graph

A high-performance intelligent DNS proxy built in Python that enhances traditional DNS resolution using **TTL-aware caching**, **predictive prefetching**, **dependency graph analytics**, and **multi-layer DNS security analysis**.

The project is designed to reduce DNS latency, proactively warm caches, and detect DNS misconfigurations such as lame delegations and cyclic nameserver dependencies — all while maintaining asynchronous, non-blocking query handling.

---

## Features

### Intelligent DNS Resolution
- Local UDP DNS proxy
- Cache-first DNS resolution
- Support for A and AAAA record caching
- Upstream DNS failover support
- TTL-aware caching with expiration handling

### Predictive DNS Prefetching
- Variable-order Markov predictor (orders 1, 2, and 3)
- HTML dependency extraction using BeautifulSoup
- Background asynchronous cache warming
- Confidence-based domain prediction
- Persistent Markov learning model

### Dependency Graph Analytics
- Domain dependency graph generation
- DFS-based dependency depth analysis
- Cycle-safe traversal
- Real-time graph summaries
- Thread-safe graph operations

### Security & DNS Health Analysis
- Lame nameserver detection
- Cyclic NS dependency detection
- Malicious domain detection
- Homoglyph attack detection
- Token bucket rate limiting
- Risk scoring system for DNS configurations

### Performance Optimizations
- Asynchronous background processing
- Thread pool execution
- Non-blocking query handling
- Cache warm-up optimization
- Structured logging and metrics tracking

---

# System Architecture

```text
                ┌─────────────────────┐
                │     DNS Client      │
                └─────────┬───────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │      DNS Proxy      │
                │    (UDP Server)     │
                └─────────┬───────────┘
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
 ┌───────────────┐               ┌────────────────┐
 │   DNS Cache   │               │  DNS Resolver  │
 └───────────────┘               └────────────────┘
         │
         ▼
 ┌──────────────────────────────────────────┐
 │          Background Callbacks            │
 ├──────────────────────────────────────────┤
 │  Prefetch Engine                         │
 │  Dependency Graph                        │
 │  Security Analyzer                       │
 └──────────────────────────────────────────┘
