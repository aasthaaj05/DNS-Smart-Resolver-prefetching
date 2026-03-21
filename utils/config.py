"""
utils/config.py
Loads config.yaml once at startup and exposes a clean Config object.
All other modules import from here — never read the YAML directly.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.yaml")


@dataclass
class DnsConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 53
    upstream_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    upstream_port: int = 53
    query_timeout: int = 5


@dataclass
class CacheConfig:
    default_ttl: int = 300
    max_ttl: int = 86400
    min_ttl: int = 30
    max_entries: int = 5000


@dataclass
class PrefetchConfig:
    enabled: bool = True
    max_depth: int = 3
    max_domains: int = 50


@dataclass
class SecurityConfig:
    enabled: bool = True
    check_ns_responsiveness: bool = True
    same_ip_ns_threshold: int = 2


@dataclass
class LoggingConfig:
    level: str = "INFO"
    log_to_file: bool = False
    log_file: str = "dns_resolver.log"


@dataclass
class Config:
    dns: DnsConfig = field(default_factory=DnsConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    prefetch: PrefetchConfig = field(default_factory=PrefetchConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _load_yaml(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def load_config(path: str = CONFIG_PATH) -> Config:
    """
    Parse config.yaml and return a fully-populated Config object.
    Missing keys fall back to dataclass defaults.
    """
    raw = _load_yaml(path)

    dns_raw = raw.get("dns", {})
    cache_raw = raw.get("cache", {})
    prefetch_raw = raw.get("prefetch", {})
    security_raw = raw.get("security", {})
    logging_raw = raw.get("logging", {})

    return Config(
        dns=DnsConfig(
            listen_host=dns_raw.get("listen_host", "127.0.0.1"),
            listen_port=dns_raw.get("listen_port", 53),
            upstream_servers=dns_raw.get("upstream_servers", ["8.8.8.8"]),
            upstream_port=dns_raw.get("upstream_port", 53),
            query_timeout=dns_raw.get("query_timeout", 5),
        ),
        cache=CacheConfig(
            default_ttl=cache_raw.get("default_ttl", 300),
            max_ttl=cache_raw.get("max_ttl", 86400),
            min_ttl=cache_raw.get("min_ttl", 30),
            max_entries=cache_raw.get("max_entries", 5000),
        ),
        prefetch=PrefetchConfig(
            enabled=prefetch_raw.get("enabled", True),
            max_depth=prefetch_raw.get("max_depth", 3),
            max_domains=prefetch_raw.get("max_domains", 50),
        ),
        security=SecurityConfig(
            enabled=security_raw.get("enabled", True),
            check_ns_responsiveness=security_raw.get("check_ns_responsiveness", True),
            same_ip_ns_threshold=security_raw.get("same_ip_ns_threshold", 2),
        ),
        logging=LoggingConfig(
            level=logging_raw.get("level", "INFO"),
            log_to_file=logging_raw.get("log_to_file", False),
            log_file=logging_raw.get("log_file", "dns_resolver.log"),
        ),
    )


# Module-level singleton — import this everywhere
config = load_config()