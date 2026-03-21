"""
utils/logger.py
Centralised logging setup. All modules call get_logger(__name__).
Respects the level set in config.yaml.
"""

import logging
import sys
from utils.config import config


_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_DATE_FORMAT = "%H:%M:%S"

_configured = False


def _configure_root():
    global _configured
    if _configured:
        return

    level = _LOG_LEVELS.get(config.logging.level.upper(), logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]

    if config.logging.log_to_file:
        handlers.append(logging.FileHandler(config.logging.log_file))

    logging.basicConfig(
        level=level,
        format=_FORMAT,
        datefmt=_DATE_FORMAT,
        handlers=handlers,
    )
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Usage (in any module):
        from utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Resolved %s -> %s", domain, ip)
    """
    _configure_root()
    return logging.getLogger(name)