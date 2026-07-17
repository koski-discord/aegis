import logging
import re
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|authorization|cookie|key|ciphertext|nonce|recovery)",
    re.IGNORECASE,
)
REDACTED = "[redacted]"


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in data.items():
        if SENSITIVE_KEY_RE.search(str(key)):
            safe[str(key)] = REDACTED
        elif isinstance(value, Mapping):
            safe[str(key)] = redact_mapping(value)
        else:
            safe[str(key)] = value
    return safe


def _redact_processor(
    _: logging.Logger,
    __: str,
    event_dict: MutableMapping[str, Any],
) -> dict[str, Any]:
    return redact_mapping(event_dict)


def configure_logging(service: str, environment: str) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _redact_processor,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    structlog.contextvars.bind_contextvars(service=service, environment=environment)
