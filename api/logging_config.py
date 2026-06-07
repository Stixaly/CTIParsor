"""
Centralized logging configuration for CTIParsor.

This module provides a consistent logging setup across the entire application,
replacing print() statements with proper logging that includes:
- Log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Timestamps
- Module names
- Request IDs for tracing
- JSON formatting option for structured logging

Usage:
    from api.logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("Processing started")
    logger.error("Failed to process", exc_info=True)
"""

import json
import logging
import logging.handlers
import os
import sys
import threading
from datetime import datetime
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Environment variables
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "text")  # "text" or "json"
LOG_FILE = os.environ.get("LOG_FILE", "")  # Empty = no file logging
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", "10485760"))  # 10MB
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

# Thread-local storage for request IDs
_thread_local = threading.local()


# ---------------------------------------------------------------------------
# Request ID Management
# ---------------------------------------------------------------------------

def set_request_id(request_id: Optional[str] = None) -> str:
    """
    Set a request ID for the current thread.

    If request_id is None, generates a new UUID.
    Returns the request ID that was set.
    """
    if request_id is None:
        import uuid
        request_id = str(uuid.uuid4())[:8]
    _thread_local.request_id = request_id
    return request_id


def get_request_id() -> str:
    """Get the current request ID for this thread, or 'none' if not set."""
    return getattr(_thread_local, "request_id", "none")


def clear_request_id() -> None:
    """Clear the request ID for the current thread."""
    if hasattr(_thread_local, "request_id"):
        delattr(_thread_local, "request_id")


# ---------------------------------------------------------------------------
# Custom JSON Formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """Formatter that outputs log records as JSON."""

    def __init__(self, include_timestamp: bool = True, include_level: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_level = include_level

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a JSON string."""
        log_data: Dict[str, Any] = {
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
        }

        if self.include_timestamp:
            log_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

        if self.include_level:
            log_data["level"] = record.levelname
            log_data["level_num"] = record.levelno

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info),
            }

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "created", "filename", "funcName",
                "levelname", "levelno", "lineno", "module", "msecs",
                "pathname", "process", "processName", "relativeCreated",
                "stack_info", "exc_info", "exc_text", "thread", "threadName",
                "message", "request_id", "asctime"
            ):
                try:
                    # Only include JSON-serializable values
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


# ---------------------------------------------------------------------------
# Custom Text Formatter
# ---------------------------------------------------------------------------

class TextFormatter(logging.Formatter):
    """Custom text formatter with request ID."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with request ID."""
        request_id = get_request_id()
        timestamp = self.formatTime(record)
        level = record.levelname
        logger = record.name
        message = record.getMessage()

        # Build the base format
        base = f"[{timestamp}] [{level:8}] [{request_id}] {logger}: {message}"

        # Add exception info if present
        if record.exc_info:
            base += f"\n{self.formatException(record.exc_info)}"

        return base


# ---------------------------------------------------------------------------
# Logger Setup
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    """
    Configure the root logger with handlers.

    This should be called once at application startup.
    """
    # Convert log level string to logging constant
    level = getattr(logging, LOG_LEVEL, logging.INFO)

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatter based on configuration
    formatter: logging.Formatter
    if LOG_FORMAT == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if configured)
    if LOG_FILE:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_LOG_SIZE,
            backupCount=LOG_BACKUP_COUNT,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Set levels for noisy libraries
    logging.getLogger("pdfminer").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("transformers").setLevel(logging.ERROR)
    logging.getLogger("sentence_transformers").setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: The logger name (typically __name__)

    Returns:
        A configured logger instance
    """
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def log_function_call(logger: logging.Logger, func_name: str, **kwargs) -> None:
    """Log a function call with its arguments."""
    args_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.debug(f"Calling {func_name}({args_str})")


def log_error(logger: logging.Logger, message: str, exc_info: bool = True, **extra) -> None:
    """Log an error with optional exception info."""
    extra["request_id"] = get_request_id()
    if exc_info:
        logger.error(message, exc_info=True, extra=extra)
    else:
        logger.error(message, extra=extra)


def log_warning(logger: logging.Logger, message: str, **extra) -> None:
    """Log a warning with extra context."""
    extra["request_id"] = get_request_id()
    logger.warning(message, extra=extra)


# ---------------------------------------------------------------------------
# Initialize logging on module import
# ---------------------------------------------------------------------------

# Only setup logging once
_setup_done = False
if not _setup_done:
    setup_logging()
    _setup_done = True
