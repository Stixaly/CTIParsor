"""api/logging_config.py — request ids, the JSON and text formatters, and
setup_logging's handlers (the root logger is restored after each test)."""
from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys

import pytest

from api import logging_config as lc


@pytest.fixture(autouse=True)
def _fresh_request_id():
    lc.clear_request_id()
    yield
    lc.clear_request_id()


@pytest.fixture()
def root_logger():
    """Put the root logger back as it was: setup_logging() replaces its handlers."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield root
    for handler in root.handlers[:]:
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    for handler in handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(level)


def _record(msg: str = "hello %s", args=("world",), exc_info=None, **extra) -> logging.LogRecord:
    record = logging.LogRecord("cti.test", logging.WARNING, __file__, 1, msg, args, exc_info)
    record.__dict__.update(extra)
    return record


def _exc_info():
    try:
        raise ValueError("bad value")
    except ValueError:
        return sys.exc_info()


# ── Request ids ──────────────────────────────────────────────────────────────

def test_request_ids_are_set_generated_and_cleared():
    assert lc.get_request_id() == "none"
    assert lc.set_request_id("req-1") == "req-1" and lc.get_request_id() == "req-1"

    generated = lc.set_request_id()
    assert re.fullmatch(r"[0-9a-f]{8}", generated) and lc.get_request_id() == generated

    lc.clear_request_id()
    assert lc.get_request_id() == "none"


# ── JSON formatter ───────────────────────────────────────────────────────────

def test_json_lines_carry_message_level_timestamp_and_request_id():
    lc.set_request_id("abc123")
    line = json.loads(lc.JSONFormatter().format(_record()))

    assert line["message"] == "hello world" and line["logger"] == "cti.test"
    assert line["request_id"] == "abc123"
    assert (line["level"], line["level_num"]) == ("WARNING", logging.WARNING)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", line["timestamp"])


def test_json_timestamp_and_level_can_be_left_out():
    line = json.loads(lc.JSONFormatter(include_timestamp=False, include_level=False).format(_record()))
    assert "timestamp" not in line and "level" not in line and "level_num" not in line


def test_json_lines_carry_the_exception():
    line = json.loads(lc.JSONFormatter().format(_record(exc_info=_exc_info())))
    assert line["exception"]["type"] == "ValueError"
    assert line["exception"]["message"] == "bad value"
    assert "Traceback" in line["exception"]["traceback"]


def test_json_extra_fields_are_kept_and_unserialisable_ones_stringified():
    line = json.loads(lc.JSONFormatter().format(_record(job_id="j1", chunks=[1, 2], path=object())))
    assert line["job_id"] == "j1" and line["chunks"] == [1, 2]
    assert line["path"].startswith("<object object at")
    assert "msg" not in line and "args" not in line          # LogRecord internals stay out


# ── Text formatter ───────────────────────────────────────────────────────────

def test_text_lines_carry_the_request_id_and_the_traceback():
    lc.set_request_id("r9")
    text = lc.TextFormatter().format(_record(exc_info=_exc_info()))

    first, *rest = text.splitlines()
    assert re.fullmatch(r"\[.+\] \[WARNING \] \[r9\] cti\.test: hello world", first)
    assert rest[0].startswith("Traceback") and rest[-1] == "ValueError: bad value"


# ── setup_logging ────────────────────────────────────────────────────────────

def test_setup_replaces_the_handlers_with_one_console_handler(root_logger, monkeypatch):
    monkeypatch.setattr(lc, "LOG_LEVEL", "WARNING")
    monkeypatch.setattr(lc, "LOG_FORMAT", "text")
    monkeypatch.setattr(lc, "LOG_FILE", "")
    root_logger.addHandler(logging.NullHandler())

    lc.setup_logging()

    (handler,) = root_logger.handlers
    assert isinstance(handler, logging.StreamHandler) and handler.stream is sys.stdout
    assert isinstance(handler.formatter, lc.TextFormatter)
    assert root_logger.level == logging.WARNING
    assert logging.getLogger("transformers").level == logging.ERROR


def test_setup_can_log_json_to_a_rotating_file(root_logger, monkeypatch, tmp_path):
    log_file = tmp_path / "cti.log"
    monkeypatch.setattr(lc, "LOG_LEVEL", "NOT_A_LEVEL")        # falls back to INFO
    monkeypatch.setattr(lc, "LOG_FORMAT", "json")
    monkeypatch.setattr(lc, "LOG_FILE", str(log_file))

    lc.setup_logging()
    logging.getLogger("cti.file").info("written to disk")
    for handler in root_logger.handlers:
        handler.flush()

    assert root_logger.level == logging.INFO
    console, rotating = root_logger.handlers
    assert isinstance(rotating, logging.handlers.RotatingFileHandler)
    assert rotating.maxBytes == lc.MAX_LOG_SIZE and rotating.backupCount == lc.LOG_BACKUP_COUNT
    assert all(isinstance(h.formatter, lc.JSONFormatter) for h in (console, rotating))
    assert json.loads(log_file.read_text().splitlines()[-1])["message"] == "written to disk"


# ── Convenience helpers ──────────────────────────────────────────────────────

def test_the_helpers_log_with_the_request_id(caplog):
    logger = lc.get_logger("cti.helpers")
    lc.set_request_id("rid")

    with caplog.at_level(logging.DEBUG, logger="cti.helpers"):
        lc.log_function_call(logger, "enrich", job="j1", n=2)
        try:
            raise KeyError("k")
        except KeyError:
            lc.log_error(logger, "with traceback", job="j1")
        lc.log_error(logger, "without traceback", exc_info=False)
        lc.log_warning(logger, "careful", stage="3")

    debug, err_tb, err, warn = caplog.records
    assert debug.getMessage() == "Calling enrich(job=j1, n=2)"
    assert err_tb.exc_info is not None and err_tb.job == "j1" and err_tb.request_id == "rid"
    assert err.exc_info is None and err.levelno == logging.ERROR
    assert warn.levelno == logging.WARNING and warn.stage == "3" and warn.request_id == "rid"
