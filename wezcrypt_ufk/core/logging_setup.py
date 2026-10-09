"""Logging configuration: application log plus a per-session log file."""

from __future__ import annotations

import logging
import logging.handlers
import os
import time

LOGGER_NAME = "wezcrypt"
_FORMAT = "%(asctime)sZ %(levelname)-8s [%(threadName)s] %(name)s: %(message)s"


class _UTCFormatter(logging.Formatter):
    converter = time.gmtime


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)


def setup_app_logging(log_dir: str, verbose: bool = False, debug: bool = False, console: bool = True) -> str:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    for handler in list(logger.handlers):
        if getattr(handler, "_wezcrypt_app", False):
            logger.removeHandler(handler)
            handler.close()
    path = os.path.join(log_dir, "wezcrypt_app.log")
    file_handler = logging.handlers.RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(_UTCFormatter(_FORMAT))
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    file_handler._wezcrypt_app = True
    logger.addHandler(file_handler)
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(_UTCFormatter("%(levelname)s: %(message)s"))
        stream.setLevel(logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING))
        stream._wezcrypt_app = True
        logger.addHandler(stream)
    return path


def attach_session_log(path: str) -> logging.Handler:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(_UTCFormatter(_FORMAT))
    handler.setLevel(logging.DEBUG)
    logging.getLogger(LOGGER_NAME).addHandler(handler)
    logging.getLogger(LOGGER_NAME).setLevel(logging.DEBUG)
    return handler


def detach_handler(handler: logging.Handler) -> None:
    logging.getLogger(LOGGER_NAME).removeHandler(handler)
    handler.close()
