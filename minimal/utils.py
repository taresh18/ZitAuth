import logging
import os
from typing import Optional

_LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "app.log")
_FILE_HANDLER: Optional[logging.Handler] = None


def _ensure_file_handler() -> logging.Handler:
    global _FILE_HANDLER
    if _FILE_HANDLER is None:
        handler = logging.FileHandler(_LOG_FILE_PATH, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s:%(funcName)s] %(message)s")
        )
        _FILE_HANDLER = handler
    return _FILE_HANDLER


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = _ensure_file_handler()
    if handler not in logger.handlers:
        logger.addHandler(handler)
    logger.propagate = False
    return logger