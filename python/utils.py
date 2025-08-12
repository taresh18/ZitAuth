import logging
import os
import secrets
import hashlib
import base64
from typing import Optional

_PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
_LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)
_LOG_FILE_PATH = os.path.join(_LOG_DIR, "app.log")
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


def generate_state() -> str:
    """Generate a random state"""
    return secrets.token_urlsafe(32)


def generate_code_verifier() -> str:
    """Generate a random code verifier"""
    return secrets.token_urlsafe(64)


def generate_code_challenge(code_verifier: str) -> str:
    """calculates the hash of the code verifier and returns the base64 encoded string"""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")