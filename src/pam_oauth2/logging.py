"""Syslog wrapper for PAM OAuth2 authentication logging."""

from __future__ import annotations

import syslog

_opened = False


def _ensure_open() -> None:
    global _opened
    if not _opened:
        syslog.openlog("pam_oauth2", syslog.LOG_PID, syslog.LOG_AUTH)
        _opened = True


def log_info(msg: str) -> None:
    _ensure_open()
    syslog.syslog(syslog.LOG_INFO, msg)


def log_error(msg: str) -> None:
    _ensure_open()
    syslog.syslog(syslog.LOG_ERR, msg)


def log_debug(msg: str) -> None:
    _ensure_open()
    syslog.syslog(syslog.LOG_DEBUG, msg)
