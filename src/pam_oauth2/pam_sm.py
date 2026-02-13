"""PAM entry points for OAuth2/OIDC JWT authentication.

These functions are called by pam_python.so. Each receives:
  - pamh: PAM handle object (provides get_user(), conversation(), authtok, etc.)
  - flags: PAM flags (unused)
  - argv: list of strings from the PAM config line
"""

from __future__ import annotations

from .config import ConfigError, parse_args
from .logging import log_error, log_info
from .token_validator import TokenValidationError, validate_token

# PAM return codes (duplicated here so they work without pam_python at import time)
PAM_SUCCESS = 0
PAM_AUTH_ERR = 7
PAM_IGNORE = 25
PAM_PROMPT_ECHO_OFF = 1


def pam_sm_authenticate(pamh, flags, argv):
    """Authenticate a user by validating an OAuth2/OIDC JWT token.

    The JWT is obtained from pamh.authtok (if already set by a prior module)
    or by prompting the user via PAM conversation.
    """
    try:
        config = parse_args(argv)
    except ConfigError as exc:
        log_error(f"configuration error: {exc}")
        return PAM_AUTH_ERR

    user = None  # Initialize to prevent NameError in exception handlers
    try:
        # Get username
        try:
            user = pamh.get_user(None)
        except Exception:
            user = pamh.get_user()
        if not user:
            log_error("could not determine username")
            return PAM_AUTH_ERR

        # Get the token from authtok or conversation
        token = getattr(pamh, "authtok", None)
        if not token:
            try:
                msg = pamh.Message(PAM_PROMPT_ECHO_OFF, "Token: ")
                resp = pamh.conversation(msg)
                token = resp.resp
            except Exception as exc:
                log_error(f"conversation failed: {exc}")
                return PAM_AUTH_ERR

        if not token:
            log_error("no token provided")
            return PAM_AUTH_ERR

        # Validate the token
        validate_token(token, user, config)
        log_info(f"authentication succeeded for user '{user}'")
        return PAM_SUCCESS

    except TokenValidationError as exc:
        log_error(f"authentication failed for user '{user}': {exc}")
        return PAM_AUTH_ERR
    except Exception:
        # Fail closed: any unexpected error → deny
        log_error("authentication failed: unexpected error")
        return PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    """Set credentials — not used, return success."""
    return PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    """Account management — not used, return ignore."""
    return PAM_IGNORE


def pam_sm_open_session(pamh, flags, argv):
    """Open session — not used, return success."""
    return PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    """Close session — not used, return success."""
    return PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    """Change auth token — not applicable for OAuth, return ignore."""
    return PAM_IGNORE
