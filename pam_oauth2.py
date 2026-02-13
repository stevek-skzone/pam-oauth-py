"""Thin shim loaded by pam_python.so.

This file sits at the top level so pam_python.so can load it directly.
It re-exports all PAM entry points from the package.
"""

from pam_oauth2.pam_sm import (  # noqa: F401
    pam_sm_acct_mgmt,
    pam_sm_authenticate,
    pam_sm_chauthtok,
    pam_sm_close_session,
    pam_sm_open_session,
    pam_sm_setcred,
)
