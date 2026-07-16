"""
agent/privilege.py — Windows Privilege Guard
=============================================

This module provides a single-responsibility utility for detecting and
ensuring that the InsiEDR agent process is running with administrator-level
privileges on Windows.

Architecture
------------
* :func:`is_admin` — thin wrapper around ``ctypes.windll.shell32.IsUserAnAdmin()``.
  Returns ``True`` if the current process token holds the Administrators group
  in its enabled privileges.  Safe to call on non-Windows (always returns
  ``False``).

* :func:`relaunch_as_admin` — re-launches the *current* Python process via
  ``ShellExecuteW`` with the ``runas`` verb, which triggers exactly one UAC
  consent dialog and then exits the unprivileged parent.  This function never
  returns in normal operation.

* :func:`require_admin` — the primary entry-point for callers.  If the process
  is already elevated, it is a no-op.  If not, it calls
  :func:`relaunch_as_admin`, producing the UAC prompt.  It must **not** be
  called when the agent is already running under the Windows Task Scheduler
  with SYSTEM/HIGHEST privileges (detected via the ``INSIEDR_SCHEDULED_TASK``
  environment variable) to avoid an infinite re-launch loop.

Warning Suppression
-------------------
All privilege-check failures that are non-fatal (e.g., ``ctypes`` not
available, non-Windows OS) are logged at DEBUG level only — they are never
raised to the caller as exceptions.  This keeps the agent fully operational
in development or Linux CI environments.

UAC Re-launch Loop Prevention
------------------------------
The batch installer sets ``INSIEDR_SCHEDULED_TASK=1`` in the Task Scheduler
action's environment block.  :func:`require_admin` checks for this variable
before attempting any elevation so that the already-elevated scheduled task
never triggers a UAC dialog.
"""
from __future__ import annotations

import logging
import os
import sys

log = logging.getLogger("insiedr.privilege")

# ---------------------------------------------------------------------------
# Platform guard — all ctypes/win32 imports are deferred so this module is
# safely importable on Linux / macOS (CI environments, cross-platform tests).
# ---------------------------------------------------------------------------
_WINDOWS = sys.platform == "win32"


def is_admin() -> bool:
    """Return ``True`` if the current process has administrator privileges.

    On non-Windows platforms this always returns ``False`` (and logs a DEBUG
    message).  The caller is responsible for deciding whether to abort or
    continue in a degraded mode.

    Implementation detail
    ~~~~~~~~~~~~~~~~~~~~~
    ``shell32.IsUserAnAdmin()`` checks the process token for the built-in
    Administrators SID with ``SE_GROUP_ENABLED``.  It is the canonical,
    documented Win32 method and does not require pywin32.
    """
    if not _WINDOWS:
        log.debug("privilege.is_admin: non-Windows platform — returning False")
        return False

    try:
        import ctypes
        result: bool = bool(ctypes.windll.shell32.IsUserAnAdmin())
        log.debug("privilege.is_admin: IsUserAnAdmin() = %s", result)
        return result
    except Exception as exc:  # pragma: no cover — hardware/policy edge-cases
        log.debug("privilege.is_admin: ctypes call failed (%s) — assuming not admin", exc)
        return False


def relaunch_as_admin() -> None:
    """Re-launch the current process with administrator privileges via UAC.

    This function uses ``ShellExecuteW`` with the ``runas`` verb, which
    triggers the Windows UAC consent dialog exactly **once**.  After the
    elevated child process is launched this function calls ``sys.exit(0)``
    so the unprivileged parent exits cleanly.

    Behaviour on non-Windows
    ~~~~~~~~~~~~~~~~~~~~~~~~
    Logs a WARNING and returns without doing anything — the caller decides
    how to proceed.

    Raises
    ------
    SystemExit(0)
        Always raised after successfully dispatching the elevated process so
        the unprivileged parent does not continue execution.
    """
    if not _WINDOWS:
        log.warning(
            "privilege.relaunch_as_admin: called on non-Windows — cannot elevate; "
            "continuing without elevation"
        )
        return

    try:
        import ctypes

        # Build the exact command the elevated child should run.
        # sys.executable  → python.exe (or pythonw.exe)
        # sys.argv[0]     → the script / -m module path
        # sys.argv[1:]    → all original arguments
        python_exe = sys.executable
        script_args = " ".join(f'"{a}"' for a in sys.argv)

        log.info(
            "privilege: not running as admin — requesting elevation via UAC. "
            "This prompt will appear only once during initial setup."
        )

        ret = ctypes.windll.shell32.ShellExecuteW(
            None,       # hwnd (no parent window — background/service context)
            "runas",    # lpVerb — triggers UAC consent dialog
            python_exe, # lpFile
            script_args,# lpParameters
            None,       # lpDirectory (inherit cwd)
            1,          # nShowCmd: SW_SHOWNORMAL
        )

        # ShellExecuteW returns a value > 32 on success.
        if ret <= 32:  # pragma: no cover
            log.error(
                "privilege: ShellExecuteW returned %d — UAC elevation may have been "
                "denied or the executable path is invalid. Agent will continue "
                "without full privileges.", ret
            )
            return  # Let caller decide — do not exit so the agent can limp along

        # Success: the elevated child is starting. Exit the unprivileged parent.
        log.debug("privilege: elevated child launched (ShellExecuteW=%d). Exiting parent.", ret)
        sys.exit(0)

    except Exception as exc:  # pragma: no cover
        log.error(
            "privilege: unexpected error during UAC re-launch (%s). "
            "Continuing without elevation.", exc
        )


def require_admin(reason: str = "InsiEDR endpoint agent requires administrator privileges") -> None:
    """Ensure the process is running as administrator, elevating via UAC if needed.

    This is the **primary entry-point** for privilege management.  Call it
    once near the top of :func:`agent.agent.main` *before* any privileged
    operations (WMI queries, raw socket access, LSASS inspection, etc.).

    UAC Re-launch Loop Prevention
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    If the environment variable ``INSIEDR_SCHEDULED_TASK=1`` is set (as
    injected by ``install_agent_task.bat``), this function is a guaranteed
    no-op.  The Task Scheduler already runs the task with ``HIGHEST``
    privilege under the ``SYSTEM`` account, so no elevation is needed and
    triggering another ``ShellExecuteW`` would create an infinite loop.

    Parameters
    ----------
    reason:
        Human-readable string logged at INFO level explaining *why* elevation
        is required.  Shown before the UAC prompt appears.
    """
    # --- Guard: already running via scheduled task (SYSTEM/HIGHEST) -----------
    if os.environ.get("INSIEDR_SCHEDULED_TASK", "").strip() == "1":
        log.debug(
            "privilege.require_admin: INSIEDR_SCHEDULED_TASK=1 detected — "
            "skipping UAC check (already elevated by Task Scheduler)"
        )
        return

    # --- Guard: test / development mode --------------------------------------
    # Read the same env vars that AgentConfig uses so there is a single source
    # of truth for the runtime mode.  In "test" or "development" mode we skip
    # the UAC check entirely so that:
    #   (a) the test suite can call main() without triggering sys.exit(0), and
    #   (b) developers running from a non-elevated shell aren't blocked.
    _mode = (
        os.environ.get("INSIEDR_AGENT_MODE")
        or os.environ.get("INSIEDR_MODE")
        or "production"
    ).strip().lower()
    if _mode in {"test", "development"}:
        log.debug(
            "privilege.require_admin: mode=%s — skipping UAC check in non-production environment",
            _mode,
        )
        return

    # --- Guard: running inside the pytest test suite -------------------------
    # pytest automatically sets PYTEST_CURRENT_TEST to the currently-running
    # test node ID.  We use this as a reliable, zero-configuration signal that
    # we are inside a test session and must not trigger sys.exit() or UAC.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        log.debug(
            "privilege.require_admin: PYTEST_CURRENT_TEST detected — "
            "skipping UAC check inside test session"
        )
        return

    # --- Guard: non-Windows platform -----------------------------------------
    if not _WINDOWS:
        log.debug("privilege.require_admin: non-Windows platform — skipping UAC check")
        return

    # --- Main path -----------------------------------------------------------
    if is_admin():
        log.debug("privilege.require_admin: process already has administrator privileges")
        return

    # Not elevated and not under the scheduler — request elevation.
    log.info("privilege.require_admin: %s", reason)
    relaunch_as_admin()
    # relaunch_as_admin() calls sys.exit(0) on success; if we reach here it
    # means elevation failed silently — log and continue in degraded mode.
    log.warning(
        "privilege.require_admin: elevation was not successful. Some collectors "
        "that require administrator access (WMI, LSASS, raw sockets) may fail."
    )
