"""
agent/warning_filters.py — Warning Suppression & Redirection
=============================================================

Background
----------
Several third-party libraries used by InsiEDR collectors (``psutil``, WMI,
``wmi``, ``pythoncom``) emit repetitive, non-critical ``warnings.warn()``
calls during normal background operation on Windows endpoints.  Examples:

* ``psutil.AccessDenied`` permission warnings on system processes (expected
  for certain PIDs even under SYSTEM; not a sign of malfunction).
* WMI COM ``ResourceWarning`` on slow or disconnected WMI namespaces.
* ``DeprecationWarning`` from optional dependencies that have not yet been
  updated to newer Python versions.

These warnings clutter the ``INFO``-level log output, can trigger false-positive
alert rules in SIEM ingestion pipelines, and do not represent actionable events
for the analyst.

Design
------
This module installs two complementary suppression strategies:

1. **``warnings.filterwarnings`` rules** — added to the global filter chain
   so that matching ``warnings.warn()`` calls are silently caught before
   they reach the default ``showwarning`` handler.

2. **``logging.captureWarnings(True)``** — redirects *all* surviving
   ``warnings.warn()`` calls (those not matched by the filter rules) into
   the standard Python ``logging`` framework under the logger named
   ``"py.warnings"``.  Combined with setting that logger to ``DEBUG`` level,
   warnings become invisible at the default ``INFO`` threshold but are still
   inspectable when ``INSIEDR_LOG_LEVEL=DEBUG``.

Idempotency
-----------
:func:`apply_warning_filters` is safe to call multiple times.  It checks a
module-level flag ``_FILTERS_APPLIED`` and returns immediately on subsequent
calls, so importing this module in tests or sub-processes never double-installs
the filters.

Usage
-----
Call :func:`apply_warning_filters` as early as possible in
:func:`agent.agent.main`, before any collector or config initialisation:

.. code-block:: python

    from agent.warning_filters import apply_warning_filters
    apply_warning_filters()
"""
from __future__ import annotations

import logging
import warnings

log = logging.getLogger("insiedr.warnings")

# Module-level idempotency flag — set to True after first successful install.
_FILTERS_APPLIED: bool = False

# ---------------------------------------------------------------------------
# Filter rule definitions
# Each entry is a tuple of (action, message_pattern, category, module_pattern)
# matching the signature of warnings.filterwarnings().
# "ignore"  → completely suppress (no logging, no output)
# "always"  → let through so logging.captureWarnings can catch them at DEBUG
# ---------------------------------------------------------------------------
_FILTER_RULES: list[tuple[str, str, type, str]] = [
    # -----------------------------------------------------------------------
    # psutil — permission / access-denied noise
    # These are emitted when iterating processes that the OS protects (e.g.
    # System, Idle, csrss.exe).  Under SYSTEM they are expected and benign.
    # -----------------------------------------------------------------------
    ("ignore", r".*could not read.*", UserWarning, r"psutil.*"),
    ("ignore", r".*AccessDenied.*",   UserWarning, r"psutil.*"),
    ("ignore", r".*NoSuchProcess.*",  UserWarning, r"psutil.*"),
    ("ignore", r".*ZombieProcess.*",  UserWarning, r"psutil.*"),

    # -----------------------------------------------------------------------
    # WMI / pythoncom — COM infrastructure warnings
    # WMI queries can time-out or return partial results on loaded systems;
    # these are recoverable and should not alert an analyst.
    # -----------------------------------------------------------------------
    ("ignore", r".*WMI.*",          ResourceWarning,    r"wmi.*"),
    ("ignore", r".*WMI.*",          UserWarning,        r"wmi.*"),
    ("ignore", r".*pythoncom.*",    ResourceWarning,    r".*"),

    # -----------------------------------------------------------------------
    # win32com / pywin32 — optional dependency deprecation noise
    # -----------------------------------------------------------------------
    ("ignore", r".*win32.*",        DeprecationWarning, r".*"),

    # -----------------------------------------------------------------------
    # General DeprecationWarning from third-party packages
    # We still want to *see* our own code's deprecation warnings in dev,
    # so we only suppress those originating outside the agent/ package.
    # -----------------------------------------------------------------------
    ("ignore", r".*",               DeprecationWarning, r"(?!agent\.).*"),

    # -----------------------------------------------------------------------
    # ResourceWarning from unclosed sockets / handles inside collectors
    # Noisy during normal teardown; not actionable.
    # -----------------------------------------------------------------------
    ("ignore", r".*unclosed.*",     ResourceWarning,    r".*"),
]


def apply_warning_filters() -> None:
    """Install warning suppression filters and redirect survivors to DEBUG logging.

    This function:

    1. Checks the idempotency flag ``_FILTERS_APPLIED`` — returns immediately
       if already called.
    2. Installs each rule from ``_FILTER_RULES`` via
       ``warnings.filterwarnings()``.  Rules are prepended (``insert_index=0``)
       so they take priority over any default rules already present.
    3. Calls ``logging.captureWarnings(True)`` to redirect all remaining
       ``warnings.warn()`` calls into the ``py.warnings`` logger.
    4. Sets the ``py.warnings`` logger to ``DEBUG`` level so the captured
       warnings are invisible at the default ``INFO`` threshold but available
       when the operator runs with ``INSIEDR_LOG_LEVEL=DEBUG``.

    Safe to call multiple times — no-op after the first call.
    """
    global _FILTERS_APPLIED  # noqa: PLW0603

    if _FILTERS_APPLIED:
        log.debug("warning_filters.apply_warning_filters: already applied — skipping")
        return

    # ------------------------------------------------------------------
    # Step 1: Install filter rules (prepend so they win against defaults)
    # ------------------------------------------------------------------
    for action, message, category, module in _FILTER_RULES:
        warnings.filterwarnings(
            action,
            message=message,
            category=category,
            module=module,
        )

    log.debug(
        "warning_filters: installed %d suppression rules for psutil/WMI/win32com",
        len(_FILTER_RULES),
    )

    # ------------------------------------------------------------------
    # Step 2: Redirect surviving warnings into Python logging at DEBUG
    # ------------------------------------------------------------------
    logging.captureWarnings(True)

    # The logger that captureWarnings() writes to is always "py.warnings".
    # Set it to DEBUG so it does not bubble up to the root logger at INFO.
    py_warnings_logger = logging.getLogger("py.warnings")
    py_warnings_logger.setLevel(logging.DEBUG)

    # Prevent "py.warnings" from propagating to the root logger — this
    # ensures suppressed warnings truly stay silent unless the operator
    # explicitly adds a DEBUG handler.
    py_warnings_logger.propagate = False

    log.debug(
        "warning_filters: logging.captureWarnings(True) active — "
        "surviving warnings routed to py.warnings logger at DEBUG level"
    )

    _FILTERS_APPLIED = True


def reset_warning_filters() -> None:
    """Remove all custom warning filters installed by :func:`apply_warning_filters`.

    **For testing use only.**  Restores the default ``warnings.filters`` list
    and resets the idempotency flag so the module can be re-initialised.
    """
    global _FILTERS_APPLIED  # noqa: PLW0603

    warnings.resetwarnings()
    logging.captureWarnings(False)

    py_warnings_logger = logging.getLogger("py.warnings")
    py_warnings_logger.setLevel(logging.WARNING)
    py_warnings_logger.propagate = True

    _FILTERS_APPLIED = False
    log.debug("warning_filters.reset_warning_filters: filters cleared")
