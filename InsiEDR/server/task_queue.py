"""
server/task_queue.py
--------------------
PostgreSQL-backed durable task queue.

Replaces the in-memory ThreadPoolExecutor approach so that:
  - Pending ML inference and webhook tasks survive a server restart.
  - Concurrency is controlled by Postgres row-level locking (FOR UPDATE SKIP LOCKED).
  - Failed tasks are automatically retried up to max_attempts.

Architecture:
  - PgTaskQueue  : Enqueue / claim / complete / fail tasks against the DB.
  - TaskWorker   : A daemon thread that continuously polls and dispatches tasks.
  - start_worker : Factory that wires up handlers and starts the background thread.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from contextlib import closing
from typing import Any, Callable

log = logging.getLogger("insiedr.task_queue")

# Unique identity for this process so multiple servers can share one queue
_WORKER_ID = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"

# How many seconds to sleep between polls when the queue is empty
_POLL_INTERVAL = 2.0


class PgTaskQueue:
    """Thin wrapper around the task_queue table for enqueue / dequeue operations."""

    def __init__(self, storage) -> None:
        self._storage = storage

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(self, task_type: str, payload: dict[str, Any], max_attempts: int = 3) -> int | None:
        """
        Insert a new task into the queue.
        Returns the new task ID, or None on failure.
        """
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        INSERT INTO task_queue (task_type, payload_json, max_attempts)
                        VALUES (%s, %s, %s)
                        RETURNING id
                        """,
                        (task_type, json.dumps(payload), max_attempts),
                    )
                    row = cur.fetchone()
                    conn.commit()
                    return row[0] if row else None
        except Exception as exc:
            log.error("Failed to enqueue task '%s': %s", task_type, exc)
            return None

    def claim_next(self) -> dict[str, Any] | None:
        """
        Atomically claim one pending/retry task using SKIP LOCKED.
        Returns the task dict, or None if the queue is empty.
        """
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        UPDATE task_queue
                        SET status    = 'running',
                            locked_at = CURRENT_TIMESTAMP,
                            locked_by = %s,
                            attempts  = attempts + 1
                        WHERE id = (
                            SELECT id FROM task_queue
                            WHERE status IN ('pending', 'retry')
                              AND scheduled_at <= CURRENT_TIMESTAMP
                            ORDER BY scheduled_at
                            LIMIT 1
                            FOR UPDATE SKIP LOCKED
                        )
                        RETURNING id, task_type, payload_json, attempts, max_attempts
                        """,
                        (_WORKER_ID,),
                    )
                    row = cur.fetchone()
                    conn.commit()
                    if not row:
                        return None
                    task_id, task_type, payload_json, attempts, max_attempts = row
                    payload = (
                        payload_json if isinstance(payload_json, dict)
                        else json.loads(payload_json or "{}")
                    )
                    return {
                        "id": task_id,
                        "task_type": task_type,
                        "payload": payload,
                        "attempts": attempts,
                        "max_attempts": max_attempts,
                    }
        except Exception as exc:
            log.error("Failed to claim task: %s", exc)
            return None

    def complete(self, task_id: int) -> None:
        """Mark a task as successfully completed."""
        self._update_status(task_id, "completed", completed=True)

    def fail(self, task_id: int, task: dict[str, Any], error: str) -> None:
        """
        Mark a task as failed.
        If retries remain, reschedule it as 'retry' with exponential back-off.
        Otherwise mark it permanently 'failed'.
        """
        attempts = task.get("attempts", 1)
        max_attempts = task.get("max_attempts", 3)
        if attempts < max_attempts:
            # Exponential back-off: 10s, 40s, 160s …
            delay_seconds = 10 * (4 ** (attempts - 1))
            self._reschedule(task_id, error, delay_seconds)
        else:
            self._update_status(task_id, "failed", error=error)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_status(self, task_id: int, status: str, *, error: str = None, completed: bool = False) -> None:
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        UPDATE task_queue
                        SET status       = %s,
                            error_message = %s,
                            completed_at  = CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE completed_at END
                        WHERE id = %s
                        """,
                        (status, error, completed, task_id),
                    )
                    conn.commit()
        except Exception as exc:
            log.error("Failed to update task %s status to '%s': %s", task_id, status, exc)

    def _reschedule(self, task_id: int, error: str, delay_seconds: int) -> None:
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        UPDATE task_queue
                        SET status        = 'retry',
                            locked_at     = NULL,
                            locked_by     = NULL,
                            scheduled_at  = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                            error_message = %s
                        WHERE id = %s
                        """,
                        (delay_seconds, error, task_id),
                    )
                    conn.commit()
                log.info("Task %s rescheduled for retry in %ds", task_id, delay_seconds)
        except Exception as exc:
            log.error("Failed to reschedule task %s: %s", task_id, exc)


class TaskWorker:
    """
    Background daemon thread that polls PgTaskQueue and dispatches tasks
    to registered handler functions.
    """

    def __init__(self, queue: PgTaskQueue, poll_interval: float = _POLL_INTERVAL) -> None:
        self._queue = queue
        self._poll_interval = poll_interval
        self._handlers: dict[str, Callable[[dict[str, Any]], None]] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, task_type: str, handler: Callable[[dict[str, Any]], None]) -> None:
        """Register a handler function for a given task_type string."""
        self._handlers[task_type] = handler
        log.info("Registered handler for task type '%s'", task_type)

    def start(self) -> None:
        """Start the background polling thread."""
        self._thread = threading.Thread(
            target=self._run,
            name="PgTaskWorker",
            daemon=True,
        )
        self._thread.start()
        log.info("PgTaskWorker started (worker_id=%s, poll=%.1fs)", _WORKER_ID, self._poll_interval)

    def stop(self) -> None:
        """Signal the worker to stop after the current task completes."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal polling loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop_event.is_set():
            task = self._queue.claim_next()
            if task is None:
                # Queue is empty — sleep before polling again
                self._stop_event.wait(timeout=self._poll_interval)
                continue
            self._dispatch(task)

    def _dispatch(self, task: dict[str, Any]) -> None:
        task_id = task["id"]
        task_type = task["task_type"]
        handler = self._handlers.get(task_type)
        if handler is None:
            log.warning("No handler registered for task type '%s' (id=%s)", task_type, task_id)
            self._queue.fail(task_id, task, f"No handler for task_type '{task_type}'")
            return
        try:
            log.debug("Dispatching task %s (type=%s, attempt=%s)", task_id, task_type, task["attempts"])
            handler(task["payload"])
            self._queue.complete(task_id)
            log.debug("Task %s completed successfully", task_id)
        except Exception as exc:
            log.error("Task %s (type=%s) failed on attempt %s: %s", task_id, task_type, task["attempts"], exc)
            self._queue.fail(task_id, task, str(exc))


def start_worker(storage, app) -> TaskWorker:
    """
    Factory: create a PgTaskQueue, register all known task handlers,
    attach the queue to the Flask app, start the worker thread, and return it.
    """
    from server.model_bridge import bridge as model_bridge
    from server.utils.webhook import _send_webhook

    queue = PgTaskQueue(storage)

    # ---- Handler: ML inference pipeline ----
    def handle_ml_inference(payload: dict[str, Any]) -> None:
        with app.app_context():
            storage_instance = app.extensions.get("insiedr_storage")
            if storage_instance:
                model_bridge.process_payload(storage_instance, payload)

    # ---- Handler: Webhook alert ----
    def handle_webhook_alert(payload: dict[str, Any]) -> None:
        _send_webhook(payload)

    worker = TaskWorker(queue)
    worker.register("ml_inference", handle_ml_inference)
    worker.register("webhook_alert", handle_webhook_alert)
    worker.start()

    # Make the queue accessible from anywhere via app.extensions
    app.extensions["task_queue"] = queue

    return worker
