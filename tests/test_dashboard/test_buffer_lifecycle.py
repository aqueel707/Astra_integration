"""
tests/test_dashboard/test_buffer_lifecycle.py
──────────────────────────────────────────────
Guards for the live-view buffers.

Three defects, all invisible with one user on a laptop:

  P3  _buffers grew forever. Each entry owns a daemon thread and two deques,
      and the thread's stop flag was only checked AFTER a message arrived — so
      a quiet session's thread, and the deques it held, lived until the process
      exited even after the buffer was dropped.

  P4  logs_count was len() of a deque capped at 500, so the counter froze
      partway through a session and stopped telling the truth.

  P5  Sparkline history lived in a module-level dict shared by every visitor
      and mutated from Dash's multi-threaded handlers.
"""

from __future__ import annotations

import threading
import time

import pytest

from dashboard.callbacks import streaming as st


@pytest.fixture(autouse=True)
def clean_registry():
    with st._buffers_lock:
        st._buffers.clear()
    yield
    with st._buffers_lock:
        st._buffers.clear()


def test_true_totals_survive_the_deque_cap():
    """The counter must keep counting past the buffer's maxlen."""
    buf = st._get_buffer("s1")
    for i in range(700):
        with buf.lock:
            buf.logs.append({"id": i})
            buf.total_logs += 1

    assert len(buf.logs) == 500, "deque cap changed; test assumption stale"
    assert buf.total_logs == 700, "counter froze at the cap"


def test_idle_buffers_are_evicted():
    buf = st._get_buffer("stale-session")
    buf.last_seen = time.monotonic() - (st._BUFFER_TTL_SEC + 60)

    st._get_buffer("fresh-session")          # any access prunes

    with st._buffers_lock:
        assert "stale-session" not in st._buffers
        assert "fresh-session" in st._buffers
    assert buf.stop_event.is_set(), "evicted buffer's worker was never signalled"


def test_active_buffers_are_not_evicted():
    st._get_buffer("live-session")
    for _ in range(3):
        st._get_buffer("live-session")       # each access touches last_seen
    with st._buffers_lock:
        assert "live-session" in st._buffers


def test_drop_signals_the_worker():
    buf = st._get_buffer("s2")
    st._drop_buffer("s2")
    assert buf.stop_event.is_set()
    with st._buffers_lock:
        assert "s2" not in st._buffers


def test_stop_worker_cancels_the_subscription_task():
    """stop_event alone left a quiet worker blocked on the feed forever."""
    import asyncio

    buf = st._get_buffer("s3")
    cancelled = threading.Event()
    ready = threading.Event()

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        buf.loop = loop

        async def _forever():
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        task = loop.create_task(_forever())
        buf.task = task
        loop.call_soon(ready.set)
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
        finally:
            loop.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    assert ready.wait(timeout=5)

    st._stop_worker(buf)
    thread.join(timeout=5)

    assert cancelled.is_set(), "the worker was never cancelled"
    assert not thread.is_alive(), "the worker thread outlived its buffer"


def test_sparkline_state_is_per_session():
    """It used to be one module-level dict shared by everyone."""
    assert not hasattr(st, "_spark_state"), "module-level shared state is back"

    a, b = st._get_buffer("user-a"), st._get_buffer("user-b")
    a.spark_history = [1, 2, 3]
    a.spark_tick = 7

    assert b.spark_history == []
    assert b.spark_tick == 0
