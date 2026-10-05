"""
tests/test_streaming/test_manager_channels.py
──────────────────────────────────────────────
Guard for the WebSocket fan-out consumer.

The per-session consumer task is created once, on the first client's connect,
and used to be keyed to THAT client's requested stream set. A later client
asking for more (?streams=logs,alerts against a room opened with ?streams=logs)
was registered as wanting alerts while nothing was subscribed to the alerts
channel — so it silently received nothing, forever.
"""

from __future__ import annotations

import asyncio

import pytest

from streaming.channels import StreamType, all_channels_for
from streaming.manager import ConnectionManager


class _RecordingBackend:
    """Captures the channels subscribed to, then blocks like a real feed."""

    def __init__(self):
        self.subscribed: list[str] = []

    async def subscribe(self, *channels):
        self.subscribed.extend(channels)
        await asyncio.Event().wait()          # never yields a message
        yield  # pragma: no cover


@pytest.mark.asyncio
async def test_consumer_subscribes_to_every_stream(monkeypatch):
    import streaming.manager as manager

    backend = _RecordingBackend()
    monkeypatch.setattr(manager, "get_backend", lambda: backend)

    mgr = ConnectionManager()
    session_id = "session-abc"

    # A client that asked for logs only — the narrowest possible request.
    task = asyncio.create_task(mgr._run_consumer(session_id))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert set(backend.subscribed) == set(all_channels_for(session_id))

    # Every stream a session can publish must be covered, so a second client
    # asking for alerts is not silently starved.
    for stream in StreamType:
        assert any(c.endswith(f":{stream.value}") for c in backend.subscribed), stream


def test_all_channels_covers_every_stream_type():
    channels = all_channels_for("s1")
    assert len(channels) == len(list(StreamType))
