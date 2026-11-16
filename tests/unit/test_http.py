"""Unit tests for VulnLake's shared source HTTP transport."""

import httpx
import pytest

from vulnlake.ingestion.http import SourceHttpClient


def test_http_client_retries_transient_failure_then_succeeds() -> None:
    """A temporary 503 should be retried before returning successful bytes."""

    request_count = 0
    recorded_delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return one transient failure followed by a successful response."""

        nonlocal request_count
        request_count += 1

        if request_count == 1:
            return httpx.Response(
                status_code=503,
                request=request,
            )

        return httpx.Response(
            status_code=200,
            content=b"source-payload",
            request=request,
        )

    client = SourceHttpClient(
        timeout_seconds=30.0,
        max_attempts=3,
        backoff_base_seconds=1.0,
        transport=httpx.MockTransport(handler),
        sleeper=recorded_delays.append,
    )

    payload = client.get_bytes("https://example.test/source")

    assert payload == b"source-payload"
    assert request_count == 2

    # First retry uses the configured base delay.
    assert recorded_delays == [1.0]


def test_http_client_stops_after_bounded_attempts() -> None:
    """Persistent transient failures must not retry forever."""

    request_count = 0
    recorded_delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return a persistent transient failure."""

        nonlocal request_count
        request_count += 1

        return httpx.Response(
            status_code=503,
            request=request,
        )

    client = SourceHttpClient(
        timeout_seconds=30.0,
        max_attempts=3,
        backoff_base_seconds=1.0,
        transport=httpx.MockTransport(handler),
        sleeper=recorded_delays.append,
    )

    with pytest.raises(httpx.HTTPStatusError):
        client.get_bytes("https://example.test/source")

    assert request_count == 3

    # Retries occur only between attempts:
    #
    # attempt 1 -> wait 1 second
    # attempt 2 -> wait 2 seconds
    # attempt 3 -> fail
    assert recorded_delays == [1.0, 2.0]
