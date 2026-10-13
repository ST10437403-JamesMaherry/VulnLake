"""Reusable HTTP transport for VulnLake external data sources."""

import time
from collections.abc import Callable

import httpx

# These status codes commonly represent temporary conditions where retrying
# can succeed without changing the request.
RETRYABLE_STATUS_CODES = frozenset(
    {
        408,  # Request Timeout
        429,  # Too Many Requests
        500,  # Internal Server Error
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
    }
)


class SourceHttpClient:
    """Retrieve external source payloads with bounded retry behaviour."""

    def __init__(
        self,
        timeout_seconds: float,
        max_attempts: int,
        backoff_base_seconds: float,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        """Configure the reusable source HTTP client.

        ``transport`` and ``sleeper`` are injectable primarily so tests can
        simulate HTTP behaviour without contacting real external services or
        actually waiting between retry attempts.
        """

        if timeout_seconds <= 0:
            raise ValueError("HTTP timeout must be greater than zero.")

        if max_attempts < 1:
            raise ValueError("HTTP max_attempts must be at least one.")

        if backoff_base_seconds < 0:
            raise ValueError("HTTP backoff_base_seconds must not be negative.")

        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.backoff_base_seconds = backoff_base_seconds
        self.transport = transport
        self.sleeper = sleeper

    def _backoff_delay(
        self,
        attempt: int,
        response: httpx.Response | None = None,
    ) -> float:
        """Calculate the delay before the next retry attempt.

        A numeric Retry-After header is preferred when supplied by the remote
        service. Otherwise VulnLake falls back to exponential backoff.
        """

        if response is not None:
            retry_after = response.headers.get("Retry-After")

            if retry_after is not None:
                try:
                    parsed_delay = float(retry_after)

                    if parsed_delay >= 0:
                        return parsed_delay
                except ValueError:
                    # Non-numeric HTTP-date Retry-After values are ignored for
                    # now; exponential backoff remains deterministic.
                    pass

        return self.backoff_base_seconds * (2 ** (attempt - 1))

    def get_bytes(self, url: str) -> bytes:
        """Retrieve raw bytes from an external source.

        Redirects are followed because some public feeds, including EPSS,
        redirect stable "current" URLs to dated source objects.

        Only transient transport/status failures are retried. Permanent HTTP
        failures propagate immediately.
        """

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=True,
            transport=self.transport,
        ) as client:
            for attempt in range(1, self.max_attempts + 1):
                try:
                    response = client.get(url)

                    should_retry_status = (
                        response.status_code in RETRYABLE_STATUS_CODES
                        and attempt < self.max_attempts
                    )

                    if should_retry_status:
                        delay = self._backoff_delay(
                            attempt=attempt,
                            response=response,
                        )
                        self.sleeper(delay)
                        continue

                    # Permanent failures and exhausted transient failures
                    # become explicit exceptions.
                    response.raise_for_status()

                    return response.content

                except httpx.TransportError:
                    # DNS failures, connection resets and similar transport
                    # problems are retried only while attempts remain.
                    if attempt >= self.max_attempts:
                        raise

                    delay = self._backoff_delay(attempt=attempt)
                    self.sleeper(delay)

        # The loop either returns bytes or raises. This guard protects against
        # future control-flow changes accidentally returning None.
        raise RuntimeError("HTTP retrieval ended without a result.")
