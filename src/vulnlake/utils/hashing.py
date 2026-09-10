"""Hashing utilities used to track source integrity and idempotency."""

import hashlib


def sha256_bytes(payload: bytes) -> str:
    """Return the SHA-256 hexadecimal digest for a byte payload.

    Hashing the original source bytes gives VulnLake a deterministic
    fingerprint that can be used for provenance and duplicate detection.
    """

    return hashlib.sha256(payload).hexdigest()
