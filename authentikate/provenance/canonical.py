"""The versioned args-hash contract for provenance tokens.

A provenance token binds the cleartext args it was minted for via a hash (`ahs`)
rather than carrying them inline. The hash is computed over a *canonical* byte
encoding so that any verifier reproduces the exact bytes before hashing. The
encoding is a versioned contract: the issuer names the version in the `aha`
claim and any change is breaking and bumps ``CANONICALIZATION_VERSION``.

This must stay byte-for-byte identical to the issuer side (Rekuest's
``facade/provenance/canonical.py``).
"""

import hashlib
import json
from typing import Any

from authentikate.errors import UnsupportedCanonicalizationError

CANONICALIZATION_VERSION = "sha256-canonical-v1"
"""The current canonicalization version, mirrored into the token's ``aha`` claim."""


def canonicalize_v1(args: Any) -> bytes:
    """Canonicalize args under v1.

    v1: ``json.dumps`` with sorted keys and no insignificant whitespace,
    non-ASCII left as UTF-8, encoded to UTF-8 bytes.
    """
    return json.dumps(
        args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def args_hash(args: Any, version: str = CANONICALIZATION_VERSION) -> str:
    """Compute the hex SHA-256 of the canonicalized args for ``version``.

    Raises
    ------
    UnsupportedCanonicalizationError
        When ``version`` is not a canonicalization this verifier can reproduce.
    """
    if version != CANONICALIZATION_VERSION:
        raise UnsupportedCanonicalizationError(
            f"Unsupported canonicalization version: {version!r}"
        )

    return hashlib.sha256(canonicalize_v1(args)).hexdigest()
