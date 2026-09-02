"""Checking verified tokens against an issuer's revocation list.

A JWT is verified offline, so on its own it stays valid until ``exp`` no matter
what the issuer has decided since. lok closes that gap by publishing the ``jti``
of every access token it has revoked but which has not yet expired. This module
consumes that list.

The design goal is a bounded number of outbound requests. The list is fetched at
most once per ``refresh_interval`` per issuer, and every check in between is
answered from the cached copy -- so the request rate is set by configuration,
not by inbound traffic: a thousand tokens presented within one interval cost one
fetch, and so does one token. A refresh that fails is not retried before the
next interval either, for the same reason the JWKS loader throttles failures --
an unreachable issuer must not turn each inbound request into an outbound one.

Expected response shape::

    {"revoked": ["<jti>", "<jti>", ...]}

A bare JSON list of ``jti`` strings is accepted too. The issuer only needs to
list tokens that are both revoked and unexpired, so the document stays small.
"""

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def _parse_revoked(payload: Any) -> frozenset[str]:
    """Extract the set of revoked ``jti``s from a revocation-list document."""

    if isinstance(payload, dict):
        payload = payload.get("revoked")

    if not isinstance(payload, list) or not all(isinstance(jti, str) for jti in payload):
        raise ValueError("Revocation list must be a list of jti strings, or an object with a 'revoked' list")

    return frozenset(payload)


class RevocationList:
    """A periodically refreshed, cached copy of one issuer's revoked ``jti``s.

    Fail-open by design, with a stale copy preferred over none: when a refresh
    fails the previous list keeps answering, and until a first load succeeds no
    token is treated as revoked. Revocation is defence in depth on top of
    signature and expiry checks, and failing closed here would let an
    unreachable issuer log every user out of every service at once. Both
    failure modes are logged as warnings.
    """

    def __init__(self, uri: str, refresh_interval: float, request_timeout: float) -> None:
        """Create a list for ``uri``, refreshed at most once per ``refresh_interval`` seconds."""

        self.uri = uri
        self.refresh_interval = refresh_interval
        self.request_timeout = request_timeout
        self._revoked: frozenset[str] | None = None
        self._last_attempt: float | None = None
        self._last_success: float | None = None
        self._lock = asyncio.Lock()

    @property
    def revoked(self) -> frozenset[str]:
        """The currently cached set of revoked ``jti``s (empty before the first load)."""

        return self._revoked if self._revoked is not None else frozenset()

    def _is_due(self) -> bool:
        """Whether the cached copy is older than ``refresh_interval`` (or missing)."""

        return self._last_attempt is None or time.monotonic() - self._last_attempt >= self.refresh_interval

    async def ais_revoked(self, jti: str) -> bool:
        """Report whether ``jti`` is revoked, refreshing the list first when it is due."""

        if self._is_due():
            async with self._lock:
                # Re-check under the lock: the waiters queued behind the one
                # request that was actually refreshing must reuse its result
                # rather than each firing a request of their own.
                if self._is_due():
                    await self._refresh()

        return jti in self.revoked

    def is_revoked(self, jti: str) -> bool:
        """Synchronous :meth:`ais_revoked`, for the blocking decode path."""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.ais_revoked(jti))

        raise RuntimeError("Cannot check revocation synchronously while an event loop is running; use ais_revoked instead")

    async def _refresh(self) -> None:
        """Fetch the list once, recording the attempt whether or not it succeeds."""

        self._last_attempt = time.monotonic()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.request_timeout)) as client:
                response = await client.get(self.uri)
                response.raise_for_status()
                revoked = _parse_revoked(response.json())
        except Exception:
            if self._last_success is None:
                logger.warning(
                    "Could not load the revocation list from %s; no token is treated as revoked until it loads (next attempt in %.0fs)",
                    self.uri,
                    self.refresh_interval,
                    exc_info=True,
                )
            else:
                logger.warning(
                    "Could not refresh the revocation list from %s; keeping the copy loaded %.0fs ago (next attempt in %.0fs)",
                    self.uri,
                    self._last_attempt - self._last_success,
                    self.refresh_interval,
                    exc_info=True,
                )
            return

        self._revoked = revoked
        self._last_success = self._last_attempt
