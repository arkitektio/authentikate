"""Pydantic models for a decoded provenance token.

A provenance token attests *who caused a unit of work and with which inputs*. It
is minted by Rekuest (the provenance issuer) at each assignment and verified
offline on the consuming/audience end (this library). See ``decode.py`` for the
verification entrypoint.
"""

import datetime
from typing import Any, Type

from pydantic import BaseModel, ConfigDict, field_validator

from authentikate.base_models import coerce_aud_to_list, coerce_unix_to_datetime
from authentikate.provenance import canonical


class Actor(BaseModel):
    """The actor a provenance token is issued to: the executing agent.

    The verifier binds these against the agent's own auth token (see
    ``verify.verify_actor``).
    """

    model_config = ConfigDict(extra="ignore")

    sub: str
    """The executing agent's user sub."""
    cid: str
    """The executing agent's OAuth client_id."""


class ProvenanceToken(BaseModel):
    """A decoded, signature-verified provenance token.

    Standard registered claims keep their canonical names; Rekuest's own claims
    use compact three-letter symbols.
    """

    model_config = ConfigDict(extra="ignore")

    # --- registered claims ---
    iss: str
    """The provenance issuer id (e.g. "rekuest")."""
    aud: list[str]
    """The target services the token is scoped to (always a list, never wildcard)."""
    sub: str
    """The immediate causer of this hop (the request principal)."""
    act: Actor
    """The actor the token is issued to (the executing agent)."""
    iat: datetime.datetime
    """Issued-at."""
    exp: datetime.datetime
    """Expiry."""
    jti: str
    """Unique per token; the verifier enforces single-use."""

    # --- rekuest provenance claims ---
    tsk: str
    """This assignation id."""
    ptk: str | None = None
    """Immediate parent assignation id (None if this is the root)."""
    rtk: str
    """Root assignation id of the whole tree (== tsk when this is the root)."""
    rcb: str
    """The human principal at the root of the tree (always human)."""
    ahs: str
    """SHA-256 of the canonicalized args."""
    aha: str
    """The canonicalization algorithm/version, so a verifier can recompute ahs."""

    raw: str
    """The raw original token string."""

    @field_validator("aud", mode="before")
    def aud_to_list(
        cls: Type["ProvenanceToken"], v: str | list[str] | None
    ) -> list[str] | None:
        """Convert the aud to a list"""
        return coerce_aud_to_list(v)

    @field_validator("iat", mode="before")
    def iat_to_datetime(
        cls: Type["ProvenanceToken"], v: int
    ) -> datetime.datetime | None:
        """Convert the iat to a datetime object"""
        return coerce_unix_to_datetime(v)

    @field_validator("exp", mode="before")
    def exp_to_datetime(
        cls: Type["ProvenanceToken"], v: int
    ) -> datetime.datetime | None:
        """Convert the exp to a datetime object"""
        return coerce_unix_to_datetime(v)

    @property
    def is_root(self) -> bool:
        """Whether this token is the root of its causal tree."""
        return self.ptk is None

    def has_audience(self, service: str) -> bool:
        """Whether ``service`` is one of the token's target audiences."""
        return service in self.aud

    def verify_args(self, args: Any) -> bool:
        """Whether ``args`` canonically hash to this token's ``ahs``.

        Recomputes the hash using the canonicalization named by ``aha``.

        Raises
        ------
        UnsupportedCanonicalizationError
            When ``aha`` names a canonicalization this verifier cannot reproduce.
        """
        return canonical.args_hash(args, self.aha) == self.ahs
