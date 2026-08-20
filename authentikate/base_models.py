import hashlib
import json
import logging
import time
import asyncio
from typing import Callable, Coroutine, Literal, Union, Annotated, cast
import httpx
from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    field_validator,
    AliasChoices,
    Discriminator,
    FilePath,
    PrivateAttr,
)
import datetime
from typing import Dict, Any
from joserfc.jwk import KeySet, RSAKey
from authentikate.errors import JwksError, InvalidJwtTokenError


logger = logging.getLogger(__name__)


ANY_AUDIENCE = "*"
"""Configured ``audience`` value meaning "accept a token for any audience".

A property of *this service*, not of a token: it says this verifier does not care
which service a token was minted for. A token whose own ``aud`` claim contains
``"*"`` gains nothing by it -- a service configured with a literal audience still
rejects that token. Making the wildcard token-side instead would let an issuer
mint one credential valid at every service, which is exactly the cross-service
replay that audience checking exists to prevent.
"""


def coerce_aud_to_list(v: str | list[str] | None) -> list[str] | None:
    """Coerce an ``aud`` claim into a list (or None when absent)."""
    if not v:
        return None
    if isinstance(v, str):
        return [v]
    return v


def coerce_unix_to_datetime(v: int | datetime.datetime | None) -> datetime.datetime | None:
    """Coerce a unix-seconds timestamp claim into a tz-aware datetime."""
    if v is None:
        return None
    if isinstance(v, int):
        return datetime.datetime.fromtimestamp(v, tz=datetime.timezone.utc)
    return v


class JWTToken(BaseModel):
    """A JWT token

    This is a pydantic model that represents a JWT token.
    It is used to validate the token and to extract information from it.
    The token is decoded using the `decode_token` function.

    """

    model_config = ConfigDict(extra="ignore")

    sub: str
    """A unique identifier for the user (is unique for the issuer)"""
    iss: str
    """The issuer of the token"""

    exp: datetime.datetime
    """The expiration time of the token"""

    active_org: str | None = None
    """The active organization of the user, if any"""

    client_id: str
    """The client_id of the app that requested the token"""
    preferred_username: str
    """The username of the user"""
    roles: list[str]
    """The roles of the user"""
    scope: str
    """The scope of the token"""

    iat: datetime.datetime
    """The issued at time of the token"""

    aud: list[str] | None = None
    """The audience of the token"""

    jti: str | None = None
    """The unique identifier for the token"""

    raw: str
    """ The raw original token string """

    client_app: str | None = None
    """ The client app name """

    client_release: str | None = None
    """ The client release version """

    client_device: str | None = None
    """ The client device identifier """

    @field_validator("aud", mode="before")
    @classmethod
    def aud_to_list(cls, v: str | list[str] | None) -> list[str] | None:
        """Convert the aud to a list"""
        return coerce_aud_to_list(v)

    @field_validator("sub", mode="before")
    @classmethod
    def sub_to_username(cls, v: str) -> str:
        """Convert the sub to a username compatible string"""
        if isinstance(v, int):
            return str(v)
        return v

    @field_validator("iat", mode="before")
    @classmethod
    def iat_to_datetime(cls, v: int) -> datetime.datetime | None:
        """Convert the iat to a datetime object"""
        return coerce_unix_to_datetime(v)

    @field_validator("exp", mode="before")
    @classmethod
    def exp_to_datetime(cls, v: int) -> datetime.datetime | None:
        """Convert the exp to a datetime object"""
        return coerce_unix_to_datetime(v)

    @property
    def changed_hash(self) -> str:
        """A hash that changes when the user changes"""
        # Must be stable across processes and restarts (the value is persisted
        # on the user model), so the salted builtin hash() cannot be used.
        # JSON-encoded rather than "|".join: joining on a separator let a role
        # named "a|b" produce the same fingerprint as the roles ["a", "b"],
        # which could suppress the update that propagates a role change.
        fingerprint = json.dumps(
            [self.sub, self.preferred_username, sorted(self.roles), self.active_org],
            separators=(",", ":"),
        )
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    @property
    def scopes(self) -> list[str]:
        """The scopes of the token. Each scope is a string separated by a space"""
        return self.scope.split(" ")

    def has_scopes(self, scopes: list[str]) -> bool:
        """Check if the user has the given scope"""
        if not scopes:
            return True

        return all(scope in self.scopes for scope in scopes)

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if the user has any of the given roles"""
        if not roles:
            return True

        return any(role in self.roles for role in roles)

    def has_roles(self, roles: list[str]) -> bool:
        """Check if the user has the given role"""
        if not roles:
            return True

        return all(role in self.roles for role in roles)

    def has_any_scope(self, scopes: list[str]) -> bool:
        """Check if the user has any of the given scopes"""
        if not scopes:
            return True

        return any(scope in self.scopes for scope in scopes)


class StaticToken(JWTToken):
    """A static JWT token

    A pre-defined token that bypasses signature verification. Configured via
    `AuthentikateSettings.static_tokens` and intended for tests only.
    """

    sub: str
    """A unique identifier for the user (is unique for the issuer)"""
    iss: str = "static_issuer"
    """The issuer of the token"""
    iat: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    """The issued at time of the token (defaults to now, UTC)"""
    exp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=1)
    )
    """The expiration time of the token (defaults to one day from now, UTC)"""
    client_id: str = "static"
    """The client_id of the app that requested the token"""
    client_app: str = "static_app"
    """The client app name"""
    client_release: str = "v1.0.0"
    """The client release version"""
    client_device: str = "static_device"
    """The client device identifier"""
    active_org: str = "static_org"
    """The active organization of the user"""
    preferred_username: str = "static_user"
    """The username of the user"""
    scope: str = "openid profile email"
    """The space-separated scopes of the token"""
    roles: list[str] = Field(default_factory=lambda: ["admin"])
    """The roles of the user"""
    raw: str = Field(default_factory=lambda: "static_token")
    """The raw original token string"""


class Issuer(BaseModel):
    """A token issuer

    Base class for all issuer kinds. An issuer is a trusted party whose
    signing keys (JWKS) are used to verify incoming JWT tokens.
    """

    model_config = ConfigDict(extra="forbid")
    kind: str
    """The discriminator that selects the concrete issuer kind"""
    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer url (must match the iss claim of incoming tokens)"""

    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        raise NotImplementedError(
            "get_jwks not implemented. Must be implemented in subclass"
        )

    def refresh(self) -> None:
        """Refresh the issuer jwks if applicable"""
        pass


class JWKIssuer(Issuer):
    """An issuer configured with an inline JWKS document

    The full JWKS dict (with a "keys" list) is provided directly in the
    settings, so no key retrieval is needed at runtime.
    """

    kind: Literal["jwks_dict"] = Field(
        default="jwks_dict",
    )
    """The discriminator for this issuer kind"""

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer url (must match the iss claim of incoming tokens)"""

    jwks: Dict[str, Any] = Field(
        validation_alias=AliasChoices("jwks", "JWKS", "JWKS_DICT")
    )
    """The JWKS document of the issuer (a dict with a "keys" list)"""

    @field_validator("jwks", mode="before")
    @classmethod
    def validate_jwks_dict(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the jwks dict"""
        if not isinstance(v, dict):
            raise ValueError("jwks_dict must be a dict")
        if "keys" not in v:
            raise ValueError("jwks_dict must contain a keys field")
        if not isinstance(v["keys"], list):
            raise ValueError("jwks_dict keys must be a list")
        return v

    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        # validate_jwks_dict has already guaranteed "keys" exists and is a list;
        # the cast records that invariant rather than hiding an unchecked one.
        return cast(list[Dict[str, Any]], self.jwks["keys"])


class RSAKeyIssuer(Issuer):
    """An issuer configured with a single RSA public key

    The PEM-encoded public key is provided inline and exposed as a
    one-key JWKS under the configured key id.
    """

    model_config = ConfigDict(extra="forbid")
    kind: Literal["rsa"] = Field(
        default="rsa",
    )
    """The discriminator for this issuer kind"""

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer url (must match the iss claim of incoming tokens)"""
    key_id: str = Field(
        default="1", validation_alias=AliasChoices("key_id", "kid", "KID")
    )
    """The key id (kid) under which the public key is published"""
    public_key: str = Field(validation_alias=AliasChoices("public_key", "PUBLIC_KEY"))
    """The PEM-encoded RSA public key used to verify token signatures"""

    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        t = RSAKey.import_key(self.public_key)
        return [t.as_dict(kid=self.key_id)]


class RSAKeyFileIssuer(Issuer):
    """An issuer configured with an RSA public key read from a PEM file

    Like RSAKeyIssuer, but the public key is loaded from a file on disk
    each time the JWKS is requested.
    """

    model_config = ConfigDict(extra="forbid")
    kind: Literal["rsa_file"] = Field(
        default="rsa_file",
    )
    """The discriminator for this issuer kind"""

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer url (must match the iss claim of incoming tokens)"""
    key_id: str = Field(
        default="1", validation_alias=AliasChoices("key_id", "kid", "KID")
    )
    """The key id (kid) under which the public key is published"""
    public_key_pem_file: FilePath = Field(
        validation_alias=AliasChoices("public_key_pem_file", "PUBLIC_KEY_PEM_FILE")
    )
    """Path to the PEM file containing the RSA public key"""

    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""

        with open(self.public_key_pem_file, "rb") as f:
            public_key = f.read()

        t = RSAKey.import_key(public_key)
        return [t.as_dict(kid=self.key_id)]


class JWKSUriIssuer(Issuer):
    """An issuer whose JWKS is fetched from a remote endpoint

    The JWKS document is retrieved from the configured uri on first use and
    cached; it is re-fetched when an unknown key id is encountered.
    """

    model_config = ConfigDict(extra="forbid")
    kind: Literal["jwks_uri"] = Field(
        default="jwks_uri",
    )
    """The discriminator for this issuer kind"""

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer url (must match the iss claim of incoming tokens)"""
    jwks_uri: str = Field(validation_alias=AliasChoices("jwks_uri", "JWKS_URI"))
    """The url of the remote JWKS endpoint (e.g. .../.well-known/jwks.json)"""
    min_refresh_interval: float = Field(
        default=10.0,
        validation_alias=AliasChoices(
            "min_refresh_interval", "MIN_REFRESH_INTERVAL"
        ),
    )
    """Minimum seconds between two JWKS *refreshes*.

    An unknown ``kid`` triggers a refresh so a rotated key is picked up
    promptly. Without a floor, a caller presenting a stream of made-up ``kid``s
    would drive one live request to the issuer per inbound request. The initial
    load is never throttled, and neither is the first refresh after it, so key
    rotation is still picked up immediately.
    """
    _cache: list[Dict[str, Any]] | None = PrivateAttr(default=None)
    _cache_lock: asyncio.Lock = PrivateAttr(default_factory=asyncio.Lock)
    _last_refresh: float | None = PrivateAttr(default=None)

    def _run_blocking(self, factory: Callable[[], Coroutine[Any, Any, Any]]) -> None:
        """Run one of this issuer's coroutines from synchronous code."""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(factory())
            return

        raise JwksError(
            "Cannot refresh JWKS synchronously while an event loop is running; use arefresh instead"
        )

    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""

        if self._cache is None:
            # The initial load is not a refresh, and must not consume the
            # refresh budget -- otherwise the first unknown kid after startup
            # would be throttled and a rotated key missed.
            self._run_blocking(self.aget_as_jwks)

        return cast(list[Dict[str, Any]], self._cache)

    async def aget_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer without blocking the event loop."""

        if self._cache is None:
            async with self._cache_lock:
                if self._cache is None:
                    await self._fetch_jwks()

        return cast(list[Dict[str, Any]], self._cache)

    def refresh(self) -> None:
        """Refresh the jwks from the uri"""

        self._run_blocking(self.arefresh)

    async def arefresh(self) -> None:
        """Refresh the jwks from the uri without blocking the event loop.

        Rate-limited to one refresh per ``min_refresh_interval``; when a refresh
        is skipped the existing cache is kept, so an unresolvable ``kid`` simply
        fails verification instead of hitting the issuer again.
        """

        async with self._cache_lock:
            now = time.monotonic()
            if (
                self._last_refresh is not None
                and now - self._last_refresh < self.min_refresh_interval
            ):
                logger.debug(
                    "Skipping JWKS refresh for %s: refreshed %.1fs ago",
                    self.jwks_uri,
                    now - self._last_refresh,
                )
                return

            self._last_refresh = now
            await self._fetch_jwks()

    async def _fetch_jwks(self) -> None:
        """Fetch and cache the JWKS document from the issuer."""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.jwks_uri)
                response.raise_for_status()
                data = response.json()
                self._cache = data["keys"]
        except Exception as e:
            raise JwksError(f"Error fetching jwks from {self.jwks_uri}") from e


IssuerUnion = Annotated[
    Union[JWKIssuer, RSAKeyIssuer, RSAKeyFileIssuer, JWKSUriIssuer],
    Discriminator("kind"),
]


def _index_issuer_keys(iss: str, keys: list[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Validate and index a *single* issuer's keys by ``kid``.

    ``kid``s only need to be unique within one issuer: a token is verified
    against the keys of the one issuer its ``iss`` claim names, never against a
    set merged across issuers. Two issuers may therefore safely publish the same
    ``kid`` -- which they do by default, since ``RSAKeyIssuer.key_id`` and
    ``RSAKeyFileIssuer.key_id`` both default to ``"1"``.
    """

    if not isinstance(keys, list):
        raise JwksError(f"keys of issuer {iss!r} must be a list")

    indexed: Dict[str, Dict[str, Any]] = {}

    for key in keys:
        kid = key.get("kid")
        if kid is None:
            raise JwksError(f"key of issuer {iss!r} must contain a kid field")

        if kid in indexed:
            raise JwksError(f"Duplicate kid {kid!r} in jwks of issuer {iss!r}")

        indexed[kid] = key

    if not indexed:
        raise JwksError(f"No keys found in jwks of issuer {iss!r}")

    return indexed


async def _aget_issuer_jwks(issuer: IssuerUnion) -> list[Dict[str, Any]]:
    """Get one issuer's JWKS, without blocking the loop on a remote fetch."""

    if isinstance(issuer, JWKSUriIssuer):
        return await issuer.aget_as_jwks()
    return issuer.get_as_jwks()


def _collect_jwks(issuers: list[IssuerUnion]) -> list[Dict[str, Any]]:
    """Collect the validated keys of every issuer (blocking).

    For introspection only. Verification never uses a merged set -- it resolves
    keys against a single issuer via :func:`_resolve_issuer_key_set`.
    """

    merged: list[Dict[str, Any]] = []
    for issuer in issuers:
        merged.extend(_index_issuer_keys(issuer.iss, issuer.get_as_jwks()).values())
    return merged


async def _acollect_jwks(issuers: list[IssuerUnion]) -> list[Dict[str, Any]]:
    """Collect the validated keys of every issuer without blocking the loop."""

    merged: list[Dict[str, Any]] = []
    for issuer in issuers:
        keys = await _aget_issuer_jwks(issuer)
        merged.extend(_index_issuer_keys(issuer.iss, keys).values())
    return merged


def _find_issuer(issuers: list[IssuerUnion], iss: str) -> IssuerUnion:
    """Select the configured issuer named by a token's ``iss`` claim.

    Runs before any signature check and before any network I/O. Reading ``iss``
    unverified is safe here because it only *selects* a trust anchor -- the
    signature is what proves the token actually came from that issuer, and
    :func:`authentikate.decode._validate_claims` re-checks ``iss`` against the
    selected issuer afterwards. Rejecting up front also means an unknown issuer
    can never trigger an outbound JWKS fetch.
    """

    for issuer in issuers:
        if issuer.iss == iss:
            return issuer

    raise InvalidJwtTokenError(f"Untrusted issuer: {iss!r}")


def _resolve_issuer_key_set(issuer: IssuerUnion, kid: str) -> KeySet:
    """Resolve a KeySet of ``issuer``'s keys only, refreshing on a miss."""

    keys = _index_issuer_keys(issuer.iss, issuer.get_as_jwks())

    if kid not in keys:
        issuer.refresh()
        keys = _index_issuer_keys(issuer.iss, issuer.get_as_jwks())

    return KeySet.import_key_set({"keys": list(keys.values())})


async def _aresolve_issuer_key_set(issuer: IssuerUnion, kid: str) -> KeySet:
    """Resolve a KeySet of ``issuer``'s keys only, without blocking the loop."""

    keys = _index_issuer_keys(issuer.iss, await _aget_issuer_jwks(issuer))

    if kid not in keys:
        if isinstance(issuer, JWKSUriIssuer):
            await issuer.arefresh()
        else:
            issuer.refresh()
        keys = _index_issuer_keys(issuer.iss, await _aget_issuer_jwks(issuer))

    return KeySet.import_key_set({"keys": list(keys.values())})


ASYMMETRIC_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "Ed25519",
    "Ed448",
    "EdDSA",
]
"""Every asymmetric signature algorithm joserfc supports.

The default auth-token allow-list. What pinning has to exclude is the *symmetric*
family (``HS*``) and ``none``: with those permitted, an attacker can take the
issuer's public key -- which is public by definition -- and use it as an HMAC
secret, or drop the signature altogether. Narrowing further to the single
algorithm your issuer actually uses is better still (RFC 8725 §3.1) and is what
the ``ALGORITHMS`` setting is for; it is not the default only because it would
break every deployment whose issuer does not sign with RS256.
"""


def reject_unsafe_algorithms(algorithms: list[str]) -> list[str]:
    """Pin the alg per RFC 8725: forbid an empty list and the ``none`` alg.

    An empty allow-list or ``alg: none`` would let an attacker present an
    unsigned (or arbitrarily-signed) token, defeating the whole point of
    verification. Shared by the auth and provenance settings.
    """
    if not algorithms:
        raise ValueError("algorithms must not be empty")
    if any(alg.strip().lower() == "none" for alg in algorithms):
        raise ValueError("The 'none' algorithm is not allowed")
    return algorithms


class ProvenanceSettings(BaseModel):
    """Configuration for verifying inbound provenance tokens.

    Provenance tokens are an orthogonal trust domain to the auth token: a
    different issuer (Rekuest), a different signing algorithm (Ed25519), and a
    different JWKS endpoint. This block scopes those issuers separately so a
    provenance token is never verified against an auth issuer and vice versa.
    """

    model_config = ConfigDict(extra="forbid")

    issuers: list[IssuerUnion] = Field(
        validation_alias=AliasChoices("issuers", "ISSUERS")
    )
    """The trusted provenance issuers (typically one JWKSUriIssuer at Rekuest)."""
    audience: str = Field(validation_alias=AliasChoices("audience", "AUDIENCE"))
    """This service's identifier (e.g. "mikro"); checked against the token aud.

    Required, so the choice is always deliberate: a provenance token exists to
    attest *which service* a unit of work was scoped to, and accepting one with an
    unchecked audience would defeat its purpose. Set it to :data:`ANY_AUDIENCE`
    (``"*"``) to accept a provenance token scoped to any service -- you still have
    to write it down.
    """
    algorithms: list[str] = Field(
        default_factory=lambda: ["Ed25519"],
        validation_alias=AliasChoices("algorithms", "ALGORITHMS"),
    )
    """The signature algorithms allowed for provenance tokens (alg is pinned)."""

    @field_validator("algorithms")
    @classmethod
    def check_algorithms(cls, v: list[str]) -> list[str]:
        """Reject an empty allow-list or the ``none`` alg (RFC 8725)."""
        return reject_unsafe_algorithms(v)

    def get_jwks(self) -> list[Dict[str, Any]]:
        """Get the merged jwks of all provenance issuers."""
        return _collect_jwks(self.issuers)

    async def aget_jwks(self) -> list[Dict[str, Any]]:
        """Get the merged jwks of all provenance issuers without blocking."""
        return await _acollect_jwks(self.issuers)

    def resolve_key_set(self, iss: str, kid: str) -> KeySet:
        """Resolve the verification keys of the provenance issuer named by ``iss``."""
        return _resolve_issuer_key_set(_find_issuer(self.issuers, iss), kid)

    async def aresolve_key_set(self, iss: str, kid: str) -> KeySet:
        """Resolve the keys of the issuer named by ``iss`` without blocking."""
        return await _aresolve_issuer_key_set(_find_issuer(self.issuers, iss), kid)


class AuthentikateSettings(BaseModel):
    """The settings for authentikate

    This is a pydantic model that represents the settings for authentikate.
    It is used to configure the library.
    """

    model_config = ConfigDict(extra="forbid")

    issuers: list[IssuerUnion] = Field(
        validation_alias=AliasChoices(
            "issuers",
            "iss",
            "issuer",
            "issuer_url",
            "ISSUERS",
        )
    )
    """The trusted issuers whose keys are used to verify incoming tokens"""
    authorization_headers: list[str] = Field(
        default_factory=lambda: [
            "Authorization",
            "X-Authorization",
            "AUTHORIZATION",
            "authorization",
        ],
        validation_alias=AliasChoices(
            "authorization_headers", "AUTHORIZATION_HEADERS", "AUTHORIZATION_HEADERS"
        ),
    )
    """The request header names that are searched (in order) for a Bearer token"""
    provenance_header: list[str] = Field(
        default_factory=lambda: [
            # The provenance token is delivered under the Rekuest task header
            # (the legacy plaintext task payload is gone). ASGI servers deliver
            # header names lowercased, so the lowercase variants must be
            # included; the provenance-token names are kept as a fallback.
            "rekuest-task",
            "x-rekuest-task",
            "Rekuest-Task",
            "X-Rekuest-Task",
            "REKUEST_TASK",
            "rekuest_task",
            "provenance-token",
            "x-provenance-token",
            "Provenance-Token",
            "X-Provenance-Token",
            "PROVENANCE_TOKEN",
            "provenance_token",
        ],
        validation_alias=AliasChoices("provenance_header", "PROVENANCE_HEADER"),
    )
    """The request header names that are searched (in order) for a provenance token"""
    static_tokens: dict[str, StaticToken] = Field(
        default_factory=dict,
        validation_alias=AliasChoices(
            "static_tokens", "STATIC_TOKENS", "STATIC_TOKENS"
        ),
    )
    """A map of static tokens to their decoded values. Should only be used in tests."""
    provenance: ProvenanceSettings | None = Field(
        default=None,
        validation_alias=AliasChoices("provenance", "PROVENANCE"),
    )
    """Configuration for verifying inbound provenance tokens (None disables it)."""
    audience: str | None = Field(
        default=None, validation_alias=AliasChoices("audience", "AUDIENCE")
    )
    """This service's identifier; checked against the token's ``aud`` claim.

    Optional for now so existing deployments keep working, but strongly
    recommended: without it, a token the IdP minted for *any* service is accepted
    by this one. ``prepare_settings`` warns when it is unset, and it becomes
    required in 4.0.

    Set it to :data:`ANY_AUDIENCE` (``"*"``) to accept any audience deliberately.
    That is the same security posture as leaving it unset, but it reads as a
    decision rather than an oversight, and it will still satisfy the 4.0
    requirement.
    """
    algorithms: list[str] = Field(
        default_factory=lambda: list(ASYMMETRIC_ALGORITHMS),
        validation_alias=AliasChoices("algorithms", "ALGORITHMS"),
    )
    """The signature algorithms allowed for auth tokens.

    Defaults to every asymmetric algorithm, which blocks the ``HS*``/``none``
    confusion attacks. Narrow it to the one your issuer uses -- see
    :data:`ASYMMETRIC_ALGORITHMS`.
    """
    allowed_organizations: list[str] | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "allowed_organizations", "ALLOWED_ORGANIZATIONS"
        ),
    )
    """Organizations this service accepts, or None to accept whatever the token names.

    Without it, every distinct ``active_org`` claim auto-creates an Organization
    and a Membership, making token claims an unbounded write primitive.
    """
    allow_static_tokens_in_production: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "allow_static_tokens_in_production", "ALLOW_STATIC_TOKENS_IN_PRODUCTION"
        ),
    )
    """Escape hatch to permit ``static_tokens`` while ``DEBUG`` is False."""

    @field_validator("algorithms")
    @classmethod
    def check_algorithms(
        cls, v: list[str]
    ) -> list[str]:
        """Reject an empty allow-list or the ``none`` alg (RFC 8725)."""
        return reject_unsafe_algorithms(v)

    def get_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""

        return _collect_jwks(self.issuers)

    async def aget_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer without blocking the event loop."""

        return await _acollect_jwks(self.issuers)

    def resolve_key_set(self, iss: str, kid: str) -> KeySet:
        """Resolve the verification keys of the issuer named by ``iss``.

        Scoped to that one issuer, so a token can only ever be verified against
        the keys of the issuer it claims to come from.
        """

        return _resolve_issuer_key_set(_find_issuer(self.issuers, iss), kid)

    async def aresolve_key_set(self, iss: str, kid: str) -> KeySet:
        """Resolve the keys of the issuer named by ``iss`` without blocking."""

        return await _aresolve_issuer_key_set(_find_issuer(self.issuers, iss), kid)
