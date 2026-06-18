import hashlib
import logging
import asyncio
from typing import Literal, Type, Union, Annotated, cast
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
from joserfc.jwk import GuestProtocol
from authentikate.errors import JwksError, MalformedJwtTokenError


logger = logging.getLogger(__name__)


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
    def aud_to_list(
        cls: Type["JWTToken"], v: str | list[str] | None
    ) -> list[str] | None:
        """Convert the aud to a list"""
        return coerce_aud_to_list(v)

    @field_validator("sub", mode="before")
    def sub_to_username(cls: Type["JWTToken"], v: str) -> str:
        """Convert the sub to a username compatible string"""
        if isinstance(v, int):
            return str(v)
        return v

    @field_validator("iat", mode="before")
    def iat_to_datetime(
        cls: Type["JWTToken"], v: int
    ) -> datetime.datetime | None:
        """Convert the iat to a datetime object"""
        return coerce_unix_to_datetime(v)

    @field_validator("exp", mode="before")
    def exp_to_datetime(
        cls: Type["JWTToken"], v: int
    ) -> datetime.datetime | None:
        """Convert the exp to a datetime object"""
        return coerce_unix_to_datetime(v)

    @property
    def changed_hash(self) -> str:
        """A hash that changes when the user changes"""
        # Must be stable across processes and restarts (the value is persisted
        # on the user model), so the salted builtin hash() cannot be used.
        fingerprint = "|".join(
            [self.sub, self.preferred_username, *self.roles, self.active_org or ""]
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


class ImitationRequest(BaseModel):
    """An imitation request

    Identifies the user (by sub and iss) that should be imitated.
    """

    sub: str
    """The sub claim of the user to imitate"""
    iss: str
    """The issuer of the user to imitate"""


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
    def validate_jwks_dict(cls: Type["JWKIssuer"], v: Dict[str, Any]) -> Dict[str, Any]:
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
        return self.jwks["keys"]


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
    _cache: list[Dict[str, Any]] | None = PrivateAttr(default=None)
    _cache_lock: asyncio.Lock = PrivateAttr(default_factory=asyncio.Lock)

    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""

        if self._cache is None:
            self.refresh()

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

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.arefresh())
            return

        raise JwksError(
            "Cannot refresh JWKS synchronously while an event loop is running; use arefresh instead"
        )

    async def arefresh(self) -> None:
        """Refresh the jwks from the uri without blocking the event loop."""

        async with self._cache_lock:
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


def _merge_jwks(
    jwks_by_issuer: list[list[Dict[str, Any]]],
) -> list[Dict[str, Any]]:
    """Validate and merge the keys returned by a set of issuers.

    Rejects duplicate or missing ``kid``s, since key resolution is by ``kid``.
    """

    merged_jwks: Dict[str, Dict[str, Any]] = {}

    for keys in jwks_by_issuer:
        if not isinstance(keys, list):
            raise JwksError("keys must be a list")

        for key in keys:
            if key.get("kid") is None:
                raise JwksError("key must contain a kid field")

            if key["kid"] in merged_jwks:
                raise JwksError(f"Duplicate kid found: {key['kid']}")

            merged_jwks[key["kid"]] = key

    if not merged_jwks:
        raise JwksError("No keys found in jwks")

    return list(merged_jwks.values())


def _collect_jwks(issuers: list[IssuerUnion]) -> list[Dict[str, Any]]:
    """Collect and merge the JWKS of every issuer (blocking)."""

    return _merge_jwks([issuer.get_as_jwks() for issuer in issuers])


async def _acollect_jwks(issuers: list[IssuerUnion]) -> list[Dict[str, Any]]:
    """Collect and merge the JWKS of every issuer without blocking the loop."""

    jwks_by_issuer = []
    for issuer in issuers:
        if isinstance(issuer, JWKSUriIssuer):
            jwks_by_issuer.append(await issuer.aget_as_jwks())
        else:
            jwks_by_issuer.append(issuer.get_as_jwks())

    return _merge_jwks(jwks_by_issuer)


def _resolve_key_set(issuers: list[IssuerUnion], kid: str | None) -> KeySet:
    """Resolve a KeySet for ``kid``, refreshing issuers on a miss (blocking)."""

    if not kid:
        raise MalformedJwtTokenError("Missing kid in header")

    jwks = _collect_jwks(issuers)

    if not any(key.get("kid") == kid for key in jwks):
        for issuer in issuers:
            issuer.refresh()
        jwks = _collect_jwks(issuers)

    return KeySet.import_key_set({"keys": jwks})


async def _aresolve_key_set(issuers: list[IssuerUnion], kid: str) -> KeySet:
    """Resolve a KeySet for ``kid``, refreshing issuers on a miss (async)."""

    jwks = await _acollect_jwks(issuers)

    if not any(key.get("kid") == kid for key in jwks):
        for issuer in issuers:
            if isinstance(issuer, JWKSUriIssuer):
                await issuer.arefresh()
            else:
                issuer.refresh()
        jwks = await _acollect_jwks(issuers)

    return KeySet.import_key_set({"keys": jwks})


class ProvenanceSettings(BaseModel):
    """Configuration for verifying inbound provenance tokens.

    Provenance tokens are an orthogonal trust domain to the auth token: a
    different issuer (Rekuest), a different signing algorithm (EdDSA), and a
    different JWKS endpoint. This block scopes those issuers separately so a
    provenance token is never verified against an auth issuer and vice versa.
    """

    model_config = ConfigDict(extra="forbid")

    issuers: list[IssuerUnion] = Field(
        validation_alias=AliasChoices("issuers", "ISSUERS")
    )
    """The trusted provenance issuers (typically one JWKSUriIssuer at Rekuest)."""
    audience: str | None = Field(
        default=None, validation_alias=AliasChoices("audience", "AUDIENCE")
    )
    """This service's identifier (e.g. "mikro"); checked against the token aud."""
    algorithms: list[str] = Field(
        default_factory=lambda: ["EdDSA"],
        validation_alias=AliasChoices("algorithms", "ALGORITHMS"),
    )
    """The signature algorithms allowed for provenance tokens (alg is pinned)."""

    @field_validator("algorithms")
    def reject_unsafe_algorithms(cls: Type["ProvenanceSettings"], v: list[str]) -> list[str]:
        """Pin the alg per RFC 8725: forbid an empty list and the ``none`` alg.

        An empty allow-list or ``alg: none`` would let an attacker present an
        unsigned (or arbitrarily-signed) provenance token, defeating the whole
        point of verification.
        """
        if not v:
            raise ValueError("Provenance algorithms must not be empty")
        if any(alg.strip().lower() == "none" for alg in v):
            raise ValueError("The 'none' algorithm is not allowed for provenance tokens")
        return v

    def get_jwks(self) -> list[Dict[str, Any]]:
        """Get the merged jwks of all provenance issuers."""
        return _collect_jwks(self.issuers)

    async def aget_jwks(self) -> list[Dict[str, Any]]:
        """Get the merged jwks of all provenance issuers without blocking."""
        return await _acollect_jwks(self.issuers)

    def load_key(self, obj: GuestProtocol) -> KeySet:
        """Resolve the key set from a JWS header (joserfc callable resolver)."""
        return _resolve_key_set(self.issuers, obj.headers().get("kid"))

    async def aload_key(self, kid: str) -> KeySet:
        """Resolve the key set for a given key id without blocking the loop."""
        return await _aresolve_key_set(self.issuers, kid)


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

    def get_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""

        return _collect_jwks(self.issuers)

    async def aget_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer without blocking the event loop."""

        return await _acollect_jwks(self.issuers)

    def load_key(self, obj: GuestProtocol) -> KeySet:
        """Resolve the key from the header"""

        return _resolve_key_set(self.issuers, obj.headers().get("kid"))

    async def aload_key(self, kid: str) -> KeySet:
        """Resolve the key set for a given key id without blocking the event loop."""

        return await _aresolve_key_set(self.issuers, kid)
