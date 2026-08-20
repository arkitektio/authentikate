# Authentikate — Usage & Configuration

Authentikate is a Django library for validating OAuth2 self-encoded (JWT) access
tokens and turning them into Django users, OAuth2 clients, organizations and
memberships. It also verifies **provenance tokens** (EdDSA-signed work
attestations minted by Rekuest) on the consuming/audience end.

This document covers installation, the full settings shape, and the public API.

---

## 1. Installation & Django wiring

Authentikate is a Django app and ships a custom user model. Add it to
`INSTALLED_APPS`, wire up Guardian for object-level permissions, and point
`AUTH_USER_MODEL` at the bundled user.

```python
INSTALLED_APPS = [
    # ...
    "guardian",          # required for object-level permissions
    "authentikate",
]

AUTH_USER_MODEL = "authentikate.User"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
]
```

Everything else is configured through a single `AUTHENTIKATE` dict in your
Django settings.

> **Keys are case-insensitive.** Every settings key accepts both an uppercase
> (`ISSUERS`, `STATIC_TOKENS`, `PROVENANCE`) and a lowercase (`issuers`,
> `static_tokens`, `provenance`) form. The uppercase form is the convention in
> Django settings; the examples below use it.

---

### Importing

The common names are available from the package root:

```python
from authentikate import (
    authenticate_header,     # authenticate a request's headers
    JWTToken,                # the decoded token
    get_user, get_membership,  # the current principal, within a request
    AuthentikatePermissionDenied,
)
```

`authentikate.__all__` lists the full public surface. Anything outside it is an
implementation detail and may move between releases. The package ships a
`py.typed` marker, so these names carry their annotations into your own type
checking.

---

## 2. The `AUTHENTIKATE` settings dict

The dict is validated by the `AuthentikateSettings` pydantic model
(`authentikate/base_models.py`). **Extra keys are rejected** (`extra="forbid"`),
so a typo raises `ImproperlyConfigured` at startup rather than failing silently.

| Key | Type | Required | Default | Purpose |
|-----|------|----------|---------|---------|
| `ISSUERS` | list of issuer dicts | **yes** | — | Trusted issuers whose keys verify incoming auth tokens. |
| `AUTHORIZATION_HEADERS` | list of strings | no | `["Authorization", "X-Authorization", "AUTHORIZATION", "authorization"]` | Header names searched (in order) for a `Bearer` token. |
| `PROVENANCE_HEADER` | list of strings | no | Rekuest task + provenance-token header variants | Header names searched (in order) for a provenance token. |
| `STATIC_TOKENS` | map of `str → token dict` | no | `{}` | Hard-coded tokens that bypass signature verification. **Tests only** — refused when `DEBUG` is `False`. |
| `PROVENANCE` | provenance dict | no | `None` | Configuration for verifying inbound provenance tokens. `None` disables provenance verification. |
| `AUDIENCE` | string | no | `None` | This service's identifier, checked against the token's `aud`. **Strongly recommended**; see below. Becomes required in 4.0. |
| `ALGORITHMS` | list of strings | no | every asymmetric algorithm | Allowed signature algorithms. The default blocks the `HS*`/`none` confusion attacks; narrow it to the one your issuer uses (RFC 8725 §3.1). An empty list and `none` are rejected. |
| `ALLOWED_ORGANIZATIONS` | list of strings | no | `None` | Organizations this service accepts. `None` accepts whatever the token names. |
| `ALLOW_STATIC_TOKENS_IN_PRODUCTION` | bool | no | `False` | Escape hatch permitting `STATIC_TOKENS` while `DEBUG` is `False`. |

### Minimal example

```python
AUTHENTIKATE = {
    "ISSUERS": [
        {
            "kind": "jwks_uri",
            "iss": "https://lok.my-org.com",
            "jwks_uri": "https://lok.my-org.com/.well-known/jwks.json",
        }
    ],
}
```

### Audience (`AUDIENCE`) — strongly recommended

A token is only ever verified against the keys of the issuer named by its `iss`
claim, so one issuer can never mint a token for another. What signature checking
alone cannot tell you is *which service* a token was meant for: without
`AUDIENCE`, a token your IdP minted for any other service is accepted here.

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "AUDIENCE": "mikro",   # this service's identifier
}
```

When set, `aud` becomes an essential claim and must contain this value (a
list-valued `aud` matches on membership, so a token scoped to several services is
valid at each of them). When unset, a warning is logged at startup and `aud` is
not checked — this is for backwards compatibility only and becomes an error in
4.0.

### Organization allow-list (`ALLOWED_ORGANIZATIONS`)

`Organization` and `Membership` rows are created on demand from the token's
`active_org` claim. Unless you constrain it, every distinct value the issuer
emits creates rows:

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "ALLOWED_ORGANIZATIONS": ["acme", "beta-corp"],
}
```

A token naming anything else is rejected with `OrganizationNotAllowed` before any
database write.

This is enforced on the `authenticate_*` entry points in `authentikate.utils`
(and therefore by the Strawberry extension), which is where settings are in
hand. If you drive `adecode_token` and `aexpand_token_context` yourself (§7),
the allow-list is not consulted — check it yourself, or go through
`authenticate_token`.

---

## 3. Issuers (`ISSUERS`)

`ISSUERS` is a list of issuer configs. Each entry is a **discriminated union**
keyed on `kind` — the `kind` field selects which issuer type is being
configured. Every issuer needs an `iss` (the issuer URL, which must match the
`iss` claim of incoming tokens; aliases: `iss`, `issuer`, `issuer_url`).

Keys collected from all issuers are merged by `kid`. **Duplicate or missing
`kid`s raise an error** — a token's header `kid` is how the right key is found.

There are four issuer kinds:

### `jwks_uri` — remote JWKS endpoint (recommended for production)

The JWKS document is fetched from `jwks_uri` on first use, cached, and re-fetched
when an unknown `kid` is encountered. This is the only kind that does async
network I/O; the async decode path (`adecode_token`) fetches without blocking the
event loop.

```python
{
    "kind": "jwks_uri",
    "iss": "https://lok.my-org.com",
    "jwks_uri": "https://lok.my-org.com/.well-known/jwks.json",
}
```

### `jwks_dict` — inline JWKS document

The full JWKS dict (a `{"keys": [...]}` object) is provided inline; no retrieval
at runtime.

```python
{
    "kind": "jwks_dict",
    "iss": "https://lok.my-org.com",
    "jwks": {"keys": [ { "kid": "1", "kty": "RSA", "n": "...", "e": "AQAB" } ]},
}
```

### `rsa` — inline RSA public key

A single PEM-encoded RSA public key, exposed as a one-key JWKS under `key_id`.

```python
{
    "kind": "rsa",
    "iss": "lok",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "key_id": "1",   # optional, defaults to "1" (aliases: key_id, kid)
}
```

### `rsa_file` — RSA public key from a PEM file

Like `rsa`, but the key is read from a file on disk each time the JWKS is
requested. The path must exist at startup (validated as a `FilePath`).

```python
{
    "kind": "rsa_file",
    "iss": "lok",
    "public_key_pem_file": "public_key.pem",
    "key_id": "1",   # optional
}
```

---

## 4. Static tokens (`STATIC_TOKENS`)

Static tokens are hard-coded tokens that **bypass signature verification**. They
are matched by exact string against the presented token and are intended for
tests and local development only — never production.

The map is `token_string → claim dict`. Every field of the resulting
`StaticToken` has a sensible default, so a static token can be as small as a
`sub`/`iss` pair:

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "STATIC_TOKENS": {
        "my-test-token": {
            "sub": "1",
            "iss": "lok",
            # all of the following are optional, defaults shown:
            # "client_id": "static",
            # "preferred_username": "static_user",
            # "scope": "openid profile email",
            # "roles": ["admin"],   # <- note the default is admin
            # "active_org": "static_org",
            # "client_app": "static_app",
            # "client_release": "v1.0.0",
            # "client_device": "static_device",
        }
    },
}
```

A request presenting `Authorization: Bearer my-test-token` is then authenticated
as that user without any cryptographic check.

Two guards apply:

- **Refused outside development.** A non-empty `STATIC_TOKENS` while
  `DEBUG` is `False` raises `ImproperlyConfigured` at startup. Set
  `ALLOW_STATIC_TOKENS_IN_PRODUCTION` to override this deliberately.
- **`exp` is honoured.** A static token past its expiry is rejected with
  `AuthentikateTokenExpired`, so a short-lived one really is short-lived.

Note the default `roles` is `["admin"]` — set it explicitly unless you mean it.

---

## 5. Provenance (`PROVENANCE`)

Provenance tokens are a **separate trust domain** from auth tokens: a different
issuer (Rekuest), a different algorithm (EdDSA), and a different JWKS endpoint. A
provenance token attests *who caused a unit of work, and with which inputs*. The
`PROVENANCE` block scopes its issuers separately, so a provenance token is never
verified against an auth issuer and vice versa. Omit the block (or set `None`) to
disable provenance entirely.

| Key | Type | Required | Default | Purpose |
|-----|------|----------|---------|---------|
| `ISSUERS` | list of issuer dicts | **yes** | — | Trusted provenance issuers (same issuer shapes as §3; typically one `jwks_uri` at Rekuest). |
| `AUDIENCE` | string | **yes** | — | This service's identifier (e.g. `"mikro"`), checked against the token's `aud`. Required: a provenance token exists to attest which service a unit of work was scoped to. |
| `ALGORITHMS` | list of strings | no | `["Ed25519"]` | Allowed signature algorithms. The algorithm is pinned per RFC 8725: an empty list and the `none` algorithm are rejected. |

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "PROVENANCE": {
        "ISSUERS": [
            {
                "kind": "jwks_uri",
                "iss": "https://rekuest.my-org.com",
                "jwks_uri": "https://rekuest.my-org.com/.well-known/provenance-jwks.json",
            }
        ],
        "AUDIENCE": "mikro",
    },
}
```

---

## 6. Authenticating requests

The high-level entry points live in `authentikate.utils`. They are async and, by
default, pull settings from Django via `get_settings()`.

```python
from authentikate.utils import (
    authenticate_header,          # raises on failure
    authenticate_header_or_none,  # returns None on AuthentikatePermissionDenied
    authenticate_token,           # authenticate a raw token string
    authenticate_token_or_none,
)

async def my_view(request):
    token = await authenticate_header_or_none(dict(request.headers))
    if token:
        token.sub                 # subject (user id, unique per issuer)
        token.preferred_username  # username
        token.client_id           # OAuth2 client that requested the token
        token.scopes              # list[str], split from the space-separated `scope`
        token.roles               # list[str]
        token.active_org          # active organization slug (or None)
```

`authenticate_header` walks `AUTHORIZATION_HEADERS` in order, extracts the
`Bearer <token>` value, then either matches a static token or verifies the JWT.

### The decoded token (`JWTToken`)

`JWTToken` carries the standard claims plus convenience helpers:

| Method | Returns |
|--------|---------|
| `has_scopes(scopes)` | `True` if **all** scopes are present |
| `has_any_scope(scopes)` | `True` if **any** scope is present |
| `has_roles(roles)` | `True` if **all** roles are present |
| `has_any_role(roles)` | `True` if **any** role is present |

(Each returns `True` for an empty input list.)

---

## 7. Expanding tokens into Django models

A verified token can be materialized into database records via
`authentikate.expand`. Sync and async variants exist; the async ones are prefixed
`a`.

```python
from authentikate.expand import aexpand_token_context

ctx = await aexpand_token_context(token)
ctx.user          # authentikate.User    (get-or-created from sub + iss)
ctx.client        # authentikate.Client  (OAuth2 client, with release/device)
ctx.organization  # authentikate.Organization (from active_org)
ctx.membership    # authentikate.Membership   (user ⇄ org, mirrors roles)
```

Individual expanders are also available:
`aexpand_user_from_token`, `aexpand_client_from_token`,
`aexpand_organization_from_token`, `aexpand_membership`. A blocked membership
raises `BlockedMembership`, and a token without `active_org` raises
`MissingActiveOrganization`.

> **Changed in 3.0 — token roles are no longer mirrored onto Django `Group`s.**
> Mirroring meant any IdP role name that happened to match a locally managed,
> permission-bearing group silently granted those permissions. Roles now live on
> the token and on `Membership.roles`, and are enforced in the Strawberry layer
> (see §8). If you relied on the auto-created groups, replace those checks with
> `AuthExtension(roles=...)` or `AuthExtension(org_roles=...)`.

Revocation note: deleting a `Membership` does **not** revoke access — it is
recreated from the token on the next request. Set `blocked=True` instead; that is
the one authorization control in this library that the issuer cannot override.

---

## 8. GraphQL / Strawberry integration

Authentikate ships a Strawberry schema extension (it expects the
[Kante](https://github.com/jhnnsrs/kante) GraphQL layer for request context).

```python
import strawberry
from authentikate.strawberry import AuthentikateExtension, AuthExtension, AuthSubscribeExtension

schema = strawberry.Schema(
    query=Query,
    extensions=[AuthentikateExtension],
)
```

`AuthentikateExtension` authenticates each operation (HTTP via headers,
WebSocket via `connection_params["token"]`), expands the token context, and
stashes the token, user, client, organization and membership on the request and
in context vars. When `PROVENANCE` is configured, it also decodes the provenance
header **fail-closed**: if no provenance header is present the request proceeds
unprovenanced, but a provenance token that *is* present yet fails validation
raises `ProvenanceValidationError` and fails the whole operation (rather than
being silently ignored). It also binds the provenance token's actor to the auth
token presenting it (`verify_actor`), so a valid provenance token minted for a
different agent cannot be replayed under someone else's credentials. Both the
HTTP and WebSocket paths do this; over WebSocket the provenance token is read
from `connection_params` under the same names as the HTTP header.

> Single-use `jti` enforcement still needs a datastore and remains **your**
> responsibility — the `jti` claim is exposed on `ProvenanceToken` for that.

### Per-field auth with `AuthExtension`

```python
import strawberry
from authentikate.strawberry import AuthExtension

@strawberry.type
class Query:
    @strawberry.field(extensions=[AuthExtension(scopes=["read:users"])])
    def users(self, info) -> list[User]: ...

    @strawberry.field(extensions=[AuthExtension(roles=["admin"])])
    def secret(self, info) -> str: ...

    # "any of" variants
    @strawberry.field(extensions=[AuthExtension(any_scope_of=["read:a", "read:b"])])
    def either(self, info) -> str: ...
```

    # org-scoped roles: checked against Membership.roles for the request's
    # active organization, rather than the token's global roles
    @strawberry.field(extensions=[AuthExtension(org_roles=["owner"])])
    def billing(self, info) -> str: ...
```

`AuthExtension` accepts:

| Argument | Checked against | Passes when |
|----------|-----------------|-------------|
| `scopes` | token `scope` | all are present |
| `any_scope_of` | token `scope` | any is present |
| `roles` | token `roles` (global) | all are present |
| `any_role_of` | token `roles` (global) | any is present |
| `org_roles` | `Membership.roles` for the active org | all are present |
| `any_org_role_of` | `Membership.roles` for the active org | any is present |

`scopes`, `roles` and `org_roles` may each be a bare string instead of a list.
It raises a `GraphQLError` when the request is unauthenticated or lacks a
requirement. Org-scoped checks fail closed: no membership on the request means no
org roles. `AuthSubscribeExtension` takes the same arguments and applies to
subscription fields.

For checks that don't fit a field directive:

```python
from authentikate.strawberry import has_role, has_org_role, get_org_roles

if not has_org_role(info, "owner"):
    raise GraphQLError("Not permitted")
```

### Reading the current principal

Within a request you can read the active principal from context vars:

```python
from authentikate.vars import (
    get_token,
    get_user,
    get_client,
    get_organization,
    get_membership,   # carries the roles held within the active organization
)
```

---

## 9. Verifying provenance tokens

When `PROVENANCE` is configured, decode and verify a provenance token on the
audience side:

```python
from authentikate.provenance import (
    adecode_provenance_token,   # decode + verify signature, expiry, audience
    verify_actor,               # bind the token's actor to the auth token
    verify_args,                # recompute the args hash against cleartext args
    aauthenticate_provenance_header,          # extract from headers; raises the specific error
    aauthenticate_provenance_header_or_raise, # fail-closed: None if absent, ProvenanceValidationError if present-but-invalid
    aauthenticate_provenance_header_or_none,  # graceful: None on absent OR invalid (logs the reason)
)

provenance = await adecode_provenance_token(raw_token, settings)
verify_actor(provenance, auth_token)   # act.sub/act.cid must match the auth token
verify_args(provenance, cleartext_args)  # SHA-256 of canonical args must equal `ahs`
```

`decode_provenance_token` verifies the EdDSA signature against the provenance
issuers, validates expiry, and (when `AUDIENCE` is set) checks that this service
is in the token's `aud`. Single-use `jti` enforcement needs a database and
remains the host application's responsibility — the `jti` claim is exposed on
`ProvenanceToken` for that purpose.

The args-hash contract is versioned (`sha256-canonical-v1`,
`authentikate.provenance.canonical`) and must stay byte-for-byte identical to the
issuer side.

---

## 10. Error model

All errors derive from one of two bases (`authentikate.errors`):

- **`AuthentikatePermissionDenied`** (subclass of Django's `PermissionDenied`) —
  authentication/authorization failures. The `*_or_none` helpers catch these.
  Includes `AuthentikateTokenExpired`, `MalformedJwtTokenError`,
  `InvalidJwtTokenError`, `NoAuthorizationHeader`,
  `MalformedAuthorizationHeader`, `MissingActiveOrganization`,
  `BlockedMembership`, and the provenance errors (`InvalidProvenanceTokenError`,
  `MalformedProvenanceTokenError`, `ProvenanceAudienceError`,
  `ProvenanceActorMismatchError`, `ProvenanceArgsMismatchError`,
  `ProvenanceValidationError`). `ProvenanceValidationError` is raised when a
  provenance token is *present* on a request but fails validation — the
  fail-closed path used by the Strawberry extension and
  `aauthenticate_provenance_header_or_raise`; the specific underlying failure is
  chained as its `__cause__`.
- **`AuthentikateError`** — non-permission/configuration errors:
  `JwksError`, `ProvenanceNotConfiguredError`,
  `UnsupportedCanonicalizationError`.

### Codes on the wire

Every auth failure reaches a GraphQL client with a machine-readable code, so it
never has to parse the message:

```json
{ "errors": [ { "message": "The access token has expired.",
                "extensions": { "code": "UNAUTHENTICATED",
                                "reason": "TOKEN_EXPIRED" } } ] }
```

`code` is the coarse category, shared with `kante.errors` — it is the branch you
act on. `reason` names the specific failure; new reasons can be added without
breaking a client that switches on `code`, so **switch on `code` and treat
`reason` as detail**.

| `code` | What the client should do |
|---|---|
| `UNAUTHENTICATED` | Refresh the token, or send the user to log in again. |
| `PERMISSION_DENIED` | Nothing will help; the credentials are valid but insufficient. |
| `INTERNAL_ERROR` | A server-side fault (e.g. the issuer is unreachable). Retry later. |

| `reason` | `code` | Raised when |
|---|---|---|
| `NO_AUTHORIZATION_HEADER` | `UNAUTHENTICATED` | No `Authorization` header was sent. |
| `MALFORMED_AUTHORIZATION_HEADER` | `UNAUTHENTICATED` | The header is not a Bearer token. |
| `TOKEN_EXPIRED` | `UNAUTHENTICATED` | The token's `exp` has passed — **the signal to refresh**. |
| `TOKEN_MALFORMED` | `UNAUTHENTICATED` | The token is not a well-formed JWT. |
| `TOKEN_INVALID` | `UNAUTHENTICATED` | Bad signature, untrusted issuer, or wrong audience. |
| `SIGNING_KEY_NOT_FOUND` | `UNAUTHENTICATED` | The `kid` matches no key of that issuer. |
| `NOT_AUTHENTICATED` | `UNAUTHENTICATED` | The field requires auth and the request carried none. |
| `INSUFFICIENT_SCOPE` | `PERMISSION_DENIED` | Missing a required scope; see `requiredScopes` / `requiredAnyScopeOf`. |
| `INSUFFICIENT_ROLE` | `PERMISSION_DENIED` | Missing a required role; see `requiredRoles` / `requiredAnyRoleOf`. |
| `INSUFFICIENT_ORGANIZATION_ROLE` | `PERMISSION_DENIED` | Missing a role *within the active organization*; see `requiredOrganizationRoles`. |
| `MISSING_ACTIVE_ORGANIZATION` | `PERMISSION_DENIED` | The token names no `active_org`. |
| `ORGANIZATION_NOT_ALLOWED` | `PERMISSION_DENIED` | `ALLOWED_ORGANIZATIONS` excludes the token's org. |
| `MEMBERSHIP_BLOCKED` | `PERMISSION_DENIED` | The membership is `blocked`. |
| `PROVENANCE_*` | `PERMISSION_DENIED` | The provenance token is malformed, invalid, mis-scoped, or issued to another actor. |
| `KEY_RETRIEVAL_FAILED` | `INTERNAL_ERROR` | The issuer's JWKS could not be fetched. |

**Authorization** failures name the requirement, both in the message and in
`extensions` (`requiredScopes`, `requiredRoles`, …). That discloses nothing new:
the `Auth` schema directive already publishes the required scopes and roles into
the introspectable schema.

**Authentication** failures deliberately do *not* echo the rejected value — the
issuer, audience or key id in a bad token is attacker-supplied, and reflecting it
turns the error surface into a probe for what the service trusts. The full detail
is logged at WARNING under `authentikate.strawberry.errors` instead.

Each exception carries `code`, `reason` and `client_message` as class attributes,
so non-GraphQL callers can read them too:

```python
from authentikate.errors import AuthentikateTokenExpired
AuthentikateTokenExpired.reason        # "TOKEN_EXPIRED"

from authentikate.strawberry import to_graphql_error
raise to_graphql_error(exc)            # -> coded GraphQL error
```
