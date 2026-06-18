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

## 2. The `AUTHENTIKATE` settings dict

The dict is validated by the `AuthentikateSettings` pydantic model
(`authentikate/base_models.py`). **Extra keys are rejected** (`extra="forbid"`),
so a typo raises `ImproperlyConfigured` at startup rather than failing silently.

| Key | Type | Required | Default | Purpose |
|-----|------|----------|---------|---------|
| `ISSUERS` | list of issuer dicts | **yes** | — | Trusted issuers whose keys verify incoming auth tokens. |
| `AUTHORIZATION_HEADERS` | list of strings | no | `["Authorization", "X-Authorization", "AUTHORIZATION", "authorization"]` | Header names searched (in order) for a `Bearer` token. |
| `PROVENANCE_HEADER` | list of strings | no | Rekuest task + provenance-token header variants | Header names searched (in order) for a provenance token. |
| `STATIC_TOKENS` | map of `str → token dict` | no | `{}` | Hard-coded tokens that bypass signature verification. **Tests only.** |
| `PROVENANCE` | provenance dict | no | `None` | Configuration for verifying inbound provenance tokens. `None` disables provenance verification. |

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
            # "roles": ["admin"],
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
| `AUDIENCE` | string | no | `None` | This service's identifier (e.g. `"mikro"`). When set, it is checked against the token's `aud`. |
| `ALGORITHMS` | list of strings | no | `["EdDSA"]` | Allowed signature algorithms. The algorithm is pinned per RFC 8725: an empty list and the `none` algorithm are rejected. |

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
`aexpand_organization_from_token`, `aexpand_membership`. Roles are mirrored onto
Django `Group`s; a blocked membership raises `BlockedMembership`, and a token
without `active_org` raises `MissingActiveOrganization` when an organization is
required.

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
being silently ignored).

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

`AuthExtension` accepts `scopes`, `roles`, `any_scope_of`, `any_role_of` (each a
list, or `scopes`/`roles` may be a bare string). It raises a `GraphQLError` when
the request is unauthenticated or lacks the required scopes/roles. Use
`AuthSubscribeExtension` for subscription fields (`scopes`/`roles` only).

### Reading the current principal

Within a request you can read the active principal from context vars:

```python
from authentikate.vars import get_token, get_user, get_client, get_organization
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
