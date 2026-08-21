# Upgrading to authentikate 4.0

Two breaking changes, both in the shape of the token this service accepts. Your
**issuer must be updated first** — every one of these tokens is minted by the
IdP, so authentikate 4.0 rejects tokens an unchanged issuer still emits.

---

## 1. The `active_org` claim is now `org`, and carries an id

The claim naming the organization a token acts in is renamed, and its value
changes meaning:

| | 3.x | 4.0 |
|---|---|---|
| claim | `active_org` | `org` |
| value | the organization *slug* (`"acme"`) | the organization *id* as a string (`str(organization_id)`, e.g. `"42"`) |

An id is stable across renames; a slug is not. `JWTToken.active_org` is likewise
`JWTToken.org`. The old claim is **not** accepted as a fallback — with
`extra="ignore"` on the model, a token still sending `active_org` decodes to
`org = None` and is rejected with `MissingActiveOrganization` on any path that
expands the organization.

**Re-key `ALLOWED_ORGANIZATIONS`.** Its values are matched against the new claim,
so a list of slugs now matches nothing and rejects every request:

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "ALLOWED_ORGANIZATIONS": ["42", "137"],   # ids, not ["acme", "beta-corp"]
}
```

**Existing `Organization` rows do not migrate themselves.** The claim is still
stored in `Organization.slug` (the column keeps its name because it is part of
the GraphQL schema), so on first request after the upgrade a *new* row keyed
`"42"` is created alongside the old `"acme"` row, with a new `Membership`, and
`User.active_organization` is re-pointed at it. That re-pointing happens for
every user because the `org` claim feeds `changed_hash`, which is what triggers
the sync.

If you have data hanging off `Organization`, write a data migration that rewrites
`slug` from the old value to the new id before deploying — authentikate cannot do
it for you, since only your issuer knows which id belongs to which slug.

## 2. `AUDIENCE` is required, and so is the token's `aud` claim

`AUDIENCE` was optional in 3.x with a startup warning. It is now required:

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "AUDIENCE": "my-service",   # this service's identifier
}
```

Omitting it raises `ImproperlyConfigured` at startup rather than silently
accepting a token your IdP minted for any other service.

`aud` is correspondingly an essential claim on every auth token, and required on
`JWTToken`. A token without one is rejected with `InvalidJwtTokenError`
(`TOKEN_INVALID`) — it is scoped to no service, so there is nothing to check it
against.

**`"*"` still works, but it no longer waives the claim.** In 3.x the wildcard
dropped the audience check entirely, which meant a token with no `aud` was
accepted; that behaviour existed only so `"*"` could never be *stricter* than
leaving the setting unset. With the setting required, there is no "unset" to be
lenient against: `"*"` now says *any* audience, not *no* audience. A token still
has to carry an `aud` — this service just stops caring which service it names,
and still warns at startup that it does.

`"*"` remains config-side only: a token whose own `aud` contains `"*"` is still
rejected by a service configured with a literal audience.

Static tokens are unaffected. They bypass signature verification by design, and
their audience is not checked either — an operator pasting a token into their own
settings is not the cross-service replay that audience checking prevents.
`StaticToken.aud` defaults to `["static_audience"]` purely to satisfy the
required claim.

---

# Upgrading to authentikate 3.0

This release fixes two authentication bypasses and a configuration that broke all
authentication. **Upgrading is strongly recommended.** Read the *Action required*
section below — two changes need a settings update, and one is breaking.

---

## Security fixes

### Cross-issuer token forgery (critical)

Every configured issuer's JWKS was merged into one flat key set indexed by `kid`,
and the token's `iss` claim was never checked against the issuer that owned the
key. **With two or more issuers configured, any one of them could mint a token
claiming to be from another** — with an arbitrary `sub`, `roles` and
`active_org`. Since users are keyed on `(sub, iss)`, that is full account
takeover of any other issuer's users.

A token is now verified against the keys of the issuer its `iss` claim names, and
only those. An `iss` naming no configured issuer is rejected before any network
I/O, so an unknown issuer can no longer trigger an outbound JWKS fetch either.

*No action required*, but see the note on multi-issuer deployments below.

### Missing audience validation (high)

Only `exp` was validated. A token your issuer minted for service X was accepted
verbatim by service Y. Set `AUDIENCE` — see *Action required*.

### Provenance actor binding was never enforced (high)

`verify_actor` existed but nothing called it: the Strawberry extension decoded a
provenance token and attached it to the request as verified without binding it to
the auth token presenting it. Anyone holding a valid provenance token could
replay it under their own credentials and misattribute the causal chain. The
extension now calls `verify_actor` on both the HTTP and WebSocket paths.

Single-use `jti` enforcement still needs a datastore and remains the host
application's responsibility.

### Two `rsa` issuers broke all authentication (high)

`RSAKeyIssuer.key_id` and `RSAKeyFileIssuer.key_id` both default to `"1"`, and
duplicate `kid`s across issuers raised `JwksError` on *every* authentication —
which, because `JwksError` was not a `PermissionDenied`, surfaced as an unhandled
500. Keys are no longer merged across issuers, so this configuration works.

### Invalid usernames for token-provisioned users

`token_to_username` built usernames as `f"{iss}_{sub}"`. With a URL issuer that
produces e.g. `https://lok.my-org.com/realms/prod_<sub>`, which **fails**
Django's `UnicodeUsernameValidator` (`:` and `/` are not allowed) and can exceed
the field's 150-character limit. `save()` skips validators so the value
persisted silently, but `full_clean()` rejected it — meaning the Django admin
could not edit any token-provisioned user — and a long issuer would raise a
`DataError` on PostgreSQL.

Usernames are now sanitized to the accepted charset, bounded to 150 characters,
and suffixed with a short digest of the original `(iss, sub)`. See *Action
required* below.

### Also fixed

- **Algorithms are pinned** (`ALGORITHMS`) per RFC 8725. The default is every
  asymmetric algorithm, which blocks the `HS*`/`none` confusion attacks without
  breaking issuers that do not sign with RS256; narrow it to the one yours uses.
- **Static tokens honour `exp`** — previously decorative, so a "short-lived"
  static token never expired.
- **Static tokens are refused when `DEBUG` is `False`** (see *Action required*).
- **JWKS refetches are throttled**, so a stream of made-up `kid`s can no longer
  drive one live request to your issuer per inbound request.
- **`JwksError` no longer escapes as a 500** from the `*_or_none` helpers.
- **A `raw` claim can no longer spoof the token string** on `JWTToken`.
- **A debug `print` that logged the full provenance token** (including the signed
  token string) on every async decode has been removed.
- **Blocked memberships are enforced on every path** — `expand_user_from_token`,
  `aexpand_user_from_token` and `AuthentikateExtension.aexpand_user_from_token`
  all skipped the check. All three now resolve the membership, and
  `_expand_user` / `_aexpand_user` are the private primitives that do not.
- **`changed_hash`** is no longer built by joining on `"|"`, which let a role
  named `a|b` collide with the roles `["a", "b"]`.
- **Two protocol bugs in kante** that made authentikate's own models fail to
  type-check: `Client.id` was declared `str` while the primary key is an `int`,
  and `Provenance`/`Actor` members were settable (hence invariant), so
  `ProvenanceToken` could not satisfy `Provenance` despite matching it exactly.
  Both are fixed in kante 2.1.1, which this release now requires. authentikate's
  workaround casts are gone and the package type-checks clean under
  `mypy --strict`.

---

## Action required

### 1. Set `AUDIENCE` (recommended in 3.0, **required** since 4.0)

> Going straight to 4.0? Read this section for context, then follow the 4.0
> section above — `AUDIENCE` is required there and `"*"` no longer waives the
> `aud` claim.


```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "AUDIENCE": "my-service",   # this service's identifier
}
```

When set, `aud` becomes an essential claim and must contain this value; a
list-valued `aud` matches on membership. When unset, a warning is logged at
startup and `aud` is not checked.

**Your issuer must actually mint scoped `aud` claims before you turn this on**,
or every token will be rejected. Roll it out issuer-first.

If you want to accept any audience deliberately rather than by omission, set
`AUDIENCE` to `"*"`. It behaves exactly like leaving it unset (and warns at
startup for the same reason), but it reads as a decision and will satisfy the 4.0
requirement. The same value works for the provenance `AUDIENCE`, which is
required. Note `"*"` is config-side only: a token carrying `aud: ["*"]` is still
rejected by a service configured with a literal audience.

### 2. kante 2.1.1 is now the minimum

The requirement moves from `kante>=2.0.1` to `kante>=2.1.1`, which carries two
protocol fixes authentikate depends on (see *Also fixed* above). The change is
types-only, so nothing behaves differently at runtime — but on an older kante
the request principals do not type-check against the protocols kante declares.

### 3. Remove `STATIC_TOKENS` from non-development settings

A non-empty `STATIC_TOKENS` while `DEBUG` is `False` now raises
`ImproperlyConfigured` at startup. If you genuinely need them there, set
`ALLOW_STATIC_TOKENS_IN_PRODUCTION: True` — but note they bypass signature
verification entirely and default to `roles: ["admin"]`.

### 4. **Breaking:** token roles are no longer mirrored onto Django `Group`s

Previously every token role was turned into a `Group` of the same name and
attached to the user. Any IdP role name that happened to match a locally managed,
permission-bearing group therefore granted those permissions — the issuer's
`roles` claim was effectively a direct write into Django's permission system.

`aset_user_groups` / `set_user_groups` are gone, and expansion no longer touches
`django.contrib.auth.Group`. Roles remain on the token and on `Membership.roles`.

**If you relied on those auto-created groups**, replace the checks:

```python
# before: relied on a Group named "admin" existing
@strawberry.field
def secret(self, info) -> str: ...

# after: check the role directly
@strawberry.field(extensions=[AuthExtension(roles=["admin"])])
def secret(self, info) -> str: ...

# or scoped to the request's active organization
@strawberry.field(extensions=[AuthExtension(org_roles=["owner"])])
def billing(self, info) -> str: ...
```

New in this release: `org_roles` / `any_org_role_of` check `Membership.roles` for
the request's active organization, and the helpers `has_role(info, role)`,
`has_org_role(info, role)` and `get_org_roles(info)` cover resolver-level checks.
`get_membership()` joins the other context vars in `authentikate.vars`.

Groups themselves still work as normal — they are simply no longer written to
from token claims. Existing group memberships are left untouched; they just stop
being re-synced.

### 5. Provenance `AUDIENCE` is now required

If you configure a `PROVENANCE` block, it must include `AUDIENCE`. Previously it
defaulted to `None`, which silently disabled the audience check — defeating the
point of a token whose job is to attest which service work was scoped to.

### 6. `expand_user_from_token` / `aexpand_user_from_token` now require `active_org`

> Renamed to `org` in 4.0 — see the 4.0 section above.


Both expansion paths are now identical, and both resolve the organization and
membership the way `aexpand_token_context` always did. A token **without** an `active_org` claim now raises
`MissingActiveOrganization` where it previously returned a user with
`active_organization = None`.

This is what makes the blocked-membership check reachable on that path — the
membership is what carries `blocked`. If you have callers that legitimately
expand org-less tokens, use the lower-level pieces directly
(`models.User.objects.get(sub=..., iss=...)`) and be explicit that no
authorization check is applied.

### 7. Usernames of newly provisioned users change format

Only *new* users are affected — existing rows keep their current usernames, and
nothing breaks, because users are looked up by `(sub, iss)` and never by
username. New usernames look like
`https---lok.my-org.com-realms-production_<sub>-<digest>`.

The digest is appended unconditionally rather than only on overflow:
sanitization is lossy (`https://a.example` and `https-//a.example` collapse to
the same string), and `username` is `unique=True`, so a collision would turn
provisioning into an `IntegrityError` — a login outage for whichever user came
second.

If you display usernames anywhere, prefer `user.first_name` (which holds the
token's `preferred_username`) or the `sub`.

### 8. Optional: constrain organizations

`Organization` and `Membership` rows are created on demand from `active_org`, so
every distinct value your issuer emits creates rows:

```python
AUTHENTIKATE = {
    "ISSUERS": [...],
    "ALLOWED_ORGANIZATIONS": ["acme", "beta-corp"],
}
```

> In 4.0 the claim is `org` and carries organization ids, so these values become
> ids too — see the 4.0 section above.

---

## New in this release

### `py.typed` — the package now ships its types

authentikate is fully annotated and mypy-strict, but shipped no `py.typed`
marker. Under PEP 561 that means type checkers **ignored every annotation** in
the installed package and treated it as `Any`. The marker is now included, so
downstream code gets real types with no change on your side — though you may see
new type errors in your own code that were previously masked.

### Auth failures now carry a machine-readable code

Every authentication and authorization failure reaches a GraphQL client with
`extensions.code` (kante's coarse category — `UNAUTHENTICATED`,
`PERMISSION_DENIED`, `INTERNAL_ERROR`) and `extensions.reason` (the specific
failure, e.g. `TOKEN_EXPIRED`, `INSUFFICIENT_SCOPE`). Clients no longer have to
parse English to tell "refresh the token" from "you will never be allowed".

**Switch on `code`, treat `reason` as detail** — new reasons will be added and
that must not break exhaustive handlers.

Two behaviour changes come with it:

- Authorization failures now also carry the requirement in `extensions`
  (`requiredScopes`, `requiredRoles`, `requiredOrganizationRoles`, …). This
  discloses nothing new: the `Auth` schema directive already publishes required
  scopes and roles into the introspectable schema.
- **Authentication failure messages changed.** They no longer echo the rejected
  value (issuer, audience, key id) — that is attacker-supplied, and reflecting it
  makes the error surface a probe for what the service trusts. The full detail is
  logged at WARNING under `authentikate.strawberry.errors`. If you assert on
  authentication error *text*, assert on `extensions.reason` instead.

The full table is in [`docs/USAGE.md`](USAGE.md) §10.

### A real top-level API

`authentikate/__init__.py` exported nothing; everything had to be imported from
submodules. The common names are now available directly:

```python
from authentikate import authenticate_header, JWTToken, get_user
```

The full list is in `authentikate.__all__`. These resolve lazily (PEP 562)
because Django imports this package before the app registry is ready — importing
models eagerly here would raise `AppRegistryNotReady` at startup. Submodule
imports keep working unchanged.

---

## Removed APIs

| Removed | Replacement |
|---------|-------------|
| `AuthentikateSettings.load_key` / `aload_key` | `resolve_key_set(iss, kid)` / `aresolve_key_set(iss, kid)` |
| `ProvenanceSettings.load_key` / `aload_key` | `resolve_key_set(iss, kid)` / `aresolve_key_set(iss, kid)` |
| `expand.aset_user_groups` / `set_user_groups` | Role directives — see §4 |
| `base_models.ImitationRequest` | — (unused; no imitation flow was ever implemented) |
| `protocols.AppModel` / `protocols.ReleaseModel` | — (unused) |

The `("imitate", "Can imitate me")` permission stays on `User.Meta`: removing it
would need a migration for no benefit.

The `load_key` resolvers were the mechanism behind the cross-issuer forgery: they
returned keys merged across all issuers. They are removed rather than deprecated
so the vulnerable resolution cannot be reintroduced by a caller.

## Notes for multi-issuer deployments

Check that each configured issuer's `iss` exactly matches the `iss` claim its
tokens carry — this was never enforced before, so a mismatch may have gone
unnoticed. A mismatch now rejects the token with
`InvalidJwtTokenError: Untrusted issuer`.
