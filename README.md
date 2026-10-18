# Authentikate

[![codecov](https://codecov.io/gh/jhnnsrs/authentikate/branch/master/graph/badge.svg?token=UGXEA2THBV)](https://codecov.io/gh/jhnnsrs/authentikate)
[![PyPI version](https://badge.fury.io/py/authentikate.svg)](https://pypi.org/project/authentikate/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://pypi.org/project/authentikate/)
![Maintainer](https://img.shields.io/badge/maintainer-jhnnsrs-blue)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/authentikate.svg)](https://pypi.python.org/pypi/authentikate/)
[![PyPI status](https://img.shields.io/pypi/status/authentikate.svg)](https://pypi.python.org/pypi/authentikate/)
[![PyPI download month](https://img.shields.io/pypi/dm/authentikate.svg)](https://pypi.python.org/pypi/authentikate/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/jhnnsrs/authentikate)


## What is Authentikate?

Authentikate is a library that provides a simple interface to validate tokens and retrieve corresponding
user information inside a django application.

> **Note:** This library is still somewhat tied to the Arkitekt Framework. We are working on making it more generic.
> If you have any ideas, please open an issue or a PR.

### Alternatives

There are a few alternatives to this library, but none of them provide the same functionality. The most popular
alternative is [Simple JWT](https://django-rest-framework-simplejwt.readthedocs.io/en/latest/) or [Strawberry-django Auth
](https://strawberry.rocks/docs/ecosystem/django-auth). Both of these libraries provide a great way to authenticate
users. So you should seriously consider using them instead of this library.

### Why Authentikate?

Authentikate was designed to work with the [Arkitekt Framework](https://arkitekt.live) and therefore comes with a few
additional features that are not available in other libraries. 

Features:
- [x] Designed to work with the more specific [Oauth2 Self-Encoded Access Tokens](https://www.oauth.com/oauth2-servers/access-tokens/self-encoded-access-tokens/)
- [x] Models Oauth2 Clients and Scopes
- [x] Build in support for [Guardian](https://django-guardian.readthedocs.io/en/stable/) for object level permissions
- [x] Build in support for Static Tokens (Token that are hard coded into the settings, e.g. for testing)
- [x] Build in support for [Strawberry](https://strawberry.rocks/) 
- [x] Designed to work with [Koherent](https://github.com/jhnnsrs/koherent) for audit logging
- [x] Imitation support with Imitation Tokens (Token that are hard coded into the settings, e.g. for testing)


### Composed Usage

If you plan to use Authentikate with the Arkitekt Framework, you should consider the [Kante](https://github.com/jhnnsrs/kante) library. It composes
Authentikate with Koherent and provides a simple interface to authenticate and log all changes that are done by a specific app and user.


## How do I use it?

Authentikate is a Django Libary, so you will have to add it to your `INSTALLED_APPS` in your `settings.py` file.

```python
INSTALLED_APPS = [
    ...
    'guardian', # This is required for object level permissions
    'authentikate',
    ...
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend", # This is required for object level permissions
]

You will also need some additional configuration in your `settings.py` file.

```python
AUTH_USER_MODEL = "authentikate.User"


AUTHENTIKATE = {
    "ISSUERS": [
        {
            "kind": "jwks_uri",
            "iss": "https://lok.my-org.com",
            "jwks_uri": "https://lok.my-org.com/.well-known/jwks.json",
            # Optional: refuse tokens lok has revoked before they expire. The
            # list is fetched at most once a minute (configurable), not per request.
            "revocation_uri": "https://lok.my-org.com/o/revoked/",
        }
    ],
    # This service's identifier, checked against the token's `aud`. Required —
    # without it a token your issuer minted for any other service would be
    # accepted here. Use "*" to accept any audience deliberately.
    "AUDIENCE": "my-service",
}

```

`ISSUERS` and `AUDIENCE` are the required keys. Each entry is selected by its `kind`
(`jwks_uri`, `jwks_dict`, `rsa`, or `rsa_file`). For the full settings shape —
issuers, static tokens, provenance, headers, the public API and error model —
see [`docs/USAGE.md`](docs/USAGE.md).

> **Upgrading?** 4.0 renames the `active_org` claim to `org` (which now carries
> the organization *id*, not a slug) and makes `AUDIENCE` and the token's `aud`
> claim required. 3.0 fixed two authentication bypasses and contains breaking
> changes of its own (most notably: token roles are no longer mirrored onto
> Django `Group`s). See [`docs/UPGRADING.md`](docs/UPGRADING.md).


### Standard Usage

Koherent is designed to work with [Strawberry](https://strawberry.rocks/), so you will need to add its extension to your
schema.

```python
from authentikate.utils import authenticate_header_or_none


def my_view(request: HttpRequest) -> None:
    auth = authenticate_header_or_none(request.headers)

    if auth:
        auth.user # This is the user that is authenticated
        auth.app # This is the app that is authenticated
        auth.scopes # These are the scopes that are authenticated

```


### GraphQL Setup

Currently we require that you use the [`Kante`](https://github.com/jhnnsrs/kante) GraphQL library, as it provides some
boilerplate code that is required to make this work.


```python
import strawberry
from authentikate.strawberry import AuthentikateExtension, AuthExtension

schema = strawberry.Schema(query=Query, extensions=[AuthentikateExtension])


@strawberry.type
class Query:

    @strawberry.field(extensions=[AuthExtension()])
    def me(self, info: Info) -> User:
        return info.context.request.user

    @strawberry.field(extensions=[AuthExtension(scopes=["read:users"])])
    def users(self, info: Info) -> List[User]:
        return User.objects.all()

```

`AuthExtension` accepts `scopes`, `roles`, `any_scope_of` and `any_role_of`. Use
`AuthSubscribeExtension` on subscription fields.

### Guests (collaborations)

A guest of an organization was granted a few *collaborations* of its services, and nothing
else. Their token says which, by service instance, with the roles they hold in each:

```json
{"org": "12", "roles": [], "collabs": {"12": {"5": ["editor"], "9": []}}}
```

A guest holds a collaboration's roles only inside that collaboration: `editor` in collaboration 5 lets
them edit what is in collaboration 5, and `[]` lets them view collaboration 9. What a collaboration holds
is the hosting service's business (`arkitekt_service.collaborations`): authentikate only
decides whether such a token is served at all, and checks a field's roles against
the guest's collaborations. The issuer caps a guest's roles to those of whoever granted
the collaboration, so a guest never holds more than that person.

`token.is_scoped` tells guests from full members, and `token.collabs_here(instance)`
lists the collaborations granted on one service instance with their roles.

```python
AUTHENTIKATE = {
    ...,
    "AUDIENCE": "12",         # this service instance: tokens must name it, and its entry of `collabs` is read
    "SCOPED_TOKENS": "auto",  # auto | reject | self
}
```

A service whose audience is `*` names no instance, so it serves no guests.

- `auto` (the default) rejects a guest's token (`SCOPED_TOKEN_UNSUPPORTED`) unless
  something in the process holds reads to the guest's collaborations and has said so with
  `authentikate.scoped.enforce_scoped()`. Where it is accepted, mutations and
  subscriptions are refused (`SCOPED_READ_ONLY`) unless every root field opted in
  with `AuthExtension(allow_scoped=True)`; subscriptions always are.
- `reject` always rejects it.
- `self` accepts it and leaves every rule to the service itself.

On an opted-in field, a guest passes the role requirements when *one* of their
collaborations holds them all. The resolver must then check that what it writes to is in
such a collaboration (`arkitekt_service.collaborations.require_in_collaboration`, which raises
`SHARE_INSUFFICIENT`). Full members are checked against their roles as before.

```python
@kante.django_mutation(extensions=[AuthExtension(any_role_of=["admin", "editor"], allow_scoped=True)])
def create_annotation(self, info: Info, input: CreateAnnotationInput) -> Annotation: ...
```

`@auth` publishes every requirement (`required_*`, `any_*`, `allow_scoped`).

Outside GraphQL, `require_full_member(token)` and the `@full_members_only` view
decorator refuse a guest (`FULL_MEMBERSHIP_REQUIRED`).

The refusal is recorded as the operation's validation errors (`on_validate`). An
extension that assigns `execution_context.pre_execution_errors` itself, such as
strawberry's `ValidationCache`, must come *before* `AuthentikateExtension` in the
schema's extensions, or it overwrites the refusal.

### Static Tokens

Static Tokens are tokens that are hard coded into the settings. They are useful for testing and development, but should
not be used in production.

```python

AUTHENTIKATE = {
    "ISSUERS": [
        {
            "kind": "jwks_uri",
            "iss": "https://lok.my-org.com",
            "jwks_uri": "https://lok.my-org.com/.well-known/jwks.json",
        }
    ],
    # Static tokens bypass signature verification entirely. They are for tests
    # and local development only: configuring them while DEBUG is False raises
    # ImproperlyConfigured at startup.
    "STATIC_TOKENS": {
        "my_token": {
            "sub": "my_user",
            "iss": "https://lok.my-org.com",
            "scope": "read:users",
            "roles": ["reader"],
        }
    }
}

```

