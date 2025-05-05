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
    "KEY_TYPE": "RS256",
    "PUBLIC_KEY_PEM_FILE": "public_key.pem",
    "FORCE_CLIENT": False, # allows non Oauth2 JWTs to be used

}

```


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
from authentikate.strawberry.permissions import IsAuthenticated, NeedsScopes

@strawberry.type
class Query

    @strawberry.field(permission_classes=[IsAuthenticated])
    def me(self, info: Info) -> User:
        return info.context.auth.user

    @strawberry.field(permission_classes=[NeedsScopes(["read:users"])])
    def users(self, info: Info) -> List[User]:
        return User.objects.all()

```

### Static Tokens

Static Tokens are tokens that are hard coded into the settings. They are useful for testing and development, but should
not be used in production.

```python

AUTHENTIKATE = {
    "KEY_TYPE": "RS256",
    "PUBLIC_KEY_PEM_FILE": "public_key.pem",
    "FORCE_CLIENT": False, # allows non Oauth2 JWTs to be used
    "STATIC_TOKENS": {
        "my_token": {
            "user": "my_user",
            "app": "my_app",
            "scopes": ["read:users"]
        }
    }
}

```

