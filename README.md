# authentikate

[![codecov](https://codecov.io/gh/jhnnsrs/authentikate/branch/master/graph/badge.svg?token=UGXEA2THBV)](https://codecov.io/gh/jhnnsrs/authentikate)
[![PyPI version](https://badge.fury.io/py/authentikate.svg)](https://pypi.org/project/authentikate/)
![Maintainer](https://img.shields.io/badge/maintainer-jhnnsrs-blue)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/herre.svg)](https://pypi.python.org/pypi/authentikate/)
[![PyPI status](https://img.shields.io/pypi/status/authentikate.svg)](https://pypi.python.org/pypi/authentikate/)
[![PyPI download month](https://img.shields.io/pypi/dm/authentikate.svg)](https://pypi.python.org/pypi/authentikate/)

#### DEVELOPMENT

This project is currently under development, and tightly integrates with the arkitekt project. While we are working on a more generic solution, the project API SHOULD be considered unstable. Please use at your own risk, and consider other solutions.


## Idea

Authentikate is a library that provides a simple interface to validate tokens and retrieve corresponding
user information inside a django application.

## Usage

In order to initialize a herre client you need to specify a specific grant to retrieve the access_token. A grant constitutes a way of retrieving a Token in an asynchronous manner.

### Installation

```bash
pip install authentikate
```

### Configuration

```python

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "guardian",
    "authentikate",
]


AUTH_USER_MODEL = "authentikate.User"

AUTHENTIKATE = {
    "KEY_TYPE": "RS256",
    "PUBLIC_KEY_PEM_FILE": "public_key.pem",
    "FORCE_CLIENT": False,

}

```

Authentication is done by using the `authenticate_token` method. This method takes a token and returns a user object if the token is valid. Otherwise it returns `None`.

```python

```python
from authentikate import authenticate_token, authenticate_headers

def my_view(request):
    auth = authenticate_headers(request.HEADERS)
    if user is not None:
        # do something with user
    else:
        # do something else
```



