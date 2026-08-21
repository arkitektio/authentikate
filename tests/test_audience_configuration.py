"""A blank ``AUDIENCE`` must be rejected as configuration, not reinterpreted.

The two verifiers used to disagree about what ``""`` meant: the auth path
treated it as a literal audience no token could match (every request failed with
an opaque claim error), while the provenance path guarded its check with
``if provenance.audience`` and so skipped the check entirely -- accepting a
provenance token minted for any other service.
"""

import datetime
import uuid

import pytest
from joserfc import jwt
from joserfc.jwk import OKPKey
from pydantic import ValidationError

from authentikate.base_models import ANY_AUDIENCE, AuthentikateSettings
from authentikate.provenance import CANONICALIZATION_VERSION, decode_provenance_token

PROV_KID = "prov-1"


@pytest.fixture
def ed_key() -> OKPKey:
    return OKPKey.generate_key("Ed25519")


def _issuers(ed_key: OKPKey) -> list[dict]:
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    return [{"iss": "rekuest", "kind": "jwks_dict", "jwks": {"keys": [pub]}}]


def _provenance_token(ed_key: OKPKey, aud: list[str]) -> str:
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    claims = {
        "iss": "rekuest",
        "aud": aud,
        "sub": "user-42",
        "act": {"sub": "agent-7", "cid": "imagej-app"},
        "iat": now,
        "exp": now + 3600,
        "jti": uuid.uuid4().hex,
        "tsk": "9b1a",
        "ptk": None,
        "rtk": "9b1a",
        "rcb": "user-42",
        "ahs": "e3b0c44298fc1c14",
        "aha": CANONICALIZATION_VERSION,
    }
    return jwt.encode(
        {"alg": "Ed25519", "kid": PROV_KID}, claims, ed_key, algorithms=["Ed25519"]
    )


@pytest.mark.parametrize("blank", ["", " ", "\t"])
def test_blank_audience_is_rejected(blank: str, ed_key: OKPKey) -> None:
    with pytest.raises(ValidationError, match="must not be blank"):
        AuthentikateSettings(audience=blank, issuers=_issuers(ed_key))


@pytest.mark.parametrize("blank", ["", " ", "\t"])
def test_blank_provenance_audience_is_rejected(blank: str, ed_key: OKPKey) -> None:
    """The fail-open case: a blank value used to skip the check silently."""
    with pytest.raises(ValidationError, match="must not be blank"):
        AuthentikateSettings(
            audience="mikro",
            issuers=_issuers(ed_key),
            provenance={"issuers": _issuers(ed_key), "audience": blank},
        )


def test_a_configured_audience_is_always_checked(ed_key: OKPKey) -> None:
    """With a real audience configured, another service's token is rejected."""
    settings = AuthentikateSettings(
        audience="mikro",
        issuers=_issuers(ed_key),
        provenance={"issuers": _issuers(ed_key), "audience": "mikro"},
    )
    token = _provenance_token(ed_key, ["some-other-service"])

    from authentikate import errors

    with pytest.raises(errors.ProvenanceAudienceError):
        decode_provenance_token(token, settings)


def test_the_wildcard_remains_the_way_to_say_any_audience(ed_key: OKPKey) -> None:
    """``"*"`` is non-blank, so it still expresses a deliberate any-audience."""
    settings = AuthentikateSettings(
        audience="mikro",
        issuers=_issuers(ed_key),
        provenance={"issuers": _issuers(ed_key), "audience": ANY_AUDIENCE},
    )
    token = _provenance_token(ed_key, ["some-other-service"])

    assert decode_provenance_token(token, settings).aud == ["some-other-service"]
