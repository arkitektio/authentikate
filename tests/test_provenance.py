"""Tests for the consuming/audience-end provenance token decoder path."""

import base64
import datetime
import hashlib
import json
import logging
import uuid

import pytest
from joserfc import jwt
from joserfc.jwk import OKPKey, RSAKey
from pydantic import ValidationError

from authentikate import errors
from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.provenance import (
    CANONICALIZATION_VERSION,
    Actor,
    ProvenanceToken,
    adecode_provenance_token,
    args_hash,
    canonicalize_v1,
    decode_provenance_token,
    verify_actor,
    verify_args,
)
from authentikate.provenance.verify import (
    aauthenticate_provenance_header,
    aauthenticate_provenance_header_or_none,
    aauthenticate_provenance_header_or_raise,
)

PROV_KID = "prov-1"


def _provenance_claims(**overrides):
    now = int(datetime.datetime.now().timestamp())
    claims = {
        "iss": "rekuest",
        "aud": ["mikro"],
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
    claims.update(overrides)
    return claims


@pytest.fixture
def ed_key() -> OKPKey:
    return OKPKey.generate_key("Ed25519")


@pytest.fixture
def other_ed_key() -> OKPKey:
    return OKPKey.generate_key("Ed25519")


def _sign(key: OKPKey, claims: dict, *, kid: str = PROV_KID) -> str:
    return jwt.encode({"alg": "EdDSA", "kid": kid}, claims, key, algorithms=["EdDSA"])


@pytest.fixture
def settings(ed_key: OKPKey) -> AuthentikateSettings:
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    return AuthentikateSettings(
        issuers=[{"iss": "lok", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
        provenance={
            "issuers": [
                {"iss": "rekuest", "kind": "jwks_dict", "jwks": {"keys": [pub]}}
            ],
            "audience": "mikro",
        },
    )


# --- decode / happy path -----------------------------------------------------


def test_decode_provenance_token(ed_key, settings):
    token = _sign(ed_key, _provenance_claims())
    decoded = decode_provenance_token(token, settings)

    assert isinstance(decoded, ProvenanceToken)
    assert decoded.iss == "rekuest"
    assert decoded.sub == "user-42"
    assert decoded.act == Actor(sub="agent-7", cid="imagej-app")
    assert decoded.jti
    assert decoded.tsk == "9b1a"
    assert decoded.is_root is True
    assert decoded.has_audience("mikro") is True
    assert decoded.has_audience("other") is False
    assert decoded.raw == token


@pytest.mark.asyncio
async def test_adecode_provenance_token(ed_key, settings):
    token = _sign(ed_key, _provenance_claims())
    decoded = await adecode_provenance_token(token, settings)
    assert decoded.sub == "user-42"
    assert decoded.is_root is True


def test_sub_assignment_is_not_root(ed_key, settings):
    token = _sign(ed_key, _provenance_claims(ptk="parent", rtk="root", sub="agent-7"))
    decoded = decode_provenance_token(token, settings)
    assert decoded.is_root is False
    assert decoded.ptk == "parent"
    assert decoded.rtk == "root"


# --- algorithm pinning (the key security property) ---------------------------


def test_rejects_rs256(settings):
    rsa_key = RSAKey.generate_key(2048)
    token = jwt.encode(
        {"alg": "RS256", "kid": PROV_KID},
        _provenance_claims(),
        rsa_key,
        algorithms=["RS256"],
    )
    with pytest.raises(errors.InvalidProvenanceTokenError):
        decode_provenance_token(token, settings)


def test_rejects_alg_none(settings):
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "kid": PROV_KID}).encode()
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(_provenance_claims()).encode()
    ).rstrip(b"=")
    token = f"{header.decode()}.{payload.decode()}."
    with pytest.raises(errors.InvalidProvenanceTokenError):
        decode_provenance_token(token, settings)


def test_rejects_wrong_signing_key(other_ed_key, settings):
    token = _sign(other_ed_key, _provenance_claims())
    with pytest.raises(errors.InvalidProvenanceTokenError):
        decode_provenance_token(token, settings)


# --- claims / config validation ----------------------------------------------


def test_expired_token(ed_key, settings):
    now = int(datetime.datetime.now().timestamp())
    token = _sign(ed_key, _provenance_claims(iat=now - 7200, exp=now - 3600))
    with pytest.raises(errors.AuthentikateTokenExpired):
        decode_provenance_token(token, settings)


def test_not_configured(ed_key):
    bare = AuthentikateSettings(
        issuers=[
            {
                "iss": "lok",
                "kind": "jwks_dict",
                "jwks": {"keys": [ed_key.as_dict(private=False, kid=PROV_KID)]},
            }
        ]
    )
    token = _sign(ed_key, _provenance_claims())
    with pytest.raises(errors.ProvenanceNotConfiguredError):
        decode_provenance_token(token, bare)


def test_audience_mismatch(ed_key, settings):
    token = _sign(ed_key, _provenance_claims(aud=["someone-else"]))
    with pytest.raises(errors.ProvenanceAudienceError):
        decode_provenance_token(token, settings)


def test_malformed_payload(ed_key, settings):
    # Valid registered claims (passes the exp/claims check) but missing a
    # required provenance claim, so the model build is what fails.
    claims = _provenance_claims()
    claims.pop("tsk")
    token = _sign(ed_key, claims)
    with pytest.raises(errors.MalformedProvenanceTokenError):
        decode_provenance_token(token, settings)


# --- actor binding -----------------------------------------------------------


def _auth_token(sub: str, client_id: str) -> JWTToken:
    now = datetime.datetime.now(datetime.timezone.utc)
    return JWTToken(
        sub=sub,
        iss="lok",
        exp=now + datetime.timedelta(hours=1),
        iat=now,
        client_id=client_id,
        preferred_username="agent",
        roles=[],
        scope="openid",
        raw="raw",
    )


def test_verify_actor_ok(ed_key, settings):
    decoded = decode_provenance_token(_sign(ed_key, _provenance_claims()), settings)
    verify_actor(decoded, _auth_token("agent-7", "imagej-app"))


def test_verify_actor_sub_mismatch(ed_key, settings):
    decoded = decode_provenance_token(_sign(ed_key, _provenance_claims()), settings)
    with pytest.raises(errors.ProvenanceActorMismatchError):
        verify_actor(decoded, _auth_token("someone-else", "imagej-app"))


def test_verify_actor_cid_mismatch(ed_key, settings):
    decoded = decode_provenance_token(_sign(ed_key, _provenance_claims()), settings)
    with pytest.raises(errors.ProvenanceActorMismatchError):
        verify_actor(decoded, _auth_token("agent-7", "other-app"))


# --- args hash ---------------------------------------------------------------


def test_canonicalization_byte_form():
    # The canonical form is the contract: sorted keys, no whitespace, UTF-8.
    assert canonicalize_v1({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert canonicalize_v1({"name": "café"}) == '{"name":"café"}'.encode("utf-8")


def test_args_hash_matches_sha256_of_canonical():
    args = {"b": 2, "a": 1}
    expected = hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
    assert args_hash(args) == expected


def test_args_hash_unsupported_version():
    with pytest.raises(errors.UnsupportedCanonicalizationError):
        args_hash({"a": 1}, version="sha256-canonical-v2")


def test_verify_args_ok(ed_key, settings):
    args = {"b": 2, "a": 1}
    token = _sign(ed_key, _provenance_claims(ahs=args_hash(args)))
    decoded = decode_provenance_token(token, settings)
    verify_args(decoded, args)  # no raise


def test_verify_args_tampered(ed_key, settings):
    token = _sign(ed_key, _provenance_claims(ahs=args_hash({"a": 1})))
    decoded = decode_provenance_token(token, settings)
    with pytest.raises(errors.ProvenanceArgsMismatchError):
        verify_args(decoded, {"a": 999})


def test_verify_args_unsupported_aha(ed_key, settings):
    token = _sign(ed_key, _provenance_claims(aha="sha256-canonical-v2"))
    decoded = decode_provenance_token(token, settings)
    with pytest.raises(errors.UnsupportedCanonicalizationError):
        verify_args(decoded, {"a": 1})


# --- header extraction -------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_provenance_header(ed_key, settings):
    token = _sign(ed_key, _provenance_claims())
    decoded = await aauthenticate_provenance_header(
        {"x-provenance-token": token}, settings
    )
    assert decoded is not None
    assert decoded.sub == "user-42"


@pytest.mark.asyncio
async def test_authenticate_provenance_header_absent(settings):
    assert await aauthenticate_provenance_header({}, settings) is None


# --- graceful extraction (logs instead of raising) --------------------------


@pytest.fixture
def bare_settings(ed_key: OKPKey) -> AuthentikateSettings:
    """Settings with no provenance block configured."""
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    return AuthentikateSettings(
        issuers=[{"iss": "lok", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
    )


@pytest.mark.asyncio
async def test_or_none_returns_token_when_valid(ed_key, settings):
    token = _sign(ed_key, _provenance_claims())
    decoded = await aauthenticate_provenance_header_or_none(
        {"rekuest-task": token}, settings
    )
    assert decoded is not None
    assert decoded.sub == "user-42"


@pytest.mark.asyncio
async def test_or_none_absent_returns_none_without_logging(settings, caplog):
    with caplog.at_level(logging.WARNING, logger="authentikate.provenance.verify"):
        assert await aauthenticate_provenance_header_or_none({}, settings) is None
    assert caplog.records == []


@pytest.mark.asyncio
async def test_or_none_invalid_signature_logs_and_returns_none(
    other_ed_key, settings, caplog
):
    token = _sign(other_ed_key, _provenance_claims())
    with caplog.at_level(logging.WARNING, logger="authentikate.provenance.verify"):
        result = await aauthenticate_provenance_header_or_none(
            {"rekuest-task": token}, settings
        )
    assert result is None
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.WARNING
    assert "InvalidProvenanceTokenError" in record.getMessage()
    # The reason is captured (exc_info attached) so the failure stays observable.
    assert record.exc_info is not None


@pytest.mark.asyncio
async def test_or_none_expired_logs_and_returns_none(ed_key, settings, caplog):
    now = int(datetime.datetime.now().timestamp())
    token = _sign(ed_key, _provenance_claims(iat=now - 7200, exp=now - 3600))
    with caplog.at_level(logging.WARNING, logger="authentikate.provenance.verify"):
        result = await aauthenticate_provenance_header_or_none(
            {"rekuest-task": token}, settings
        )
    assert result is None
    assert "AuthentikateTokenExpired" in caplog.records[0].getMessage()


@pytest.mark.asyncio
async def test_or_none_malformed_logs_and_returns_none(ed_key, settings, caplog):
    claims = _provenance_claims()
    claims.pop("tsk")
    token = _sign(ed_key, claims)
    with caplog.at_level(logging.WARNING, logger="authentikate.provenance.verify"):
        result = await aauthenticate_provenance_header_or_none(
            {"rekuest-task": token}, settings
        )
    assert result is None
    assert "MalformedProvenanceTokenError" in caplog.records[0].getMessage()


@pytest.mark.asyncio
async def test_or_none_audience_mismatch_logs_and_returns_none(ed_key, settings, caplog):
    token = _sign(ed_key, _provenance_claims(aud=["someone-else"]))
    with caplog.at_level(logging.WARNING, logger="authentikate.provenance.verify"):
        result = await aauthenticate_provenance_header_or_none(
            {"rekuest-task": token}, settings
        )
    assert result is None
    assert "ProvenanceAudienceError" in caplog.records[0].getMessage()


@pytest.mark.asyncio
async def test_or_none_not_configured_logs_and_returns_none(ed_key, bare_settings, caplog):
    token = _sign(ed_key, _provenance_claims())
    with caplog.at_level(logging.WARNING, logger="authentikate.provenance.verify"):
        result = await aauthenticate_provenance_header_or_none(
            {"rekuest-task": token}, bare_settings
        )
    assert result is None
    assert "ProvenanceNotConfiguredError" in caplog.records[0].getMessage()


# --- fail-closed extraction (raises on a present-but-invalid token) ----------


@pytest.mark.asyncio
async def test_or_raise_returns_token_when_valid(ed_key, settings):
    token = _sign(ed_key, _provenance_claims())
    decoded = await aauthenticate_provenance_header_or_raise(
        {"rekuest-task": token}, settings
    )
    assert decoded is not None
    assert decoded.sub == "user-42"


@pytest.mark.asyncio
async def test_or_raise_absent_returns_none(settings):
    # No provenance header present at all -> proceed unprovenanced.
    assert await aauthenticate_provenance_header_or_raise({}, settings) is None


@pytest.mark.asyncio
async def test_or_raise_invalid_signature_raises(other_ed_key, settings):
    token = _sign(other_ed_key, _provenance_claims())
    with pytest.raises(errors.ProvenanceValidationError) as exc_info:
        await aauthenticate_provenance_header_or_raise(
            {"rekuest-task": token}, settings
        )
    # The specific underlying failure is chained as the cause.
    assert isinstance(exc_info.value.__cause__, errors.InvalidProvenanceTokenError)


@pytest.mark.asyncio
async def test_or_raise_expired_raises(ed_key, settings):
    now = int(datetime.datetime.now().timestamp())
    token = _sign(ed_key, _provenance_claims(iat=now - 7200, exp=now - 3600))
    with pytest.raises(errors.ProvenanceValidationError) as exc_info:
        await aauthenticate_provenance_header_or_raise(
            {"rekuest-task": token}, settings
        )
    assert isinstance(exc_info.value.__cause__, errors.AuthentikateTokenExpired)


@pytest.mark.asyncio
async def test_or_raise_malformed_raises(ed_key, settings):
    claims = _provenance_claims()
    claims.pop("tsk")
    token = _sign(ed_key, claims)
    with pytest.raises(errors.ProvenanceValidationError) as exc_info:
        await aauthenticate_provenance_header_or_raise(
            {"rekuest-task": token}, settings
        )
    assert isinstance(exc_info.value.__cause__, errors.MalformedProvenanceTokenError)


@pytest.mark.asyncio
async def test_or_raise_audience_mismatch_raises(ed_key, settings):
    token = _sign(ed_key, _provenance_claims(aud=["someone-else"]))
    with pytest.raises(errors.ProvenanceValidationError) as exc_info:
        await aauthenticate_provenance_header_or_raise(
            {"rekuest-task": token}, settings
        )
    assert isinstance(exc_info.value.__cause__, errors.ProvenanceAudienceError)


@pytest.mark.asyncio
async def test_or_raise_not_configured_raises(ed_key, bare_settings):
    token = _sign(ed_key, _provenance_claims())
    with pytest.raises(errors.ProvenanceValidationError) as exc_info:
        await aauthenticate_provenance_header_or_raise(
            {"rekuest-task": token}, bare_settings
        )
    assert isinstance(exc_info.value.__cause__, errors.ProvenanceNotConfiguredError)


# --- algorithm pinning at config time (RFC 8725) -----------------------------


def test_default_algorithm_is_eddsa(ed_key):
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    settings = AuthentikateSettings(
        issuers=[{"iss": "lok", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
        provenance={"issuers": [{"iss": "rekuest", "kind": "jwks_dict", "jwks": {"keys": [pub]}}]},
    )
    assert settings.provenance is not None
    assert settings.provenance.algorithms == ["EdDSA"]


@pytest.mark.parametrize("bad", [["none"], ["NONE"], [" none "], ["EdDSA", "none"], []])
def test_rejects_unsafe_algorithm_config(ed_key, bad):
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    with pytest.raises(ValidationError):
        AuthentikateSettings(
            issuers=[{"iss": "lok", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
            provenance={
                "issuers": [{"iss": "rekuest", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
                "algorithms": bad,
            },
        )


# --- raw is authoritative, not spoofable via a claim -------------------------


def test_raw_claim_cannot_override_actual_token(ed_key, settings):
    token = _sign(ed_key, _provenance_claims(raw="spoofed-raw-value"))
    decoded = decode_provenance_token(token, settings)
    assert decoded.raw == token
    assert decoded.raw != "spoofed-raw-value"
