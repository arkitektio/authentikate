"""Provenance-token verification (consuming / audience end).

Audience servers (e.g. Mikro / koherent) receive an EdDSA-signed provenance
token minted by Rekuest alongside the cleartext args, and record a verified
provenance fact offline against Rekuest's published JWKS. This subpackage
provides that decode/verify path:

- :func:`decode_provenance_token` / :func:`adecode_provenance_token` verify the
  signature against the configured provenance issuers and return a
  :class:`ProvenanceToken`.
- :func:`verify_actor` binds the token's actor to the presenting auth token.
- :func:`verify_args` recomputes the args hash against the cleartext args.

Configure a ``PROVENANCE`` block under the ``AUTHENTIKATE`` Django setting; see
:class:`authentikate.base_models.ProvenanceSettings`.
"""

from authentikate.provenance.canonical import (
    CANONICALIZATION_VERSION,
    args_hash,
    canonicalize_v1,
)
from authentikate.provenance.decode import (
    adecode_provenance_token,
    decode_provenance_token,
)
from authentikate.provenance.models import Actor, ProvenanceToken
from authentikate.provenance.verify import (
    aauthenticate_provenance_header,
    aauthenticate_provenance_header_or_none,
    aauthenticate_provenance_header_or_raise,
    verify_actor,
    verify_args,
)

__all__ = [
    "Actor",
    "ProvenanceToken",
    "decode_provenance_token",
    "adecode_provenance_token",
    "verify_actor",
    "verify_args",
    "aauthenticate_provenance_header",
    "aauthenticate_provenance_header_or_none",
    "aauthenticate_provenance_header_or_raise",
    "args_hash",
    "canonicalize_v1",
    "CANONICALIZATION_VERSION",
]
