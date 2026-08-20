"""Tests for the package's public API surface and its typing contract.

Two things are guarded here that only fail at a distance otherwise:

- the top-level exports must resolve *lazily*, because Django imports this
  package before the app registry is ready;
- the concrete models must satisfy the structural protocols kante declares,
  which is otherwise only checked by a type checker nobody runs in CI.
"""

import subprocess
import sys
from pathlib import Path

import pytest

import authentikate

PACKAGE_ROOT = Path(authentikate.__file__).parent


def _kante_has_variance_fix() -> bool:
    """Whether the installed kante carries the protocol fixes (>= 2.1.1).

    Keyed on the capability rather than a version string, so the guard below
    switches itself on the moment a fixed kante is installed -- including a local
    checkout on PYTHONPATH -- and does not need touching when the pin moves.
    """
    from kante import context

    # On an unfixed kante ``act`` is a plain annotation, so it is not a class
    # attribute at all -- hence getattr with a default rather than direct access.
    return isinstance(getattr(context.Provenance, "act", None), property)


requires_fixed_kante = pytest.mark.skipif(
    not _kante_has_variance_fix(),
    reason=(
        "needs kante >= 2.1.1: Client.id must be int and Provenance/Actor "
        "members must be read-only properties"
    ),
)


# --- public API --------------------------------------------------------------


def test_every_exported_name_resolves() -> None:
    """`__all__` must not promise a name that cannot be imported."""
    for name in authentikate.__all__:
        assert getattr(authentikate, name) is not None, name


def test_all_matches_the_export_table() -> None:
    """The hand-written `__all__` literal must stay in step with `_EXPORTS`.

    `__all__` is spelled out rather than computed so static tools can read it,
    which means the two can drift apart without anything noticing.
    """
    assert authentikate.__all__ == sorted(authentikate._EXPORTS)


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError, match="has no attribute"):
        authentikate.does_not_exist


def test_dir_lists_the_public_names() -> None:
    assert set(authentikate.__all__) <= set(dir(authentikate))


def test_importing_the_package_does_not_import_models() -> None:
    """The exports must stay lazy.

    ``authentikate`` is in INSTALLED_APPS, so Django imports it *before* the app
    registry is ready. Eagerly importing anything that reaches
    ``authentikate.models`` raises ``AppRegistryNotReady`` and breaks startup for
    every project using this library. Run in a subprocess because the test
    session has already imported everything.
    """
    code = (
        "import os, sys;"
        "os.environ['DJANGO_SETTINGS_MODULE']='test_project.settings';"
        "import authentikate;"
        "print('authentikate.models' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=PACKAGE_ROOT.parent,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False", (
        "authentikate.models was imported at package-import time; the top-level "
        "exports must stay lazy (see the NOTE in authentikate/__init__.py)"
    )


def test_ships_py_typed() -> None:
    """PEP 561: without this marker consumers get no types from this package."""
    assert (PACKAGE_ROOT / "py.typed").is_file()


# --- structural conformance with kante ---------------------------------------


@requires_fixed_kante
def test_models_satisfy_the_kante_protocols() -> None:
    """Guard the two kante protocol bugs this release fixed.

    kante declares the principals as protocols that authentikate fills in. Both
    of these silently regressed before:

    - ``Client.id`` was typed ``str`` while our pk is an ``int``;
    - ``Provenance``'s members were settable, hence invariant, so
      ``ProvenanceToken`` could not satisfy it despite matching structurally.

    Neither breaks at runtime, so without this test the only signal is a mypy
    run. Checking with ``assert_type``-style assignments inside a type checker is
    the real test; here we assert the shapes agree so a future kante bump that
    reintroduces either one fails loudly.
    """
    from kante import context as kante_context

    from authentikate.models import Client, Membership, Organization, User
    from authentikate.provenance.models import ProvenanceToken

    def return_type(protocol: type, name: str) -> object:
        member = getattr(protocol, name)
        # Read-only protocol members are properties; grab the getter's return.
        return member.fget.__annotations__["return"]

    assert return_type(kante_context.Client, "id") is int, (
        "kante.context.Client.id must be int -- authentikate's Client has an "
        "integer primary key"
    )
    for protocol, name in (
        (kante_context.User, "id"),
        (kante_context.Organization, "id"),
        (kante_context.Membership, "id"),
    ):
        assert return_type(protocol, name) is int

    # Every Provenance/Actor member must be read-only (a property), because a
    # settable member is invariant and nothing could then satisfy it.
    for name in ("iss", "aud", "sub", "act", "iat", "exp", "jti", "tsk", "raw"):
        assert isinstance(getattr(kante_context.Provenance, name), property), (
            f"kante.context.Provenance.{name} must be a read-only property; a "
            "settable member is invariant and ProvenanceToken cannot satisfy it"
        )
    for name in ("sub", "cid"):
        assert isinstance(getattr(kante_context.Actor, name), property)

    # And the concrete models really do carry what the protocols ask for.
    for model, members in (
        (User, ("id", "sub", "is_anonymous")),
        (Client, ("id", "client_id")),
        (Organization, ("id", "slug")),
        (Membership, ("id",)),
    ):
        for member in members:
            assert hasattr(model, member) or member in {
                f.name for f in model._meta.get_fields()
            }, f"{model.__name__} is missing {member}"

    for member in ("iss", "aud", "sub", "act", "iat", "exp", "jti", "tsk", "raw"):
        assert member in ProvenanceToken.model_fields
