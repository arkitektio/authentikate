"""The ``Client`` GraphQL type exposes no display name.

Clients are created from tokens (see ``expand.py``), which carry no name, so
the field was always null and a non-nullable declaration made every
``client { name }`` selection fail. It is gone rather than nullable.
"""

from authentikate.strawberry.types import Client


def test_client_type_has_no_name_field() -> None:
    """``Client`` exposes ``id``, ``clientId`` and ``release`` but no ``name``."""
    definition = Client.__strawberry_definition__  # type: ignore[attr-defined]
    names = {f.python_name for f in definition.fields}
    assert "name" not in names
    assert {"id", "client_id", "release"} <= names
