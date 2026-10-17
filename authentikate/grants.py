"""The objects a scoped member was shared, as the issuer lists them in a token.

A member of an organization either acts for it (a *full* member) or was shared a
few of its objects and nothing else (a *scoped* member). lok marks the second kind
with an ``objects`` claim, keyed by the hub (its pk, as a string) whose services
host the objects::

    "objects": {"3": ["@mikro/arraydataset:42#derived", "@mikro/scene:7"]}

Each entry is ``<structure>:<id>[#<reach>]``: the structure the object is known by
across the hub, its id, and how far beyond the object itself the share reaches
(``self`` when left out). What a reach covers is the hosting service's business;
here it is only parsed.

The patterns are lok's own (``karakter/object_grants.py``), so that what lok
writes and what is read here cannot drift apart.
"""

import re
from dataclasses import dataclass

STRUCTURE_RE = re.compile(r"^@[a-z0-9][a-z0-9_.-]{0,63}/[a-z0-9][a-z0-9_.-]{0,127}$")
"""A structure a grant can name: ``@mikro/arraydataset``."""

OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
"""The id of the granted object, as the hosting service knows it."""

REACH_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
"""A reach: ``self``, ``derived``, ..."""

DEFAULT_REACH = "self"
"""The reach of a grant that names none: the object itself."""


@dataclass(frozen=True)
class ObjectGrant:
    """One shared object: ``@mikro/arraydataset:42#derived``."""

    structure: str
    object_id: str
    reach: str = DEFAULT_REACH

    def __str__(self) -> str:
        """The grant as the issuer writes it (``#self`` left out)."""
        suffix = "" if self.reach == DEFAULT_REACH else f"#{self.reach}"
        return f"{self.structure}:{self.object_id}{suffix}"


def parse_grant(value: str) -> ObjectGrant:
    """Parse one entry of the ``objects`` claim.

    Raises
    ------
    ValueError
        When any part does not match the issuer's pattern. A caller drops such an
        entry: an unreadable grant shares nothing, it never widens a share.
    """
    body, has_reach, reach = value.partition("#")
    structure, _, object_id = body.rpartition(":")
    if not has_reach:
        reach = DEFAULT_REACH
    if not STRUCTURE_RE.fullmatch(structure):
        raise ValueError(f"Not a grantable structure: {structure!r}")
    if not OBJECT_ID_RE.fullmatch(object_id):
        raise ValueError(f"Not a grantable object id: {object_id!r}")
    if not REACH_RE.fullmatch(reach):
        raise ValueError(f"Not a reach: {reach!r}")
    return ObjectGrant(structure, object_id, reach)


__all__ = [
    "DEFAULT_REACH",
    "OBJECT_ID_RE",
    "REACH_RE",
    "STRUCTURE_RE",
    "ObjectGrant",
    "parse_grant",
]
