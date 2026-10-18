"""The objects a scoped member was shared, as the issuer lists them in a token.

A member of an organization either acts for it (a *full* member) or was shared a
few of its objects and nothing else (a *scoped* member). lok marks the second kind
with an ``objects`` claim, keyed by the hub (its pk, as a string) whose services
host the objects::

    "objects": {"3": ["@mikro/arraydataset:42#derived", "@mikro/scene:7"]}

Each entry is ``<structure>:<id>[#<reach>][~<sharer>]``: the structure the object
is known by across the hub, its id, how far beyond the object itself the share
reaches (``self`` when left out), and who shared it (``~8``: user 8's, by their
``sub``)::

    @mikro/image:42             the image, sharer unsaid (an issuer before sharers)
    @mikro/image:42~8           the image, shared by 8
    @mikro/image:42#derived~8   and what was derived from it, shared by 8

A grant reaches no further than its sharer may: the issuer leaves out the grants
of a sharer who is no longer a full member, and a service narrows each grant by
what it knows of its sharer. What a reach covers is the hosting service's
business; here it is only parsed.

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

SHARER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
"""Who shared the object: their ``sub`` at the issuer."""

DEFAULT_REACH = "self"
"""The reach of a grant that names none: the object itself."""


@dataclass(frozen=True)
class ObjectGrant:
    """One shared object: ``@mikro/arraydataset:42#derived~8``."""

    structure: str
    object_id: str
    reach: str = DEFAULT_REACH
    sharer: str | None = None
    """The ``sub`` of who shared it; None when the issuer does not say."""

    def __str__(self) -> str:
        """The grant as the issuer writes it (``#self`` left out)."""
        reach = "" if self.reach == DEFAULT_REACH else f"#{self.reach}"
        sharer = "" if self.sharer is None else f"~{self.sharer}"
        return f"{self.structure}:{self.object_id}{reach}{sharer}"


def parse_grant(value: str) -> ObjectGrant:
    """Parse one entry of the ``objects`` claim.

    Raises
    ------
    ValueError
        When any part does not match the issuer's pattern. A caller drops such an
        entry: an unreadable grant shares nothing, it never widens a share.
    """
    # No other part can hold a `~` or a `#`, so each splits off unambiguously.
    rest, has_sharer, sharer = value.partition("~")
    body, has_reach, reach = rest.partition("#")
    structure, _, object_id = body.rpartition(":")
    if not has_reach:
        reach = DEFAULT_REACH
    if has_sharer and not SHARER_RE.fullmatch(sharer):
        raise ValueError(f"Not a sharer: {sharer!r}")
    if not STRUCTURE_RE.fullmatch(structure):
        raise ValueError(f"Not a grantable structure: {structure!r}")
    if not OBJECT_ID_RE.fullmatch(object_id):
        raise ValueError(f"Not a grantable object id: {object_id!r}")
    if not REACH_RE.fullmatch(reach):
        raise ValueError(f"Not a reach: {reach!r}")
    return ObjectGrant(structure, object_id, reach, sharer if has_sharer else None)


__all__ = [
    "DEFAULT_REACH",
    "OBJECT_ID_RE",
    "REACH_RE",
    "SHARER_RE",
    "STRUCTURE_RE",
    "ObjectGrant",
    "parse_grant",
]
