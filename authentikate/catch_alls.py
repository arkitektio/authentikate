"""The scope and the role that stand for every other one of this service.

A service declares one scope that grants an app everything it offers (``mikro_all``) and one role
that lets a member do everything in it (``mikro_admin``). Fields keep naming what they need
(``mikro_write``, ``mikro_editor``), which is what the ``@auth`` directive publishes; the check
lets the catch-alls through wherever one of those is asked for. A guest never passes on a role
this way: what a guest may do is what their collaborations hold.

A process serves one service, so the catch-alls are declared once, when its schema is built
(``arkitekt_service.graphql.annotate_schema`` does it from the service's contract).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatchAlls:
    """The scope and the role that pass every scope and role check here, when declared."""

    scope: str | None = None
    role: str | None = None


_declared = CatchAlls()


def declare_catch_alls(scope: str | None, role: str | None) -> None:
    """Say which scope and which role stand for every other one of this service."""
    global _declared
    _declared = CatchAlls(scope=scope, role=role)


def catch_alls() -> CatchAlls:
    """The catch-alls this service declared, or none."""
    return _declared


__all__ = ["CatchAlls", "catch_alls", "declare_catch_alls"]
