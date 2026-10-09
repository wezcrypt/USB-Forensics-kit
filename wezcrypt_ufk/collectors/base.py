"""Collector base class and registry."""

from __future__ import annotations

from typing import Dict, List, Type

from ..core.context import CollectionContext


class Collector:
    name: str = ""
    title: str = ""
    category: str = ""
    description: str = ""
    requires_admin: str = "no"  # no | partial | yes
    admin_note: str = ""
    windows_only: bool = True
    default_enabled: bool = True

    def run(self, ctx: CollectionContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    @classmethod
    def info(cls) -> Dict:
        return {
            "name": cls.name, "title": cls.title, "category": cls.category, "description": cls.description,
            "requires_admin": cls.requires_admin, "admin_note": cls.admin_note, "windows_only": cls.windows_only,
            "default_enabled": cls.default_enabled,
        }


_REGISTRY: Dict[str, Type[Collector]] = {}


def register(cls: Type[Collector]) -> Type[Collector]:
    if not cls.name:
        raise ValueError("collector without name")
    _REGISTRY[cls.name] = cls
    return cls


def all_collectors() -> List[Type[Collector]]:
    from . import load_all  # noqa: F401  (import side effects register collectors)

    load_all()
    return list(_REGISTRY.values())


def get_collector(name: str) -> Type[Collector]:
    all_collectors()
    if name not in _REGISTRY:
        raise KeyError(f"unknown module '{name}'")
    return _REGISTRY[name]
