"""Reusable assignment **templates**.

A template is a named, portable set of Intune resources (a "thing that gets
assigned" — a collection of profiles, policies, apps, scripts, …). You build
one from a group's current assignments or hand-author it, then *stamp* any
device group onto the whole set in one shot. This is the "create a template for
assigned things and easily add different device groups to them" workflow.

Templates are plain JSON so they live happily in source control next to the
rest of this repo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .resources import REGISTRY_BY_KEY


@dataclass
class TemplateResource:
    resource_type: str
    name: str
    id: Optional[str] = None  # resolved at apply time if absent
    intent: Optional[str] = None  # apps only
    exclude: bool = False
    filter_name: Optional[str] = None
    filter_type: str = "include"

    def to_dict(self) -> Dict[str, Any]:
        d = {"resource_type": self.resource_type, "name": self.name}
        if self.id:
            d["id"] = self.id
        if self.intent:
            d["intent"] = self.intent
        if self.exclude:
            d["exclude"] = True
        if self.filter_name:
            d["filter_name"] = self.filter_name
            d["filter_type"] = self.filter_type
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TemplateResource":
        return cls(
            resource_type=d["resource_type"],
            name=d.get("name", ""),
            id=d.get("id"),
            intent=d.get("intent"),
            exclude=bool(d.get("exclude", False)),
            filter_name=d.get("filter_name"),
            filter_type=d.get("filter_type", "include"),
        )


@dataclass
class Template:
    name: str
    description: str = ""
    resources: List[TemplateResource] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "resources": [r.to_dict() for r in self.resources],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Template":
        unknown = [
            r.get("resource_type")
            for r in d.get("resources", [])
            if r.get("resource_type") not in REGISTRY_BY_KEY
        ]
        if unknown:
            raise ValueError(f"Template references unknown resource types: {sorted(set(unknown))}")
        return cls(
            name=d.get("name", "template"),
            description=d.get("description", ""),
            version=int(d.get("version", 1)),
            resources=[TemplateResource.from_dict(r) for r in d.get("resources", [])],
        )

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), "utf-8")

    @classmethod
    def load(cls, path: str) -> "Template":
        return cls.from_dict(json.loads(Path(path).read_text("utf-8")))

    def by_area(self) -> Dict[str, List[TemplateResource]]:
        out: Dict[str, List[TemplateResource]] = {}
        for r in self.resources:
            area = REGISTRY_BY_KEY[r.resource_type].area
            out.setdefault(area, []).append(r)
        return out
