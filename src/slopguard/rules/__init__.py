"""Rule registry. Importing this package registers every built-in rule."""

from __future__ import annotations

from slopguard.models import Rule

_REGISTRY: dict[str, Rule] = {}


def register(cls: type[Rule]) -> type[Rule]:
    instance = cls()
    rule_id = instance.meta.id
    if rule_id in _REGISTRY:
        raise ValueError(f"duplicate rule id {rule_id}")
    _REGISTRY[rule_id] = instance
    return cls


def all_rules() -> list[Rule]:
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]


def get_rule(rule_id: str) -> Rule | None:
    return _REGISTRY.get(rule_id.upper())


from slopguard.rules import (  # noqa: E402,F401
    drift,
    hallucination,
    incomplete,
    llm_agents,
    llm_flow,
    secrets,
    virtual,
)
