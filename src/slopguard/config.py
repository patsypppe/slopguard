"""Configuration loading from ``slopguard.toml`` or ``[tool.slopguard]``."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from slopguard.models import Severity

MODULES = ("hal", "inc", "sec", "llm", "drf", "spc", "reg")
DEFAULT_OFF = frozenset({"drf"})  # opt-in: needs a representative baseline of the repo

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".output",
        "target",
        "vendor",
        ".eggs",
    }
)


class ConfigError(Exception):
    """Raised when the configuration file is invalid."""


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    fail_on: str = "high"
    modules: dict[str, bool] = field(
        default_factory=lambda: {m: m not in DEFAULT_OFF for m in MODULES}
    )
    registry_lookups: bool = True
    cache_ttl_hours: int = 24
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    taint_sources: list[str] = field(default_factory=list)
    taint_sinks: list[str] = field(default_factory=list)
    taint_sanitizers: list[str] = field(default_factory=list)
    private_packages: list[str] = field(default_factory=list)
    llm_provider: str = "none"
    llm_model: str = ""
    llm_base_url: str = ""
    sandbox_backend: str = "auto"
    sandbox_image: str = "python:3.12-slim"
    sandbox_timeout: int = 120
    source_file: Path | None = None

    def rule_options(self, rule_id: str) -> dict[str, Any]:
        return self.rules.get(rule_id, {})

    def rule_enabled(self, rule_id: str) -> bool:
        return self.rule_options(rule_id).get("enabled", True)

    def fail_threshold(self) -> Severity | None:
        return None if self.fail_on == "none" else Severity.parse(self.fail_on)

    @classmethod
    def from_mapping(cls, data: dict[str, Any], source: Path | None = None) -> Config:
        cfg = cls(source_file=source)
        scan = _table(data, "scan")
        cfg.exclude = _str_list(scan, "exclude")
        if "fail_on" in scan:
            value = str(scan["fail_on"]).lower()
            if value != "none":
                try:
                    Severity.parse(value)
                except ValueError as exc:
                    raise ConfigError(f"scan.fail_on: {exc}") from exc
            cfg.fail_on = value

        modules = _table(data, "modules")
        for name, enabled in modules.items():
            if name not in MODULES:
                raise ConfigError(f"modules.{name}: unknown module (expected one of {MODULES})")
            if not isinstance(enabled, bool):
                raise ConfigError(f"modules.{name}: expected true or false")
            cfg.modules[name] = enabled

        network = _table(data, "network")
        if "registry_lookups" in network:
            cfg.registry_lookups = bool(network["registry_lookups"])
        if "cache_ttl_hours" in network:
            ttl = network["cache_ttl_hours"]
            if not isinstance(ttl, int) or ttl < 0:
                raise ConfigError("network.cache_ttl_hours: expected a non-negative integer")
            cfg.cache_ttl_hours = ttl

        cfg.private_packages = _str_list(_table(data, "packages"), "private")

        llm = _table(data, "llm")
        if "provider" in llm:
            provider = str(llm["provider"]).lower()
            if provider not in ("none", "anthropic", "openai", "ollama"):
                raise ConfigError("llm.provider: expected none, anthropic, openai or ollama")
            cfg.llm_provider = provider
        cfg.llm_model = str(llm.get("model", cfg.llm_model))
        cfg.llm_base_url = str(llm.get("base_url", cfg.llm_base_url))

        sandbox = _table(data, "sandbox")
        backend = str(sandbox.get("backend", cfg.sandbox_backend)).lower()
        if backend not in ("auto", "docker", "unshare", "local"):
            raise ConfigError("sandbox.backend: expected auto, docker, unshare or local")
        cfg.sandbox_backend = backend
        cfg.sandbox_image = str(sandbox.get("image", cfg.sandbox_image))
        timeout = sandbox.get("timeout", cfg.sandbox_timeout)
        if not isinstance(timeout, int) or timeout < 1:
            raise ConfigError("sandbox.timeout: expected a positive integer (seconds)")
        cfg.sandbox_timeout = timeout

        rules = _table(data, "rules")
        for rule_id, options in rules.items():
            if not isinstance(options, dict):
                raise ConfigError(f"rules.{rule_id}: expected a table")
            cfg.rules[rule_id] = dict(options)

        for key, attr in (("sources", "taint_sources"), ("sinks", "taint_sinks"),
                          ("sanitizers", "taint_sanitizers")):
            setattr(cfg, attr, _str_list(_table(data, f"taint.{key}"), "extra"))
        return cfg

    @classmethod
    def load(cls, root: Path, explicit: Path | None = None) -> Config:
        if explicit is not None:
            if not explicit.is_file():
                raise ConfigError(f"config file not found: {explicit}")
            return cls._from_file(explicit)
        candidate = root / "slopguard.toml"
        if candidate.is_file():
            return cls._from_file(candidate)
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            data = _read_toml(pyproject)
            section = data.get("tool", {}).get("slopguard")
            if isinstance(section, dict):
                return cls.from_mapping(section, pyproject)
        return cls()

    @classmethod
    def _from_file(cls, path: Path) -> Config:
        data = _read_toml(path)
        if path.name == "pyproject.toml":
            data = data.get("tool", {}).get("slopguard", {})
        return cls.from_mapping(data, path)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc


def _table(data: dict[str, Any], dotted: str) -> dict[str, Any]:
    node: Any = data
    for part in dotted.split("."):
        node = node.get(part, {}) if isinstance(node, dict) else {}
    if not isinstance(node, dict):
        raise ConfigError(f"{dotted}: expected a table")
    return node


def _str_list(table: dict[str, Any], key: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key}: expected a list of strings")
    return list(value)


STARTER_CONFIG = """\
# slopguard configuration. See docs/PRD for every option.

[scan]
exclude = ["tests/fixtures/**"]
fail_on = "high"            # critical | high | medium | low | info | none

[modules]
hal = true                  # hallucinated or undeclared packages
inc = true                  # stubs, placeholders, swallowed errors
sec = true                  # hardcoded secrets
llm = true                  # model output reaching dangerous sinks
drf = false                 # style drift against the rest of the repo (opt-in)

[network]
registry_lookups = true     # query PyPI to check that imports exist
cache_ttl_hours = 24

# [packages]
# private = ["my_company_lib"]   # imports from a private index: skipped by the HAL rules

# [llm]                      # only used by --spec judging, gen-tests and fix
# provider = "anthropic"     # anthropic | openai | ollama | none
# model = "your-model-id"    # no default: model names change, set the one you use
#
# [sandbox]                  # where generated tests run
# backend = "auto"           # auto | docker | unshare | local
# timeout = 120

# [rules."INC-06"]
# threshold = 5

# [taint.sources]
# extra = ["myapp.llm.ask"]
# [taint.sinks]
# extra = ["myapp.runner.run_command"]
# [taint.sanitizers]
# extra = ["myapp.safety.validate_command"]
"""
