"""slopguard: verify AI-generated code.

``import slopguard`` is cheap. The API names below load on first use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "1.0.0rc1"

if TYPE_CHECKING:
    from slopguard.api import Config, Finding, ScanResult, Severity, scan, scan_source

_API = {"Config", "Finding", "ScanResult", "Severity", "scan", "scan_source"}
__all__ = ["Config", "Finding", "ScanResult", "Severity", "__version__", "scan", "scan_source"]


def __getattr__(name: str) -> Any:
    if name in _API:
        from slopguard import api

        return getattr(api, name)
    raise AttributeError(f"module 'slopguard' has no attribute {name!r}")
