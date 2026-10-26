"""PyPI existence lookups with an on-disk cache."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

Fetcher = Callable[[str], "int | None"]
JsonFetcher = Callable[[str], "dict | None"]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def default_cache_path() -> Path:
    base = os.environ.get("SLOPGUARD_CACHE_DIR")
    if base:
        return Path(base) / "registry.json"
    xdg = os.environ.get("XDG_CACHE_HOME")
    root = Path(xdg) if xdg else Path.home() / ".cache"
    return root / "slopguard" / "registry.json"


def fetch_pypi_status(name: str) -> int | None:
    """Return the HTTP status for the project page, or None when unreachable."""
    url = f"https://pypi.org/pypi/{normalize(name)}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "slopguard"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def fetch_pypi_json(name: str) -> dict | None:
    """Return the PyPI JSON document for a project, or None when unavailable."""
    url = f"https://pypi.org/pypi/{normalize(name)}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "slopguard"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def earliest_upload(document: dict) -> datetime | None:
    times = []
    for files in document.get("releases", {}).values():
        for item in files:
            stamp = item.get("upload_time_iso_8601") or item.get("upload_time")
            if stamp:
                try:
                    times.append(datetime.fromisoformat(stamp.replace("Z", "+00:00")))
                except ValueError:
                    continue
    return min(times) if times else None


class RegistryClient:
    """Answers "does this distribution exist on PyPI?" as True, False or None (unknown)."""

    def __init__(
        self,
        cache_path: Path | None = None,
        ttl_hours: int = 24,
        fetcher: Fetcher = fetch_pypi_status,
        json_fetcher: JsonFetcher = fetch_pypi_json,
    ) -> None:
        self.cache_path = cache_path or default_cache_path()
        self.ttl_seconds = ttl_hours * 3600
        self.fetcher = fetcher
        self.json_fetcher = json_fetcher
        self._cache: dict[str, dict] | None = None
        self._dirty = False

    def exists(self, name: str) -> bool | None:
        key = normalize(name)
        cache = self._load()
        entry = cache.get(key)
        if entry and time.time() - entry["checked"] < self.ttl_seconds:
            return entry["exists"]
        status = self.fetcher(key)
        if status == 200:
            result: bool | None = True
        elif status == 404:
            result = False
        else:
            return None
        cache[key] = {"exists": result, "checked": time.time()}
        self._dirty = True
        return result

    def first_release(self, name: str) -> datetime | None:
        """When the project's first file was uploaded, or None if unknown."""
        key = normalize(name)
        cache = self._load()
        entry = cache.get(key, {})
        fresh = time.time() - entry.get("released_checked", 0) < self.ttl_seconds
        if "first_release" in entry and fresh:
            stamp = entry["first_release"]
            return datetime.fromisoformat(stamp) if stamp else None
        document = self.json_fetcher(key)
        if document is None:
            return None
        born = earliest_upload(document)
        entry = cache.setdefault(key, {"exists": True, "checked": time.time()})
        entry["first_release"] = born.isoformat() if born else None
        entry["released_checked"] = time.time()
        self._dirty = True
        return born

    def save(self) -> None:
        if not self._dirty or self._cache is None:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=1))
        except OSError:  # slopguard: ignore[INC-04] the cache is best-effort
            pass

    def _load(self) -> dict[str, dict]:
        if self._cache is None:
            try:
                self._cache = json.loads(self.cache_path.read_text())
            except (OSError, ValueError):
                self._cache = {}
        return self._cache
