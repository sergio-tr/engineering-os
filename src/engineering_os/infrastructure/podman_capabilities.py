"""Version-aware Podman capability detection (EOS-11).

Pasta network mode requires Podman >= 4.4.1. Installing the passt package alone
does not add pasta support to Podman 3.4.4. Pasta also is not a destination
deny-by-default firewall by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple
import re
import shutil
import subprocess


PASTA_MIN_VERSION = (4, 4, 1)
PODMAN_34 = (3, 4, 4)


def parse_podman_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse `podman version X.Y.Z` or bare `X.Y.Z`."""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def version_tuple_to_str(version: Optional[Tuple[int, int, int]]) -> Optional[str]:
    if not version:
        return None
    return ".".join(str(x) for x in version)


def version_at_least(
    observed: Optional[Tuple[int, int, int]],
    minimum: Tuple[int, int, int],
) -> bool:
    if observed is None:
        return False
    return observed >= minimum


@dataclass
class PodmanCapabilities:
    podman_path: Optional[str]
    version: Optional[Tuple[int, int, int]]
    rootless: Optional[bool]
    pasta_binary_present: bool
    passt_binary_present: bool
    pasta_network_mode_supported: bool
    network_none_supported: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "podman_path": self.podman_path,
            "version": version_tuple_to_str(self.version),
            "version_tuple": list(self.version) if self.version else None,
            "rootless": self.rootless,
            "pasta_binary_present": self.pasta_binary_present,
            "passt_binary_present": self.passt_binary_present,
            "pasta_network_mode_supported": self.pasta_network_mode_supported,
            "pasta_min_version": version_tuple_to_str(PASTA_MIN_VERSION),
            "pasta_is_destination_firewall": False,
            "network_none_supported": self.network_none_supported,
            "recommended_egress": (
                "uds_broker_network_none"
                if self.network_none_supported
                else "unavailable"
            ),
            "error": self.error,
            "notes": [
                "Installing passt alone does not enable pasta on Podman < 4.4.1",
                "Pasta networking is not a deny-by-default destination firewall",
                "HTTP_PROXY alone is not network isolation",
            ],
        }


def probe_podman_capabilities(
    *,
    which: Optional[Callable[[str], Optional[str]]] = None,
    version_runner: Optional[Callable[[], str]] = None,
    info_runner: Optional[Callable[[], Dict[str, Any]]] = None,
) -> PodmanCapabilities:
    which_fn = which or shutil.which
    podman_path = which_fn("podman")
    pasta_bin = bool(which_fn("pasta"))
    passt_bin = bool(which_fn("passt"))
    if not podman_path:
        return PodmanCapabilities(
            podman_path=None,
            version=None,
            rootless=None,
            pasta_binary_present=pasta_bin,
            passt_binary_present=passt_bin,
            pasta_network_mode_supported=False,
            network_none_supported=False,
            error="podman_missing",
        )

    version_text = ""
    try:
        if version_runner:
            version_text = version_runner()
        else:
            proc = subprocess.run(
                ["podman", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            version_text = (proc.stdout or proc.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001
        return PodmanCapabilities(
            podman_path=podman_path,
            version=None,
            rootless=None,
            pasta_binary_present=pasta_bin,
            passt_binary_present=passt_bin,
            pasta_network_mode_supported=False,
            network_none_supported=True,  # historical EOS-08 path works on 3.4.4
            error=f"version_probe_failed:{exc}",
        )

    version = parse_podman_version(version_text)
    rootless: Optional[bool] = None
    try:
        if info_runner:
            info = info_runner()
        else:
            proc = subprocess.run(
                ["podman", "info", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            info = {}
            if proc.returncode == 0 and proc.stdout.strip():
                import json as _json

                info = _json.loads(proc.stdout)
        host = info.get("host") if isinstance(info.get("host"), dict) else {}
        security = host.get("security") if isinstance(host.get("security"), dict) else {}
        if "rootless" in security:
            rootless = bool(security.get("rootless"))
        elif "rootless" in host:
            rootless = bool(host.get("rootless"))
    except Exception:
        rootless = None

    pasta_supported = version_at_least(version, PASTA_MIN_VERSION)
    return PodmanCapabilities(
        podman_path=podman_path,
        version=version,
        rootless=rootless,
        pasta_binary_present=pasta_bin,
        passt_binary_present=passt_bin,
        pasta_network_mode_supported=pasta_supported,
        network_none_supported=True,
        error=None,
    )
