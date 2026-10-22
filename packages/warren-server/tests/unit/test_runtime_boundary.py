"""Phase 1 Success Criteria #3 regression coverage.

Proves the `ContainerRuntime` abstraction is the ONLY path routes/registry code
uses to reach Podman: no file under `src/warren/` imports the raw `podman`
package except the two files whose job is exactly that.

Pure static text scan — stdlib `pathlib` only, no I/O beyond reading `.py`
files already on disk, no `PODMAN_SOCKET` or live Podman socket required.
"""

from __future__ import annotations

from pathlib import Path

_ALLOWED_PODMAN_FILES = {
    "src/warren/runtime/podman.py",
    "src/warren/preflight.py",
}

_PODMAN_IMPORT_MARKERS = ("import podman", "from podman")


def _repo_root() -> Path:
    # tests/unit/test_runtime_boundary.py -> parents[0]=unit, [1]=tests, [2]=repo root
    return Path(__file__).parents[2]


def test_no_podman_leakage_outside_runtime_and_preflight() -> None:
    repo_root = _repo_root()
    warren_src = repo_root / "src" / "warren"

    offenders: list[str] = []
    for path in sorted(warren_src.rglob("*.py")):
        rel_path = path.relative_to(repo_root).as_posix()
        if rel_path in _ALLOWED_PODMAN_FILES:
            continue
        text = path.read_text()
        if any(marker in text for marker in _PODMAN_IMPORT_MARKERS):
            offenders.append(rel_path)

    assert not offenders, (
        f"podman-specific import leaked outside runtime/preflight: {offenders}"
    )


def test_routes_and_registry_never_import_podman_directly() -> None:
    repo_root = _repo_root()
    named_files = [
        "src/warren/routes/workspaces.py",
        "src/warren/registry/registry.py",
        "src/warren/registry/reconcile.py",
        "src/warren/registry/store.py",
    ]

    offenders: list[str] = []
    for rel_path in named_files:
        path = repo_root / rel_path
        text = path.read_text()
        if any(marker in text for marker in _PODMAN_IMPORT_MARKERS):
            offenders.append(rel_path)

    assert not offenders, (
        f"routes/registry code must never import podman directly: {offenders}"
    )


def test_composition_root_still_references_podman_runtime() -> None:
    repo_root = _repo_root()
    app_text = (repo_root / "src" / "warren" / "app.py").read_text()

    assert "PodmanRuntime" in app_text
