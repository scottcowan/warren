"""resolve_build_spec() unit tests (LIFE-04, D-09, T-04-04-PT)."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from warren.images.build_spec import BuildPathError, resolve_build_spec


def _settings(memory: str = "2g", cpus: float = 2.0) -> SimpleNamespace:
    return SimpleNamespace(image_build_memory=memory, image_build_cpus=cpus)


def _make_project(tmp_path: Path, name: str = "demo") -> Path:
    project_dir = tmp_path / name
    project_dir.mkdir()
    return project_dir


def test_deterministic_tag_reused_for_unchanged_containerfile(tmp_path: Path) -> None:
    project_dir = _make_project(tmp_path)
    (project_dir / "Containerfile").write_text("FROM debian:bookworm-slim\n")

    spec1 = resolve_build_spec("demo", "Containerfile", tmp_path, _settings())
    spec2 = resolve_build_spec("demo", "Containerfile", tmp_path, _settings())

    assert spec1.tag == spec2.tag
    assert spec1.tag.startswith("localhost/warren-project-demo:")


def test_edited_containerfile_produces_new_tag(tmp_path: Path) -> None:
    project_dir = _make_project(tmp_path)
    cf = project_dir / "Containerfile"
    cf.write_text("FROM debian:bookworm-slim\n")
    spec1 = resolve_build_spec("demo", "Containerfile", tmp_path, _settings())

    cf.write_text("FROM debian:bookworm-slim\nRUN echo hi\n")
    spec2 = resolve_build_spec("demo", "Containerfile", tmp_path, _settings())

    assert spec1.tag != spec2.tag


def test_traversal_path_rejected(tmp_path: Path) -> None:
    _make_project(tmp_path)
    with pytest.raises(BuildPathError):
        resolve_build_spec("demo", "../../../etc/shadow", tmp_path, _settings())


def test_absolute_path_rejected(tmp_path: Path) -> None:
    project_dir = _make_project(tmp_path)
    (project_dir / "Containerfile").write_text("FROM debian:bookworm-slim\n")
    with pytest.raises(BuildPathError):
        resolve_build_spec(
            "demo", str(project_dir / "Containerfile"), tmp_path, _settings()
        )


def test_symlink_escaping_project_directory_rejected(tmp_path: Path) -> None:
    project_dir = _make_project(tmp_path)
    outside = tmp_path / "outside.Containerfile"
    outside.write_text("FROM debian:bookworm-slim\n")
    link = project_dir / "Containerfile"
    os.symlink(outside, link)

    with pytest.raises(BuildPathError):
        resolve_build_spec("demo", "Containerfile", tmp_path, _settings())


def test_nonexistent_containerfile_rejected(tmp_path: Path) -> None:
    _make_project(tmp_path)
    with pytest.raises(BuildPathError):
        resolve_build_spec("demo", "Containerfile", tmp_path, _settings())


def test_memory_and_cpus_come_from_settings_not_project(tmp_path: Path) -> None:
    project_dir = _make_project(tmp_path)
    (project_dir / "Containerfile").write_text("FROM debian:bookworm-slim\n")

    spec = resolve_build_spec(
        "demo", "Containerfile", tmp_path, _settings(memory="512m", cpus=1.5)
    )

    assert spec.memory == "512m"
    assert spec.cpus == 1.5


def test_context_dir_is_project_root(tmp_path: Path) -> None:
    project_dir = _make_project(tmp_path)
    (project_dir / "Containerfile").write_text("FROM debian:bookworm-slim\n")

    spec = resolve_build_spec("demo", "Containerfile", tmp_path, _settings())

    assert spec.context_dir == project_dir.resolve()
    assert spec.containerfile == (project_dir / "Containerfile").resolve()
