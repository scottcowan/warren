"""Local-mode secret store: secrets.env parser + SecretLoader CRUD."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import structlog

from .fileperms import restrict_to_owner

log = structlog.get_logger(__name__)

_LINE_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$"
)


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def parse_secrets_env(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        result[name] = _strip_quotes(value)
    return result


def _check_mode(path: Path) -> None:
    if os.name == "nt":
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode != 0o600:
        log.warning(
            "secrets_file_permissions_lax",
            path=str(path),
            mode=f"0o{mode:o}",
            expected="0o600",
        )


def _quote_value(value: str) -> str:
    if any(c in value for c in (' ', '#', '"')):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


class SecretLoader:
    @staticmethod
    def load_local(project_name: str, projects_dir: Path) -> dict[str, str]:
        path = Path(projects_dir) / project_name / "secrets.env"
        if not path.exists():
            return {}
        _check_mode(path)
        return parse_secrets_env(path.read_text(encoding="utf-8"))

    @staticmethod
    def add_local(
        project_name: str,
        secret_name: str,
        value: str,
        projects_dir: Path,
    ) -> None:
        proj_dir = Path(projects_dir) / project_name
        proj_dir.mkdir(parents=True, exist_ok=True)
        path = proj_dir / "secrets.env"

        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        lines = existing.split("\n") if existing else []
        # Drop a single trailing empty element caused by terminating newline
        if lines and lines[-1] == "":
            lines.pop()

        # newline in secret value not supported — deferred to Phase 3 store
        new_line = f"{secret_name}={_quote_value(value)}"
        replaced = False
        out_lines: list[str] = []
        for line in lines:
            m = _LINE_RE.match(line.rstrip("\r"))
            if m and m.group(1) == secret_name:
                out_lines.append(new_line)
                replaced = True
            else:
                out_lines.append(line)
        if not replaced:
            out_lines.append(new_line)

        path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        restrict_to_owner(path)

    @staticmethod
    def list_local(project_name: str, projects_dir: Path) -> list[str]:
        path = Path(projects_dir) / project_name / "secrets.env"
        if not path.exists():
            return []
        return list(parse_secrets_env(path.read_text(encoding="utf-8")).keys())

    @staticmethod
    def delete_local(
        project_name: str,
        secret_name: str,
        projects_dir: Path,
    ) -> bool:
        path = Path(projects_dir) / project_name / "secrets.env"
        if not path.exists():
            return False

        text = path.read_text(encoding="utf-8")
        trailing_newline = text.endswith("\n")
        lines = text.split("\n")
        if trailing_newline and lines and lines[-1] == "":
            lines.pop()

        out_lines: list[str] = []
        removed = False
        for line in lines:
            m = _LINE_RE.match(line.rstrip("\r"))
            if m and m.group(1) == secret_name:
                removed = True
                continue
            out_lines.append(line)

        if not removed:
            return False

        new_text = "\n".join(out_lines)
        if trailing_newline or new_text:
            new_text += "\n"
        path.write_text(new_text, encoding="utf-8")
        return True
