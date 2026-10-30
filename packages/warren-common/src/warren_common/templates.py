"""Template resolution — walk a dotted path through ProjectConfig.templates.

A named entry under `templates` is a full ProjectConfig itself (there is no
separate "intent" type), so resolving "develop" or "develop.claude" means
walking from the root, merging each level's explicitly-set fields onto the
accumulated parent as we go:

- scalars (description, docker_image, app, ecs_cpu, ecs_memory, ecs_storage,
  ecs_image, idle_ttl_seconds, idle_destroy_seconds, seed_prompt):
  child's value wins if the child set it, else the parent's carries through.
- lists (mounts, secrets, docker_networks, harnesses): parent's items first, then the
  child's appended — additive, not replaced.
- env: key-by-key merge, the child's value wins for a key both set.
- scope/aws/ssh: shallow key-merge (child's explicitly-set sub-fields
  override the parent's, parent's other sub-fields carry through) — a child
  adding `ssh: {agent: true}` to a parent's `ssh: {keys: [...]}` must not
  silently drop `keys`.

`templates` itself is never carried into the merged result — the thing you
provision is a flat ProjectConfig with no sub-templates of its own.
"""

from __future__ import annotations

from .errors import TemplateNotFoundError
from .models import AgentConfig, AwsConfig, ProjectConfig, ScopeConfig, SshConfig

_LIST_FIELDS = ("mounts", "secrets", "docker_networks", "harnesses")
_SHALLOW_MERGE_FIELDS = ("scope", "aws", "ssh", "agent")
_SHALLOW_MERGE_TYPES = {"scope": ScopeConfig, "aws": AwsConfig, "ssh": SshConfig, "agent": AgentConfig}
_DICT_MERGE_FIELDS = ("env",)


def _merge_fields(parent: ProjectConfig, child: ProjectConfig) -> dict:
    """Merge every field except `templates`/`name` from `child` onto `parent`'s
    dump, per the scalar-override/list-append/shallow-merge rules. Returns the
    merged dict (caller decides what to do with `templates`/`name`)."""
    merged = parent.model_dump()
    for field in child.model_fields_set:
        if field == "templates" or field == "name":
            continue
        child_value = getattr(child, field)
        if field in _LIST_FIELDS:
            parent_items = merged.get(field) or []
            child_items = [
                item.model_dump() if hasattr(item, "model_dump") else item
                for item in (child_value or [])
            ]
            merged[field] = [*parent_items, *child_items]
        elif field in _DICT_MERGE_FIELDS:
            merged[field] = {**(merged.get(field) or {}), **(child_value or {})}
        elif field in _SHALLOW_MERGE_FIELDS:
            if child_value is None:
                merged[field] = None
                continue
            parent_sub = merged.get(field) or {}
            child_sub = {
                k: getattr(child_value, k) for k in child_value.model_fields_set
            }
            merged[field] = {**parent_sub, **child_sub}
        else:
            merged[field] = child_value
    return merged


def _merge_one(parent: ProjectConfig, child: ProjectConfig) -> ProjectConfig:
    merged = _merge_fields(parent, child)
    merged["templates"] = {}
    merged["name"] = child.name or parent.name
    return ProjectConfig.model_validate(merged)


def merge_projects(base: ProjectConfig, overlay: ProjectConfig) -> ProjectConfig:
    """Merge a user-scoped overlay project onto a server-wide base project.

    Same field rules as template resolution (scalars override, lists append,
    scope/aws/ssh shallow-merge) — but unlike resolving one template path to a
    leaf, `templates` here is a dict UNION by key: a key present only on one
    side carries through unchanged, a key present on both recurses through
    merge_projects again. This lets a user's overlay add a new template
    (e.g. `claude`) to a server-wide project without redeclaring the ones it
    didn't touch (e.g. `observe`, `develop`).
    """
    merged = _merge_fields(base, overlay)
    merged_templates: dict[str, ProjectConfig] = dict(base.templates)
    for key, overlay_child in overlay.templates.items():
        if key in merged_templates:
            merged_templates[key] = merge_projects(merged_templates[key], overlay_child)
        else:
            merged_templates[key] = overlay_child
    merged["templates"] = {k: v.model_dump() for k, v in merged_templates.items()}
    merged["name"] = overlay.name or base.name
    return ProjectConfig.model_validate(merged)


def resolve_template(root: ProjectConfig, path: str, *, validate: bool = True) -> ProjectConfig:
    """Resolve a dotted template path (e.g. "develop" or "develop.claude").

    Raises TemplateNotFoundError (naming the exact missing segment and the
    full path requested) if any segment along the way doesn't exist.
    """
    accumulated = root
    node = root
    segments = path.split(".")
    for i, segment in enumerate(segments):
        if segment not in node.templates:
            raise TemplateNotFoundError(
                f"template {segment!r} not found (path={path!r})"
            )
        child = node.templates[segment]
        accumulated = _merge_one(accumulated, child)
        node = child
    if validate:
        accumulated.validate_harnesses()
    return accumulated


def list_template_paths(root: ProjectConfig, _prefix: str = "") -> list[str]:
    """Return every dotted template path reachable from root, depth-first."""
    paths: list[str] = []
    for name, child in root.templates.items():
        path = f"{_prefix}{name}"
        paths.append(path)
        paths.extend(list_template_paths(child, _prefix=f"{path}."))
    return paths
