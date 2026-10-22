"""`warren new --dry-run`: show what a provision would use, without provisioning (AH9).

Secret names only, never values (the values are never even loaded here).
"""

from __future__ import annotations

from typing import Any

import typer


def plan_for(template_cfg: Any, *, project: str, template: str, target: str, image: str) -> dict:
    return {
        "target": target,
        "project": project,
        "template": template,
        "image": image,
        "app": template_cfg.app,
        "folders": [
            {
                "name": f.name,
                "type": f.type,
                "mount": f.mount,
                "source": f.url or f.path or "",
                "branch": f.branch if f.type != "local-path" else None,
                "readonly": f.readonly,
            }
            for f in template_cfg.effective_folders()
        ],
        "mounts": [
            {"host": m.host, "container": m.container, "mode": m.mode} for m in template_cfg.mounts
        ],
        "secrets": list(dict.fromkeys(ref.name for ref in template_cfg.secrets)),
        "env": sorted(template_cfg.env),
        "seed_prompt": bool(getattr(template_cfg, "seed_prompt", None)),
    }


def print_plan(plan: dict) -> None:
    echo = typer.echo
    echo(f"dry run: {plan['project']}/{plan['template']} on {plan['target']} (nothing provisioned)")
    echo(f"  image:   {plan['image']}")
    echo(f"  app:     {plan['app']}")
    echo("  folders:" if plan["folders"] else "  folders: (none)")
    for f in plan["folders"]:
        ro = " ro" if f["readonly"] else ""
        branch = f"@{f['branch']}" if f["branch"] else ""
        echo(f"    ~/{f['mount']}  {f['type']}{ro}  {f['source']}{branch}")
    echo("  mounts:" if plan["mounts"] else "  mounts:  (none)")
    for m in plan["mounts"]:
        echo(f"    {m['host']} -> {m['container']} ({m['mode']})")
    echo(f"  secrets: {', '.join(plan['secrets']) if plan['secrets'] else '(none)'}")
    echo(f"  env:     {', '.join(plan['env']) if plan['env'] else '(none)'}")
    if plan["seed_prompt"]:
        echo("  seed_prompt: set")
