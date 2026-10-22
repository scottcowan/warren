# warren-managed prompt/banner (bash) — single source of truth for bash, mirrors
# warren_banner.zsh exactly in content/behavior.
#
# R25: the zsh sibling of this file is sourced by both the locally-written
# workspace .zshrc (warren_cli.dispatch._connect_via_execvp, regenerated on every
# `warren connect`) and the .zshrc baked into warren's own remote images
# (images/warren-docker-base, packages/warren-server/images/ecs-base) -- but
# ProjectConfig.app defaults to "bash" (warren_common/models.py), and that zsh-only
# banner never fires for a template that leaves `app` unset, so most workspaces
# showed no banner/prompt at all on local connect. This gives bash the same
# treatment: reads WARREN_PROJECT/WARREN_TEMPLATE/WARREN_WORKSPACE_ID from the
# environment at shell-start time rather than being templated per-workspace, so the
# identical file works whether it was just written for this one workspace or baked
# into an image shared by every workspace that runs it.
PS1='\[\e[36m\]⬡\[\e[0m\] \[\e[33m\]${WARREN_PROJECT}\[\e[0m\] \[\e[34m\]\w\[\e[0m\] \$ '

echo ''
echo "  🐰  warren  ${WARREN_PROJECT} / ${WARREN_TEMPLATE}  [${WARREN_WORKSPACE_ID:0:8}]"
echo ''
