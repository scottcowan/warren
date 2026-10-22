# warren-managed prompt/banner — single source of truth.
#
# Sourced by BOTH the locally-written workspace .zshrc (regenerated on every
# `warren connect`, see warren_cli.dispatch._connect_via_execvp) and the
# .zshrc baked into warren's own remote images (images/warren-docker-base,
# packages/warren-server/images/ecs-base), so there is one copy of this
# content instead of two that can drift. It reads WARREN_PROJECT/
# WARREN_TEMPLATE/WARREN_WORKSPACE_ID from the environment at shell-start
# time rather than being templated per-workspace, so the identical file
# works whether it was just written for this one workspace or baked into an
# image shared by every workspace that runs it.
setopt PROMPT_SUBST
PROMPT='%F{cyan}⬡%f %F{yellow}${WARREN_PROJECT}%f %F{blue}%~%f %# '

echo ''
echo "  🐰  warren  ${WARREN_PROJECT} / ${WARREN_TEMPLATE}  [${WARREN_WORKSPACE_ID[1,8]}]"
echo ''
