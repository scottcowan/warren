# warren-ecs-agent-base — STUB, not yet buildable as a published image.
#
# ECS-env counterpart to ../../../../images/warren-agent-base. Layers the acp-harness on
# top of warren-ecs-dev-base. Deferred until acp-harness is public — there is nothing to
# install yet, so this file intentionally stops at FROM warren-ecs-dev-base until that
# lands.
#
# When acp-harness is public, this becomes:
#   RUN <install acp-harness here, however it's actually distributed>
# plus wiring it to run via WARREN_APP_CMD (ecs-base/entrypoint.sh's eager-launch
# contract, set by ECSRuntime.provision() when the connected intent declares a port —
# see IntentConfig.port in warren_common/models.py once that lands).
FROM ghcr.io/scottcowan/warren-ecs-dev-base:1.3.0@sha256:c700830841e203a965ba42a11010359932866dccdda8e5b86b3afc595223a6f6
# warren-ecs-dev-base 1.3.0 (Debian) as of 2026-11-09

# TODO: install acp-harness once public.
