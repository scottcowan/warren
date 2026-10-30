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
FROM ghcr.io/scottcowan/warren-ecs-dev-base:latest@sha256:eb81ef4c36606a5f421347539074f8ffbf0462bd0a6c40bf4b1e885c58bd7f50
# warren-ecs-dev-base:latest as of 2026-10-17

# TODO: install acp-harness once public.
