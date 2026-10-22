# warren-agent-base — STUB, not yet buildable as a published image.
#
# Purpose-built image for automated-agent workspaces (as distinct from
# warren-docker-dev-base's plain interactive-session tooling): layers the acp-harness on
# top of warren-docker-dev-base. Deferred until acp-harness is public — there is nothing
# to install yet, so this file intentionally stops at FROM warren-docker-dev-base until
# that lands.
#
# When acp-harness is public, this becomes:
#   RUN <install acp-harness here, however it's actually distributed —
#       pip/npm/cargo/git clone+build, whichever applies>
#   ENTRYPOINT/CMD wiring so the harness starts eagerly (WARREN_APP_CMD contract,
#   see packages/warren-server/images/ecs-base/entrypoint.sh for the ECS-side half
#   of this — the Docker-env equivalent entrypoint wiring is separate follow-up work).
FROM ghcr.io/scottcowan/warren-docker-dev-base:latest@sha256:7ae97b0065e6bcc070a94da0d83e875d9a8a1c8807bebdd26f5939f2084f6b6b
# warren-docker-dev-base:latest as of 2026-10-17

# TODO: install acp-harness once public.
