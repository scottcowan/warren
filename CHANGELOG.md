# Changelog

Image releases, newest first. Written by scripts/release.py.

## warren-server 1.3.0 (2026-10-27)

- feat: ECS workspace secrets only in warren's store, delivered through the workspace's EFS volume (no SSM) (#44) (71280c2)

## warren-ecs-base 1.2.0 (2026-10-27)

- feat: ECS workspace secrets only in warren's store, delivered through the workspace's EFS volume (no SSM) (#44) (71280c2)

## warren-server 1.2.0 (2026-10-26)

- feat(server): route bedrock-mode workspaces through a configured Bedrock gateway (#41) (225434d)

## warren-server 1.1.3 (2026-10-23)

- fix: control plane never reads SSM (outbox mirror), Encrypt-only KMS, session-manager-plugin in the server image (#39) (cf22f5f)

## warren-server 1.1.2 (2026-10-23)

- refactor(sidecar): reduce warren-sidecar to the in-container agent-state recorder (#38) (ab4a740)
- fix(server): drop the unused stored sidecar token and delete existing ones (#34) (eef6926)
- fix(runtime): close workspace-to-host paths and migrate off the shared podman bridge (#35) (f68bb04)
- fix(server): isolate folder clones from the root mount, protect local git stores (#36) (5e7179c)
- fix: ECS state integrity (SSM/SQLite secret divergence, single SQLite writer, EFS encryption) (#33) (959503c)
- fix(server): pin host git's object store and bound pull runtime (#32) (27bf977)
- fix(sidecar): authenticate every route, provision a per-workspace token, no-follow file access (#30) (4cbf8c0)
- fix(runtime): isolate podman and docker workspaces from each other on the network (#29) (cdcd630)
- fix(server): atomic security limits; loopback-by-default listener (#28) (7efdf17)
- fix(local): workspace id/mount path safety and untrusted legacy state (#27) (f2e0234)

## warren-docker-base 1.0.2 (2026-10-23)

- refactor(sidecar): reduce warren-sidecar to the in-container agent-state recorder (#38) (ab4a740)
- fix(sidecar): authenticate every route, provision a per-workspace token, no-follow file access (#30) (4cbf8c0)

## warren-server 1.1.1 (2026-10-23)

- deps: raise cryptography, fastapi, uvicorn, mcp caps and refresh flagged lock entries (#21) (c048493)
- build(deps): bump the python group with 3 updates (#20) (003fdc2)

## warren-ecs-dev-base 1.0.1 (2026-10-23)

- build(deps): bump scottcowan/warren-ecs-base (#18) (f24a03a)

