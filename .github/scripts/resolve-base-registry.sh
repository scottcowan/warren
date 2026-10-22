#!/usr/bin/env bash
# Pick the registry an image build pulls its digest-pinned base image from.
#
# Usage: resolve-base-registry.sh <Dockerfile> <registry-prefix>...
#
# The Dockerfile must contain `FROM ${BASE_REGISTRY}/<name>:<tag>@sha256:<digest>`. Each
# candidate prefix (e.g. mirror.gcr.io/library, public.ecr.aws/docker/library,
# docker.io/library) is probed in order, with retry and backoff, and accepted only if it
# resolves <name>:<tag>@<digest> to that exact manifest digest -- so swapping registries
# never changes what gets built (BuildKit also verifies content against the pinned digest
# on pull). Writes `primary` (first verified prefix) and `fallback` (second verified
# prefix, or primary again) to $GITHUB_OUTPUT.
#
# Why: anonymous pulls from shared GitHub runner IPs hit registry quotas intermittently
# (ECR Public: "toomanyrequests: Data limit exceeded"; Docker Hub: pull rate limit).
set -euo pipefail

dockerfile="$1"
shift

ref="$(sed -nE 's|^FROM \$\{BASE_REGISTRY\}/([^[:space:]]+@sha256:[0-9a-f]{64}).*$|\1|p' "$dockerfile" | head -n1)"
if [ -z "$ref" ]; then
    echo "::error::$dockerfile has no 'FROM \${BASE_REGISTRY}/<name>:<tag>@sha256:<digest>' line"
    exit 1
fi
want="${ref##*@}"
echo "pinned base: $ref"

verified=()
for prefix in "$@"; do
    for attempt in 1 2 3; do
        if got="$(timeout 60 docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$prefix/$ref" 2>&1)"; then
            if [ "$got" = "$want" ]; then
                echo "verified $prefix/$ref"
                verified+=("$prefix")
            else
                echo "::warning::$prefix serves digest '$got', not the pinned $want -- skipping"
            fi
            break
        fi
        echo "::warning::probe of $prefix failed (attempt $attempt): $got"
        sleep $((attempt * 5))
    done
done

if [ "${#verified[@]}" -eq 0 ]; then
    echo "::error::no registry served $ref"
    exit 1
fi
primary="${verified[0]}"
fallback="${verified[1]:-$primary}"
echo "primary=$primary fallback=$fallback"
{
    echo "primary=$primary"
    echo "fallback=$fallback"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
