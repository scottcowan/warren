#!/usr/bin/env bash
# Pick the registry an image build pulls its digest-pinned base image from.
#
# Usage: resolve-base-registry.sh <Dockerfile> <registry-prefix>...
#
# The Dockerfile must contain `FROM ${BASE_REGISTRY}/<name>:<tag>@sha256:<digest>` (every such
# line is checked, for multi-stage builds). Each
# candidate prefix (e.g. mirror.gcr.io/library, public.ecr.aws/docker/library,
# docker.io/library) is probed in order, with retry and backoff, and accepted only if it
# resolves every <name>:<tag>@<digest> to that exact manifest digest -- so swapping registries
# never changes what gets built (BuildKit also verifies content against the pinned digest
# on pull). Writes `primary` (first verified prefix) and `fallback` (second verified
# prefix, or primary again) to $GITHUB_OUTPUT.
#
# Why: anonymous pulls from shared GitHub runner IPs hit registry quotas intermittently
# (ECR Public: "toomanyrequests: Data limit exceeded"; Docker Hub: pull rate limit).
set -euo pipefail

dockerfile="$1"
shift

mapfile -t refs < <(sed -nE 's|^FROM \$\{BASE_REGISTRY\}/([^[:space:]]+@sha256:[0-9a-f]{64}).*$|\1|p' "$dockerfile")
if [ "${#refs[@]}" -eq 0 ]; then
    echo "::error::$dockerfile has no 'FROM \${BASE_REGISTRY}/<name>:<tag>@sha256:<digest>' line"
    exit 1
fi
for ref in "${refs[@]}"; do
    echo "pinned base: $ref"
done

# A prefix is accepted only if it serves every pinned base (multi-stage builds pull all
# of them from the same BASE_REGISTRY).
serves() {
    local prefix="$1" ref="$2" want="${2##*@}" got attempt
    for attempt in 1 2 3; do
        if got="$(timeout 60 docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$prefix/$ref" 2>&1)"; then
            if [ "$got" = "$want" ]; then
                echo "verified $prefix/$ref"
                return 0
            fi
            echo "::warning::$prefix serves digest '$got' for $ref, not the pinned $want -- skipping"
            return 1
        fi
        echo "::warning::probe of $prefix/$ref failed (attempt $attempt): $got"
        sleep $((attempt * 5))
    done
    return 1
}

verified=()
for prefix in "$@"; do
    ok=1
    for ref in "${refs[@]}"; do
        serves "$prefix" "$ref" || { ok=0; break; }
    done
    [ "$ok" = 1 ] && verified+=("$prefix")
done

if [ "${#verified[@]}" -eq 0 ]; then
    echo "::error::no registry served ${refs[*]}"
    exit 1
fi
primary="${verified[0]}"
fallback="${verified[1]:-$primary}"
echo "primary=$primary fallback=$fallback"
{
    echo "primary=$primary"
    echo "fallback=$fallback"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
