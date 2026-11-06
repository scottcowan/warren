#!/usr/bin/env bash
# Smoke checks for a built warren-ecs-base image (Debian bookworm since 1.5.0). Run by
# .github/workflows/warren-ecs-base-smoke.yml, and locally the same way:
#
#   .github/scripts/ecs-base-smoke.sh IMAGE [ECS_EXEC_CMD_FILE]
#
# ECS_EXEC_CMD_FILE holds the CLI's rendered ECS Exec command
# (warren_cli.dispatch.ecs_session_command('bash')); without it the script renders it
# with `uv run --package warren`. Needs docker and python3. The EBS checks run a fake KMS
# on this machine's 127.0.0.1:18080 and reach it from `docker run --network host`
# containers at SMOKE_KMS_HOST (default 127.0.0.1, right when the Docker daemon runs on
# this machine). With a VM-backed daemon, set it to the VM's name for this machine's
# loopback, e.g. SMOKE_KMS_HOST=host.lima.internal for colima.
# The entrypoint ignores CMD args (it only reacts to WARREN_APP_CMD), so inspection
# bypasses it with --entrypoint.
set -euo pipefail

IMG=${1:?usage: ecs-base-smoke.sh IMAGE [ECS_EXEC_CMD_FILE]}
REPO=${SMOKE_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}
VECTORS=$REPO/packages/warren-server/images/ecs-base/secrets-decrypt/testdata
tmp=$(mktemp -d)
kms_pid=
cleanup() {
    if [ -n "$kms_pid" ]; then kill "$kms_pid" 2>/dev/null || true; wait "$kms_pid" 2>/dev/null || true; fi
    rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }

if [ -n "${2:-}" ]; then
    CMD="$(cat "$2")"
else
    CMD="$(cd "$REPO" && uv run -q --package warren python -c "from warren_cli.dispatch import ecs_session_command; print(ecs_session_command('bash'))")"
fi

step "image config and Debian layout"
test "$(docker image inspect -f '{{.Config.User}}|{{.Config.WorkingDir}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}' "$IMG")" \
    = 'root|/home/warren|["/usr/local/bin/entrypoint.sh"]|null' || fail "image config"
docker run --rm --entrypoint sh "$IMG" -c '. /etc/os-release && test "$ID:$VERSION_CODENAME" = debian:bookworm' \
    || fail "not Debian bookworm"
docker run --rm --entrypoint git "$IMG" --version
docker run --rm --entrypoint bash "$IMG" --version | head -n 1
docker run --rm --entrypoint tmux "$IMG" -V
docker run --rm --entrypoint ssh "$IMG" -V
# su-exec is built from source (bookworm has no package) into /usr/sbin; /sbin/su-exec,
# which the scripts call, resolves through merged /usr.
test "$(docker run --rm --entrypoint /sbin/su-exec "$IMG" 1000:1000 id -u)" = 1000 || fail "/sbin/su-exec"
test "$(docker run --rm --entrypoint stat "$IMG" -L -c '%u:%g:%a' /sbin/su-exec)" = "0:0:755" || fail "su-exec mode"
# The 1000 user: home 2755 with no skel files, bash login shell.
test "$(docker run --rm --entrypoint sh "$IMG" -c 'stat -c %a /home/warren; ls -A /home/warren | wc -l; getent passwd warren | cut -d: -f3,4,6,7' | tr '\n' ' ')" \
    = "2755 0 1000:1000:/home/warren:/bin/bash " || fail "warren user"
# Shell hooks: bash reads /etc/bash.bashrc (/etc/bash/bashrc links to it), zsh reads
# /etc/zsh/zshrc, and Debian zsh's new-user menu is gone. Both give uid 1000 the warren
# shell command.
test "$(docker run --rm --entrypoint readlink "$IMG" /etc/bash/bashrc)" = ../bash.bashrc || fail "/etc/bash/bashrc link"
docker run --rm --entrypoint sh "$IMG" -c 'test -z "$(ls /usr/share/zsh/*/scripts/newuser 2>/dev/null)"' \
    || fail "zsh newuser menu present"
# (The banner prints first, so match the type on a line of its own.)
docker run --rm --entrypoint su-exec "$IMG" warren bash -ic 'type -t warren' 2>/dev/null </dev/null | grep -qx function \
    || fail "bash hook"
docker run --rm --entrypoint su-exec "$IMG" warren zsh -ic 'whence -w warren' 2>/dev/null </dev/null | grep -qx 'warren: function' \
    || fail "zsh hook"
test "$(docker run --rm --entrypoint sh "$IMG" -c 'echo $LANG')" = C.UTF-8 || fail "LANG"
# Every shell script parses under the image's /bin/sh (dash).
docker run --rm --entrypoint sh "$IMG" -c 'for f in /usr/local/bin/entrypoint.sh /usr/local/bin/warren-session /usr/local/bin/warren-init-volume /usr/local/bin/warren-git-materialize /usr/local/bin/warren-harness-init /usr/local/bin/warren-state-hook /usr/local/lib/warren/secrets.sh; do sh -n "$f" || exit 1; done' \
    || fail "script syntax"

step "privilege drop and modes"
# The entrypoint starts as root and drops to warren before running the app.
test "$(docker run --rm -e WARREN_APP_CMD='id -u; echo $HOME' "$IMG" | tr '\n' ' ')" = "1000 /home/warren " || fail "entrypoint drop"
# Helpers are root-owned 0755 in root-owned, non-writable dirs.
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /usr/local/bin/warren-session /usr/local/bin/warren-init-volume /usr/local/bin/entrypoint.sh /usr/local/bin /usr/local /usr | sort -u)" = "0:0:755" \
    || fail "helper modes"
# Pre-owned paths for uid 1000.
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g' /workspace /var/lib/warren /home/warren | sort -u)" = "1000:1000" \
    || fail "uid 1000 paths"
# A fresh root-owned task volume is chowned to warren by the entrypoint.
test "$(docker run --rm --mount type=tmpfs,destination=/var/lib/warren,tmpfs-mode=0755 -e WARREN_APP_CMD='touch /var/lib/warren/x && stat -c %u:%g /var/lib/warren/x' "$IMG")" = "1000:1000" \
    || fail "fresh volume ownership"

step "warren-session and the CLI's ECS Exec command"
# warren-session resets PATH: planted su-exec/tmux/id earlier on PATH never run.
out="$(docker run --rm --user 0 --entrypoint sh "$IMG" -c 'mkdir /tmp/evil && for b in su-exec tmux id; do printf "#!/bin/sh\necho PWNED\n" > /tmp/evil/$b; chmod +x /tmp/evil/$b; done; PATH=/tmp/evil:$PATH /usr/local/bin/warren-session bash' 2>&1 || true)"
echo "$out"
case "$out" in *PWNED*) fail "warren-session used the caller's PATH" ;; esac
case "$out" in *terminal*) ;; *) fail "warren-session did not reach tmux" ;; esac
# The CLI's ECS Exec command fails closed, with no root shell, when the helper is
# missing or writable by non-root.
for prep in 'rm /usr/local/bin/warren-session' 'chmod 0777 /usr/local/bin/warren-session' 'chown 1000 /usr/local/bin/warren-session' 'chmod 0777 /usr/local/bin'; do
    if out="$(docker run --rm --user 0 --entrypoint sh "$IMG" -c "$prep && $CMD" 2>&1 </dev/null)"; then
        fail "ECS Exec command succeeded after: $prep"
    fi
    case "$out" in *"refusing to open a root shell"*) ;; *) fail "unexpected output after $prep: $out" ;; esac
done
# Intact image: the command reaches warren-session as uid 1000 (tmux then needs a tty).
out="$(docker run --rm --user 0 --entrypoint sh "$IMG" -c "$CMD" 2>&1 </dev/null || true)"
case "$out" in *refusing*) fail "helper rejected on a clean image: $out" ;; esac
case "$out" in *terminal*) ;; *) fail "unexpected: $out" ;; esac

step "git-init (AH1)"
# git-init ships root-owned, the pinned known_hosts is read-only, and /etc/warren is
# traversable so uid 1000 reads the shell hooks.
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /usr/local/bin/warren-git-materialize)" = "0:0:755" || fail "git-materialize mode"
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /etc/warren/ssh_known_hosts)" = "0:0:444" || fail "known_hosts mode"
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /etc/warren)" = "0:0:755" || fail "/etc/warren mode"
docker run --rm --entrypoint su-exec "$IMG" 1000:1000 cat /etc/warren/banner.bash /etc/warren/harness.sh >/dev/null
# AH1 + AD3 end to end on a fresh root-owned task volume: git-init (started as root)
# runs warren-init-volume, drops to 1000, and materializes a worktree owned by 1000;
# the workspace entrypoint then links /workspace to the checkout and drops to 1000.
out="$(docker run --rm --user 0 --mount type=tmpfs,destination=/var/lib/warren,tmpfs-mode=0755 --entrypoint sh "$IMG" -c '
  set -e
  git init -q -b main /tmp/up
  git -C /tmp/up -c user.email=ci@example.invalid -c user.name=ci commit -q --allow-empty -m init
  chown -R 1000:1000 /tmp/up
  WARREN_GIT_ALLOW_PROTOCOL=file WARREN_GIT_FOLDERS="$(printf "worktree\tapp\tcode/app\tfile:///tmp/up\tmain\twarren/dev/abcdef12/code-app\tnone\t-")" \
    /usr/local/bin/warren-git-materialize >&2
  stat -c %u:%g /var/lib/warren /var/lib/warren/workspace /var/lib/warren/workspace/code/app /var/lib/warren/git/app.git-store | sort -u
  WARREN_WORKSPACE_DIR=/var/lib/warren/workspace WARREN_APP_CMD="readlink /workspace; pwd; id -u; git -C code/app branch --show-current" \
    /usr/local/bin/entrypoint.sh')"
echo "$out"
test "$out" = "$(printf '1000:1000\n/var/lib/warren/workspace\n/workspace\n1000\nwarren/dev/abcdef12/code-app')" || fail "git-init worktree"
# EBS bare seeds (runtime/ebs_seeds.py): the seed-refresh task mirrors a repo into an
# empty volume, then a seeded git-init on that volume clones from the mirror, fetches
# the delta and removes the seed.
out="$(docker run --rm --user 0 --mount type=tmpfs,destination=/var/lib/warren,tmpfs-mode=0755 --entrypoint sh "$IMG" -c '
  set -e
  git init -q -b main /tmp/up
  git -C /tmp/up -c user.email=ci@example.invalid -c user.name=ci commit -q --allow-empty -m init
  chown -R 1000:1000 /tmp/up
  key=$(/usr/local/bin/warren-git-materialize --seed-key file:///tmp/up)
  WARREN_GIT_ALLOW_PROTOCOL=file WARREN_GIT_MODE=refresh-seed \
    WARREN_GIT_SEED_REPOS="$(printf "%s\tfile:///tmp/up\tnone\t-" "$key")" /usr/local/bin/warren-git-materialize >&2
  HOME=/tmp su-exec 1000:1000 git -C /tmp/up -c user.email=ci@example.invalid -c user.name=ci commit -q --allow-empty -m after
  WARREN_GIT_ALLOW_PROTOCOL=file WARREN_GIT_SEEDED=1 \
    WARREN_GIT_FOLDERS="$(printf "worktree\tapp\tcode/app\tfile:///tmp/up\tmain\twarren/dev/abcdef12/code-app\tnone\t-")" \
    /usr/local/bin/warren-git-materialize 2>&1 | grep -c "cloned from the seed"
  ls -A /var/lib/warren | tr "\n" " "
  HOME=/tmp su-exec 1000:1000 git -C /var/lib/warren/workspace/code/app log --format=%s -1')"
echo "$out"
test "$out" = "$(printf '1\ngit workspace after')" || fail "bare seeds"

step "EFS-mode secrets (files on the volume)"
# Secrets arrive as files on the volume (runtime/ecs_secrets.py): the entrypoint
# exports workspace.env, deletes both files (git-init.env unread) before the app
# starts, and keeps a copy the workspace user can't read for ECS Exec sessions.
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /usr/local/lib/warren/secrets.sh)" = "0:0:644" || fail "secrets.sh mode"
out="$(docker run --rm --user 0 --mount type=tmpfs,destination=/var/lib/warren,tmpfs-mode=0755 --entrypoint sh "$IMG" -c '
  set -e
  mkdir -p /var/lib/warren/.warren
  printf "API_KEY=%s\n" "$(printf "s3cret\n" | base64)" > /var/lib/warren/.warren/workspace.env
  printf "GITHUB_PAT=%s\n" "$(printf clone | base64)" > /var/lib/warren/.warren/git-init.env
  chown -R 1000:1000 /var/lib/warren
  cat > /tmp/app.sh <<"EOF"
printf "%s|" "$API_KEY"
ls -A /var/lib/warren/.warren | tr "\n" " "; printf "|"
printf "%s|" "${GITHUB_PAT:-none}"
cat /run/warren/secrets.env >/dev/null 2>&1 && echo readable || echo unreadable
EOF
  chmod 755 /tmp/app.sh
  WARREN_APP_CMD=/tmp/app.sh /usr/local/bin/entrypoint.sh')"
echo "$out" | sed 's/s3cret/<value>/'
test "$out" = "$(printf 's3cret\n||none|unreadable')" || fail "EFS secrets"

step "EBS-mode secrets (KMS envelope)"
# runtime/ecs_kms_secrets.py: in EBS mode the secrets arrive as WARREN_SECRETS_BLOB,
# which warren-secrets-decrypt unwraps via KMS with the task role. A fake KMS answers
# Decrypt for the control-plane-generated test vectors (the Go tests in the image build
# cover the crypto; this covers the entrypoint/git-init wiring).
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /usr/local/bin/warren-secrets-decrypt)" = "0:0:755" || fail "decrypt mode"
# Fails closed with nothing on stdout: no blob, a malformed blob; the app never runs.
if out="$(docker run --rm --entrypoint /usr/local/bin/warren-secrets-decrypt "$IMG" workspace 2>/dev/null)"; then fail "decrypt without a blob succeeded"; fi
test -z "$out" || fail "decrypt without a blob printed output"
if out="$(docker run --rm -e WARREN_SECRETS_BLOB=v1:junk -e WARREN_WORKSPACE_ID=ws-1 --entrypoint /usr/local/bin/warren-secrets-decrypt "$IMG" workspace 2>/dev/null)"; then fail "decrypt of a junk blob succeeded"; fi
test -z "$out" || fail "decrypt of a junk blob printed output"
if docker run --rm -e WARREN_SECRETS_BLOB=v1:junk -e WARREN_WORKSPACE_ID=ws-1 -e WARREN_APP_CMD='echo RAN' "$IMG" 2>/dev/null | grep -q RAN; then fail "app ran after a failed decrypt"; fi

cat > "$tmp/fake_kms.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
vs = [json.load(open(p)) for p in sys.argv[1:]]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        ctx = body.get("EncryptionContext", {})
        v = next((v for v in vs if v["wrapped_key"] == body.get("CiphertextBlob")
                  and ctx == {"warren:workspace_id": v["workspace_id"], "warren:container": v["container"]}), None)
        ok = (v is not None and self.headers.get("X-Amz-Target") == "TrentService.Decrypt"
              and self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 "))
        out = json.dumps({"Plaintext": v["data_key"]} if ok else {"__type": "InvalidCiphertextException"}).encode()
        self.send_response(200 if ok else 400); self.send_header("Content-Length", str(len(out)))
        self.end_headers(); self.wfile.write(out)
HTTPServer(("127.0.0.1", 18080), H).serve_forever()
PY
python3 -I "$tmp/fake_kms.py" "$VECTORS/vector.json" "$VECTORS/vector-git-init.json" &
kms_pid=$!
sleep 1
ws_blob="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["blob"])' "$VECTORS/vector.json")"
git_blob="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["blob"])' "$VECTORS/vector-git-init.json")"
kms="-e AWS_ENDPOINT_URL_KMS=http://${SMOKE_KMS_HOST:-127.0.0.1}:18080 -e AWS_ACCESS_KEY_ID=AKIDEXAMPLE -e AWS_SECRET_ACCESS_KEY=x -e AWS_SESSION_TOKEN=t -e WARREN_WORKSPACE_ID=ws-0123abcd"

# Workspace container: secrets exported, the blob gone from the app's env, the
# root-only copy unreadable to the workspace user, a file planted on the volume
# deleted unread.
# shellcheck disable=SC2086
out="$(docker run --rm --network host $kms -e WARREN_SECRETS_BLOB="$ws_blob" --user 0 \
  --mount type=tmpfs,destination=/var/lib/warren,tmpfs-mode=0755 --entrypoint sh "$IMG" -c '
  set -e
  mkdir -p /var/lib/warren/.warren
  printf "PLANTED=%s\n" "$(printf x | base64)" > /var/lib/warren/.warren/workspace.env
  cat > /tmp/app.sh <<"EOF"
printf "%s|%s|" "$GITHUB_TOKEN" "${PLANTED:-none}"
printf "%s|" "${WARREN_SECRETS_BLOB:-unset}"
ls -A /var/lib/warren/.warren | tr "\n" " "; printf "|"
cat /run/warren/secrets.env >/dev/null 2>&1 && echo readable || echo unreadable
EOF
  chmod 755 /tmp/app.sh
  WARREN_APP_CMD=/tmp/app.sh /usr/local/bin/entrypoint.sh')"
echo "$out" | sed 's/ghp_example/<value>/'
test "$out" = "ghp_example|none|unset||unreadable" || fail "EBS workspace secrets"
# The workspace context can't open git-init's blob: fails closed, app never runs.
# shellcheck disable=SC2086
if docker run --rm --network host $kms -e WARREN_SECRETS_BLOB="$git_blob" -e WARREN_APP_CMD='echo RAN' "$IMG" 2>/dev/null | grep -q RAN; then fail "workspace opened git-init's blob"; fi

# git-init: its blob decrypts into the private dir and reaches the clone as the
# credential (no "not set" warning); a planted git-init.env is deleted unread.
# shellcheck disable=SC2086
out="$(docker run --rm --network host $kms -e WARREN_SECRETS_BLOB="$git_blob" --user 0 \
  --mount type=tmpfs,destination=/var/lib/warren,tmpfs-mode=0755 --entrypoint sh "$IMG" -c '
  mkdir -p /var/lib/warren/.warren
  printf "GITHUB_TOKEN=%s\n" "$(printf planted | base64)" > /var/lib/warren/.warren/git-init.env
  WARREN_GIT_FOLDERS="$(printf "clone\trepo\trepo\thttps://127.0.0.1:1/x.git\t-\t-\tpat\tGITHUB_TOKEN")" \
    /usr/local/bin/warren-git-materialize 2>&1
  ls -A /var/lib/warren/.warren')"
echo "$out"
case "$out" in *"not set"*|*"cannot decrypt"*|*git-init.env*) fail "git-init did not load its blob" ;; esac
case "$out" in *"clone failed"*) ;; *) fail "git-init did not reach the clone" ;; esac

echo "ecs-base smoke: all checks passed for $IMG"
