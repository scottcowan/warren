#!/usr/bin/env bash
# Smoke checks for a built warren-ecs-ssh-base image. Run by
# .github/workflows/warren-ecs-ssh-base-smoke.yml, and locally the same way:
#
#   .github/scripts/ecs-ssh-base-smoke.sh IMAGE
#
# Needs only docker. Every SSH client and key used here lives inside throwaway
# containers; nothing touches this machine's ~/.ssh. Checks:
#   - sshd's effective config (`sshd -T`) is the hardened one;
#   - sshd runs as uid 1000 and listens on 127.0.0.1:2222 and nowhere else;
#   - a key delivered in SSH_AUTHORIZED_KEYS (plain env, and as an EFS-mode secret
#     file) logs in as warren, from a key generated inside the container;
#   - password/keyboard-interactive auth and root logins are refused;
#   - the host key is generated on the volume, not baked in, and survives a restart;
#   - the entrypoint still drops to uid 1000 for the workload.
set -euo pipefail

IMG=${1:?usage: ecs-ssh-base-smoke.sh IMAGE}
vol=warren-ssh-smoke-$$
names=()
cleanup() {
    for n in ${names[@]+"${names[@]}"}; do docker rm -f "$n" >/dev/null 2>&1 || true; done
    docker volume rm -f "$vol" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }

# Shell snippets run inside the containers.
# shellcheck disable=SC2016
WAIT_SSHD='for _ in $(seq 1 50); do grep -q ":08AE 00000000:0000 0A" /proc/net/tcp && exit 0; sleep 0.2; done; exit 1'
SSH_OPTS='-p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5'

step "image config"
test "$(docker image inspect -f '{{.Config.User}}|{{.Config.WorkingDir}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}' "$IMG")" \
    = 'root|/home/warren|["/usr/local/bin/entrypoint.sh"]|null' || fail "image config"
# No host key in the image, anywhere sshd or a user would look.
test -z "$(docker run --rm --entrypoint sh "$IMG" -c 'ls /etc/ssh/ssh_host_* /var/lib/warren/.warren-ssh 2>/dev/null')" \
    || fail "host keys baked into the image"
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /usr/local/bin/entrypoint.sh /usr/local/bin/warren-sshd \
    /usr/local/lib/warren/ecs-entrypoint.sh /etc/ssh/sshd_config | sort -u | tr '\n' ' ')" = "0:0:644 0:0:755 " \
    || fail "helper modes"
test -z "$(docker run --rm --entrypoint ls "$IMG" -A /etc/ssh/sshd_config.d)" || fail "unexpected sshd drop-ins"
docker run --rm --entrypoint sh "$IMG" -c 'for f in /usr/local/bin/entrypoint.sh /usr/local/bin/warren-sshd /usr/local/lib/warren/ecs-entrypoint.sh; do sh -n "$f" || exit 1; done' \
    || fail "script syntax"
# warren-sshd never runs as root.
if docker run --rm --entrypoint /usr/local/bin/warren-sshd "$IMG" 2>/dev/null; then fail "warren-sshd ran as root"; fi

step "sshd -T: hardened effective config"
cfg="$(docker run --rm --entrypoint su-exec "$IMG" warren sh -c \
    "ssh-keygen -q -t ed25519 -N '' -f /tmp/k && /usr/sbin/sshd -T -f /etc/ssh/sshd_config -h /tmp/k" 2>/dev/null)"
for want in \
    'listenaddress 127.0.0.1:2222' 'addressfamily inet' 'port 2222' \
    'authenticationmethods publickey' 'pubkeyauthentication yes' \
    'passwordauthentication no' 'permitemptypasswords no' 'kbdinteractiveauthentication no' \
    'hostbasedauthentication no' 'gssapiauthentication no' 'kerberosauthentication no' 'usepam no' \
    'permitrootlogin no' 'allowusers warren' 'strictmodes yes' 'permituserenvironment no' \
    'allowtcpforwarding local' 'gatewayports no' 'permitlisten none' 'allowstreamlocalforwarding no' \
    'x11forwarding no' 'allowagentforwarding no' 'permittunnel no' \
    'hostkey /var/lib/warren/.warren-ssh/ssh_host_ed25519_key' 'maxauthtries 3'; do
    grep -qxF "$want" <<<"$cfg" || fail "sshd -T: expected '$want'"
done
test "$(grep -c '^listenaddress ' <<<"$cfg")" = 1 || fail "sshd -T: more than one listenaddress"
echo "sshd -T: $(grep -cE '^(listenaddress|authenticationmethods|passwordauthentication|kbdinteractiveauthentication|usepam|permitrootlogin|allowusers|allowtcpforwarding|x11forwarding|allowagentforwarding)' <<<"$cfg") hardening keywords as expected"

step "sshd -T: a hostile drop-in cannot weaken the hardening"
hostile="$(docker run --rm --user 0 --entrypoint sh "$IMG" -c \
    "mkdir -p /etc/ssh/sshd_config.d && printf 'PasswordAuthentication yes\nPermitRootLogin yes\nAllowAgentForwarding yes\n' > /etc/ssh/sshd_config.d/evil.conf && chmod 644 /etc/ssh/sshd_config.d/evil.conf && su-exec warren sh -c \"ssh-keygen -q -t ed25519 -N '' -f /tmp/k && /usr/sbin/sshd -T -f /etc/ssh/sshd_config -h /tmp/k\"" 2>&1)" \
    || { printf '%s\n' "$hostile" | tail -5 >&2; fail "sshd -T with hostile drop-in failed"; }
for want in 'passwordauthentication no' 'permitrootlogin no' 'allowagentforwarding no'; do
    grep -qxF "$want" <<<"$hostile" || fail "sshd -T with hostile drop-in: expected '$want'"
done
echo "sshd -T: hostile drop-in ignored"

step "workload privilege drop (unchanged from ecs-base)"
test "$(docker run --rm -e WARREN_APP_CMD='id -u; echo $HOME' "$IMG" 2>/dev/null | tr '\n' ' ')" = "1000 /home/warren " \
    || fail "entrypoint drop"

step "client key generated inside a container"
# The private key never leaves docker: it is generated in one container and copied
# into the next with docker cp via a stopped helper container.
keyc=warren-ssh-smoke-key-$$; names+=("$keyc")
docker run --name "$keyc" --entrypoint sh "$IMG" -c "ssh-keygen -q -t ed25519 -N '' -C smoke -f /tmp/id" >/dev/null
pub="$(docker cp "$keyc:/tmp/id.pub" - | tar -xO)"
case "$pub" in "ssh-ed25519 "*) ;; *) fail "client key generation" ;; esac

# Start a workspace like ECS does: entrypoint as root, a fresh root-owned volume, the
# key in plain env (the template-env delivery).
start() {  # start NAME [docker run args...]
    local n=$1; shift
    names+=("$n")
    docker run -d --name "$n" --mount "type=volume,source=$vol,destination=/var/lib/warren" "$@" "$IMG" >/dev/null
    docker cp "$keyc:/tmp/id" - | docker cp - "$n:/tmp"
    docker exec "$n" sh -c 'chown root:root /tmp/id && chmod 600 /tmp/id'
    docker exec "$n" sh -c "$WAIT_SSHD" || { docker logs "$n" >&2; fail "sshd did not start in $n"; }
}

step "plain-env key: login, listener, process owner"
c1=warren-ssh-smoke-a-$$
start "$c1" -e SSH_AUTHORIZED_KEYS="$pub" -e WARREN_WORKSPACE_ID=ws-smoke
# shellcheck disable=SC2086
out="$(docker exec "$c1" sh -c "ssh -i /tmp/id $SSH_OPTS warren@127.0.0.1 'id -u; id -un; echo \$HOME; pwd'" 2>/dev/null)"
echo "$out"
test "$out" = "$(printf '1000\nwarren\n/home/warren\n/home/warren')" || fail "key login as warren"
# Local forwarding (what editors use) works: forward to sshd's own port and read its banner.
# shellcheck disable=SC2086
out="$(docker exec "$c1" sh -c "ssh -i /tmp/id $SSH_OPTS -W 127.0.0.1:2222 warren@127.0.0.1 </dev/null 2>/dev/null | head -c 8" || true)"
test "$out" = "SSH-2.0-" || fail "local (direct-tcpip) forwarding: got '$out'"
# Remote forwarding is refused.
# shellcheck disable=SC2086
if docker exec "$c1" sh -c "ssh -i /tmp/id $SSH_OPTS -o ExitOnForwardFailure=yes -R 127.0.0.1:2299:127.0.0.1:22 warren@127.0.0.1 true" 2>/dev/null; then
    fail "remote forwarding accepted"
fi
# Exactly one TCP listener in the container, 127.0.0.1:2222 (0100007F:08AE), no IPv6.
listeners="$(docker exec "$c1" sh -c "awk '\$4 == \"0A\" {print \$2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null")"
echo "listeners: $listeners"
test "$listeners" = "0100007F:08AE" || fail "listeners: $listeners"
# sshd's processes all run as uid 1000; the host key is on the volume, owned by 1000, 0600.
owners="$(docker exec "$c1" sh -c 'for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = sshd ] && awk "/^Uid:/{print \$2}" $p/status; done | sort -u')"
test "$owners" = 1000 || fail "sshd process uids: $owners"
test "$(docker exec "$c1" stat -c '%u:%a' /var/lib/warren/.warren-ssh /var/lib/warren/.warren-ssh/ssh_host_ed25519_key | tr '\n' ' ')" \
    = "1000:700 1000:600 " || fail "host key modes"
test "$(docker exec "$c1" stat -c '%u:%a' /home/warren/.ssh /home/warren/.ssh/authorized_keys | tr '\n' ' ')" \
    = "1000:700 1000:600 " || fail "authorized_keys modes"
# SSH sessions get sshd's clean login environment, not the entrypoint's (warren-sshd
# starts sshd under `env -i`), but do get the image's PATH back (/etc/profile.d).
# shellcheck disable=SC2086
env_ssh="$(docker exec "$c1" sh -c "ssh -i /tmp/id $SSH_OPTS warren@127.0.0.1 'bash -lc env'" 2>/dev/null)"
if grep -qE '^(SSH_AUTHORIZED_KEYS|WARREN_WORKSPACE_ID)=' <<<"$env_ssh"; then fail "SSH session carries the entrypoint's environment"; fi
grep -q '^PATH=.*/usr/local/pyenv/shims' <<<"$env_ssh" || fail "SSH login PATH lacks the image's PATH"
fp1="$(docker exec "$c1" ssh-keygen -l -f /var/lib/warren/.warren-ssh/ssh_host_ed25519_key.pub)"
echo "host key: $fp1"

step "refused: password, keyboard-interactive, root, unknown key"
# shellcheck disable=SC2086
out="$(docker exec "$c1" sh -c "ssh $SSH_OPTS -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive warren@127.0.0.1 true" 2>&1 || true)"
case "$out" in *"Permission denied (publickey)"*) ;; *) fail "password auth not refused: $out" ;; esac
# Even with a password set on the account, the server offers publickey only.
docker exec "$c1" sh -c 'echo warren:smoke-password | chpasswd'
# shellcheck disable=SC2086
out="$(docker exec "$c1" sh -c "ssh $SSH_OPTS -o PubkeyAuthentication=no warren@127.0.0.1 true" 2>&1 || true)"
case "$out" in *"Permission denied (publickey)"*) ;; *) fail "password auth offered: $out" ;; esac
# shellcheck disable=SC2086
out="$(docker exec "$c1" sh -c "ssh -i /tmp/id $SSH_OPTS root@127.0.0.1 true" 2>&1 || true)"
case "$out" in *"Permission denied"*) ;; *) fail "root login not refused: $out" ;; esac
# shellcheck disable=SC2086
out="$(docker exec "$c1" sh -c "ssh-keygen -q -t ed25519 -N '' -f /tmp/other && ssh -i /tmp/other -o IdentitiesOnly=yes $SSH_OPTS warren@127.0.0.1 true" 2>&1 || true)"
case "$out" in *"Permission denied"*) ;; *) fail "unknown key not refused: $out" ;; esac
docker rm -f "$c1" >/dev/null

step "secret-file key (EFS-mode delivery), host key persists across restarts"
# The key arrives as a workspace secret (runtime/ecs_secrets.py writes .warren/workspace.env
# on the volume before RunTask); the volume, and with it the host key, is the same one.
c2=warren-ssh-smoke-b-$$; names+=("$c2")
docker run --rm --mount "type=volume,source=$vol,destination=/var/lib/warren" --entrypoint sh "$IMG" -c \
    "mkdir -p /var/lib/warren/.warren && printf 'SSH_AUTHORIZED_KEYS=%s\n' \"\$(printf '%s\n' '$pub' | base64 -w0)\" > /var/lib/warren/.warren/workspace.env"
# Plain-env key absent this time: only the secret can authorize the login.
start "$c2"
# shellcheck disable=SC2086
out="$(docker exec "$c2" sh -c "ssh -i /tmp/id $SSH_OPTS warren@127.0.0.1 'id -u'" 2>/dev/null)"
test "$out" = 1000 || fail "secret-delivered key login"
test -z "$(docker exec "$c2" ls -A /var/lib/warren/.warren)" || fail "secrets file left on the volume"
fp2="$(docker exec "$c2" ssh-keygen -l -f /var/lib/warren/.warren-ssh/ssh_host_ed25519_key.pub)"
test "$fp1" = "$fp2" || fail "host key changed across restart: $fp1 vs $fp2"
# The workload is still uid 1000 next to sshd.
test "$(docker exec "$c2" sh -c 'for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = tail ] && awk "/^Uid:/{print \$2}" $p/status; done')" = 1000 \
    || fail "workload not uid 1000"

echo "ecs-ssh-base smoke: all checks passed for $IMG"
