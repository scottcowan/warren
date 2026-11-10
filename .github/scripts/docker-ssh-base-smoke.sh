#!/usr/bin/env bash
# Smoke checks for a built warren-docker-ssh-base image. Run by
# .github/workflows/warren-docker-ssh-base-smoke.yml, and locally the same way:
#
#   .github/scripts/docker-ssh-base-smoke.sh IMAGE
#
# Needs only docker. The container is run the way PodmanRuntime runs a workspace with
# WARREN_SSH_ACCESS_ENABLED=true: port 22 published on the host's 127.0.0.1 only, and the
# minted public key written into the running container at /etc/warren/authorized_keys
# (root, 0644; PodmanRuntime uses put_archive, this uses docker cp). Every SSH client
# and key lives inside throwaway containers; nothing touches this machine's ~/.ssh.
set -euo pipefail

IMG=${1:?usage: docker-ssh-base-smoke.sh IMAGE}
names=()
cleanup() { for n in ${names[@]+"${names[@]}"}; do docker rm -f "$n" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }
SSH_OPTS='-p 22 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5'
# shellcheck disable=SC2016
WAIT_SSHD='for _ in $(seq 1 50); do grep -q ":0016 00000000:0000 0A" /proc/net/tcp && exit 0; sleep 0.2; done; exit 1'

step "image config"
test "$(docker image inspect -f '{{json .Config.Entrypoint}}' "$IMG")" = '["/usr/local/bin/warren-sshd-start"]' || fail "entrypoint"
test -z "$(docker run --rm --entrypoint sh "$IMG" -c 'ls /etc/ssh/ssh_host_* /etc/ssh/warren 2>/dev/null')" \
    || fail "host keys baked into the image"
test "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g:%a' /etc/ssh/sshd_config /usr/local/bin/warren-sshd-start /etc/warren | tr '\n' ' ')" \
    = "0:0:644 0:0:755 0:0:755 " || fail "modes"
test -z "$(docker run --rm --entrypoint ls "$IMG" -A /etc/ssh/sshd_config.d)" || fail "unexpected sshd drop-ins"
test "$(docker run --rm --entrypoint sh "$IMG" -c 'getent passwd warren warren-shell | cut -d: -f1,3' | tr '\n' ' ')" \
    = "warren:1000 warren-shell:1001 " || fail "login users"

step "sshd -T: hardened effective config"
cfg="$(docker run --rm --entrypoint sh "$IMG" -c \
    "mkdir -p /run/sshd && ssh-keygen -q -t ed25519 -N '' -f /tmp/k && /usr/sbin/sshd -T -f /etc/ssh/sshd_config -h /tmp/k" 2>/dev/null)"
for want in \
    'port 22' 'addressfamily inet' \
    'authenticationmethods publickey' 'pubkeyauthentication yes' \
    'passwordauthentication no' 'permitemptypasswords no' 'kbdinteractiveauthentication no' \
    'hostbasedauthentication no' 'gssapiauthentication no' 'kerberosauthentication no' 'usepam no' \
    'permitrootlogin no' 'allowusers warren' 'allowusers warren-shell' 'strictmodes yes' 'permituserenvironment no' \
    'authorizedkeysfile /etc/warren/authorized_keys' \
    'allowtcpforwarding local' 'gatewayports no' 'permitlisten none' 'allowstreamlocalforwarding no' \
    'x11forwarding no' 'allowagentforwarding no' 'permittunnel no' \
    'hostkey /etc/ssh/warren/ssh_host_ed25519_key' 'maxauthtries 3'; do
    grep -qxF "$want" <<<"$cfg" || fail "sshd -T: expected '$want'"
done
echo "sshd -T: hardening keywords as expected"

step "sshd -T: a hostile drop-in cannot weaken the hardening"
hostile="$(docker run --rm --entrypoint sh "$IMG" -c \
    "mkdir -p /run/sshd /etc/ssh/sshd_config.d && printf 'PasswordAuthentication yes\nPermitRootLogin yes\nAllowAgentForwarding yes\n' > /etc/ssh/sshd_config.d/evil.conf && ssh-keygen -q -t ed25519 -N '' -f /tmp/k && /usr/sbin/sshd -T -f /etc/ssh/sshd_config -h /tmp/k" 2>/dev/null)"
for want in 'passwordauthentication no' 'permitrootlogin no' 'allowagentforwarding no'; do
    grep -qxF "$want" <<<"$hostile" || fail "sshd -T with hostile drop-in: expected '$want'"
done
echo "sshd -T: hostile drop-in ignored"

step "start a workspace like PodmanRuntime does"
c=warren-docker-ssh-smoke-$$; names+=("$c")
docker run -d --name "$c" -p 127.0.0.1::22 -e WARREN_WORKSPACE_ID=ws-smoke -e WARREN_APP='sleep 600' "$IMG" >/dev/null
docker exec "$c" sh -c "$WAIT_SSHD" || { docker logs "$c" >&2; fail "sshd did not start"; }
# Host side: published on loopback only.
pub="$(docker port "$c" 22/tcp)"
echo "published: $pub"
case "$pub" in 127.0.0.1:*) ;; *) fail "port 22 published beyond loopback: $pub" ;; esac
test "$(grep -c . <<<"$pub")" = 1 || fail "port 22 published more than once: $pub"
# Container side: sshd's is the only TCP listener, and nothing on IPv6.
listeners="$(docker exec "$c" sh -c "awk '\$4 == \"0A\" {print \$2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null")"
echo "listeners: $listeners"
test "$listeners" = "00000000:0016" || fail "listeners: $listeners"
# The workspace's own entrypoint still ran (workspace_ready on stdout).
for _ in $(seq 1 25); do docker logs "$c" 2>/dev/null | grep -q '"type": "workspace_ready"' && break; sleep 0.2; done
docker logs "$c" 2>/dev/null | grep -q '"type": "workspace_ready"' || fail "warren-docker-base entrypoint did not run"
test "$(docker exec "$c" stat -c '%u:%g:%a' /etc/ssh/warren /etc/ssh/warren/ssh_host_ed25519_key /etc/warren/authorized_keys | tr '\n' ' ')" \
    = "0:0:700 0:0:600 0:0:644 " || fail "key file modes"

step "minted key: login, forwarding"
# The client key is generated inside the container; only its public half is "minted"
# into /etc/warren/authorized_keys, as PodmanRuntime.inject_ssh_key does.
docker exec "$c" sh -c "ssh-keygen -q -t ed25519 -N '' -C smoke -f /tmp/id"
docker exec "$c" sh -c 'cp /tmp/id.pub /etc/warren/authorized_keys && chmod 0644 /etc/warren/authorized_keys'
for user in warren-shell warren; do
    # shellcheck disable=SC2086
    out="$(docker exec "$c" sh -c "ssh -i /tmp/id $SSH_OPTS $user@127.0.0.1 'id -un'" 2>/dev/null)"
    test "$out" = "$user" || fail "key login as $user: '$out'"
done
echo "key login: warren-shell, warren"
# shellcheck disable=SC2086
out="$(docker exec "$c" sh -c "ssh -i /tmp/id $SSH_OPTS -W 127.0.0.1:22 warren-shell@127.0.0.1 </dev/null 2>/dev/null | head -c 8" || true)"
test "$out" = "SSH-2.0-" || fail "local (direct-tcpip) forwarding: got '$out'"
# shellcheck disable=SC2086
if docker exec "$c" sh -c "ssh -i /tmp/id $SSH_OPTS -o ExitOnForwardFailure=yes -R 127.0.0.1:2299:127.0.0.1:22 warren-shell@127.0.0.1 true" 2>/dev/null; then
    fail "remote forwarding accepted"
fi
# Sessions don't carry the container's environment (where podman puts workspace secrets).
# shellcheck disable=SC2086
env_ssh="$(docker exec "$c" sh -c "ssh -i /tmp/id $SSH_OPTS warren-shell@127.0.0.1 'bash -lc env'" 2>/dev/null)"
if grep -q '^WARREN_WORKSPACE_ID=' <<<"$env_ssh"; then fail "SSH session carries the container's environment"; fi

step "refused: password, keyboard-interactive, root, other users, wiped key"
docker exec "$c" sh -c 'echo warren-shell:smoke-password | chpasswd'
# shellcheck disable=SC2086
out="$(docker exec "$c" sh -c "ssh $SSH_OPTS -o PubkeyAuthentication=no warren-shell@127.0.0.1 true" 2>&1 || true)"
case "$out" in *"Permission denied (publickey)"*) ;; *) fail "password auth offered: $out" ;; esac
# authorized_keys is global, so the key would match root too: PermitRootLogin refuses it.
for user in root nobody; do
    # shellcheck disable=SC2086
    out="$(docker exec "$c" sh -c "ssh -i /tmp/id $SSH_OPTS $user@127.0.0.1 true" 2>&1 || true)"
    case "$out" in *"Permission denied"*) ;; *) fail "$user login not refused: $out" ;; esac
done
# D-03: the server empties the file on stop/destroy; the key stops working.
docker exec "$c" sh -c ': > /etc/warren/authorized_keys'
# shellcheck disable=SC2086
out="$(docker exec "$c" sh -c "ssh -i /tmp/id $SSH_OPTS warren-shell@127.0.0.1 true" 2>&1 || true)"
case "$out" in *"Permission denied"*) ;; *) fail "wiped key still accepted: $out" ;; esac

step "host key survives a container stop/start"
fp1="$(docker exec "$c" ssh-keygen -l -f /etc/ssh/warren/ssh_host_ed25519_key.pub)"
docker restart "$c" >/dev/null
docker exec "$c" sh -c "$WAIT_SSHD" || fail "sshd did not restart"
fp2="$(docker exec "$c" ssh-keygen -l -f /etc/ssh/warren/ssh_host_ed25519_key.pub)"
test "$fp1" = "$fp2" || fail "host key changed across restart"
echo "host key: $fp1"

echo "docker-ssh-base smoke: all checks passed for $IMG"
