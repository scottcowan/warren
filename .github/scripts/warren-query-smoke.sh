#!/bin/sh
# Image smoke check for /usr/local/bin/warren-query, fed on stdin to `docker run --user 0
# --entrypoint /bin/sh IMAGE -s`. Runs as root, like podman exec and ECS Exec do, so it
# also proves the script drops to an unprivileged user before reading anything.
set -eu
q=/usr/local/bin/warren-query
fail() {
    echo "warren-query smoke: $*" >&2
    exit 1
}
mkdir -p /workspace/main /outside
echo TOPSECRET >/outside/secret.txt
cd /workspace/main
git init -q
printf 'hello\n' >a.txt
printf '*.log\n' >.gitignore
git add -A
git -c user.email=t@t -c user.name=t commit -qm init
printf 'changed\n' >>a.txt
echo TOPSECRET >x.log
echo TOPSECRET >.env
ln -s /outside/secret.txt link.txt
chmod -R a+rX /workspace
echo r >rootonly.txt
chmod 600 rootonly.txt

list=$($q list /workspace)
echo "$list"
case $list in *"F 14 main/a.txt"*) ;; *) fail "list is missing main/a.txt" ;; esac
case $list in *x.log* | *.env* | *link.txt*) fail "list shows an excluded path" ;; esac
[ "$($q read /workspace main/a.txt 100 | sed -n 2p | base64 -d)" = "$(printf 'hello\nchanged')" ] || fail "read body"
check() {
    out=$($q read /workspace "$1" 100) && fail "read $1 succeeded"
    [ "$out" = "$2" ] || fail "read $1: $out"
}
check main/link.txt "ERR symlink"
check main/x.log "ERR excluded"
check main/.env "ERR excluded"
check main/rootonly.txt "ERR not readable"
$q diff /workspace 100000 | sed -n '/^REPO /,/^ENDREPO$/p' | sed '1d;$d' | base64 -d | grep -q '^+changed' || fail "diff"
echo "warren-query smoke: ok"
