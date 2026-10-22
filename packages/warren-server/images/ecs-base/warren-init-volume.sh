#!/bin/sh
# Root-only, run before dropping to warren (AD3): a fresh non-EFS task volume is mounted
# root:root 0755, so uid 1000 couldn't write it. Changes only the mount point's own
# ownership, never recursively and never through a symlink, and reads/executes nothing
# from the volume. EFS access points already present it as 1000:1000, so that's a no-op.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
set -e

for dir in /var/lib/warren /workspace; do
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
        continue
    fi
    if [ "$(/bin/stat -c %u:%g "$dir")" != 1000:1000 ]; then
        /bin/chown -h 1000:1000 "$dir"
    fi
done
