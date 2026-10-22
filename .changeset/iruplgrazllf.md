---
warren-common: patch
---

Seatbelt: readonly folders and ro bind mounts are write-denied after the system tmpdir grants, so a read-only path under /tmp, /private/tmp or /private/var/folders is actually read-only
