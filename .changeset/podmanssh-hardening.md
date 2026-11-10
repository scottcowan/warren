---
warren-server: patch
---

Harden rootless podman pasta detection (fail closed when neither rootlessNetworkCmd nor a parseable version is reported) and move the sshd drop-in Include last in both ssh-base images so a drop-in cannot override the hardening; the smoke scripts assert it with sshd -T.
