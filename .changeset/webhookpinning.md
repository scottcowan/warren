---
warren-server: patch
warren-cli: patch
warren-common: patch
---

Owner webhooks resolve the destination once per delivery, require every address to be public, and connect to the validated IP (SNI and certificate checks stay on the host name), closing a DNS-rebinding SSRF. Owner webhook URLs are limited to port 443 unless WARREN_NOTIFY_ALLOWED_PORTS says otherwise. Name, id and env-var validators use full matches so a trailing newline is rejected. The threat model adds residual risks for envelope ciphertext and write-token exposure.
