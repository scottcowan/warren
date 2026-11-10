---
warren: minor
warren-common: minor
warren-server: minor
---

warren proxy gains mapping kinds: `tcp` (unchanged byte relay) and `http`, an HTTP-aware gateway for web UIs with Host and Origin checks, a one-time start link exchanged for an HttpOnly session cookie, strict request parsing and size, timeout and connection limits (`warren proxy add --kind http`; template ports take `protocol: tcp|http`, returned by the workspace API). tcp mappings now refuse ports held by another process, write proxy.json atomically (0600, directory 0700, no symlinks), halt if their workspace id changes, and `warren proxy run` exits non-zero when a mapped port cannot be bound
