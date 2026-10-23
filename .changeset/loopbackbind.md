---
warren-server: minor
---

python -m warren listens on 127.0.0.1 by default (WARREN_HOST/WARREN_PORT). A non-loopback bind needs WARREN_TLS_CERTFILE/WARREN_TLS_KEYFILE or WARREN_ALLOW_INSECURE_HTTP=1, otherwise the server refuses to start. A server container published with -p must now set WARREN_HOST=0.0.0.0; ECS reached via SSM port-forward is unaffected
