---
warren-server: minor
---

Reject reserved environment names (LD_PRELOAD, PATH, BASH_ENV, GIT_*, AWS_*, WARREN_*) as workspace secret names, and require an explicit stable WARREN_SERVER_ID when EBS workspace storage or bare seeds are enabled (the hostname default orphaned tagged volumes and snapshots on redeploy and let two servers sweep each other)
