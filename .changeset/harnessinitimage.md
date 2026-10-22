---
warren-common: minor
warren-server: minor
---

Server workspaces get only their harness names in the task/container env; the profile data (dirs, persist paths, generated config, launch flags and lockdown env) is baked into the image's generated `/etc/warren/harness.sh` and `/usr/local/bin/warren-harness-init`, keeping ECS RunTask overrides small. At each start `warren-harness-init` prunes harness dirs to their persist paths and rewrites warren's own config from scratch, including a minimal `.claude.json` (onboarding flags and version only) so onboarding doesn't reappear after a relaunch
