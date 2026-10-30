---
warren-server: minor
---

EBS workspaces can start from a per-owner bare-repo seed snapshot (WARREN_ECS_EBS_BARE_SEEDS): git-init clones locally from the owner's mirrors and fetches only the delta; seeds are refreshed by a dedicated task with the owner's own credentials, skipped when no ref moved, and expire with the owner's workspaces. Adds the opt-in WARREN_GIT_CLONE_FILTER for partial clones
