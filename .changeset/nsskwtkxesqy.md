---
warren-common: minor
warren-server: minor
---

Agent workspaces (AG2b): kind: agent with harness: <name> runs the profile's agent_mode under warren-agent-supervisor (restart policy with backoff, exits recorded in .session/agent/events.jsonl, resume by the recorded session id) instead of WARREN_APP_CMD as PID 1; the warren shell still attaches beside it, and the supervisor's working/blocked/idle/exited state holds reaping. Single-turn stays an app feature
