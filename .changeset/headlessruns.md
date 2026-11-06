---
warren: minor
warren-common: minor
warren-server: minor
---

Headless runs: `warren run <project>/<template> --prompt TEXT|--prompt-file PATH [--wait] [--json]` starts a single-turn workspace whose app runs headless on the prompt (claude `-p --output-format json`, codex `exec`, gemini `-p`), and `warren run status|result|list` read it. `POST /runs`, `GET /runs`, `GET /runs/{id}` and `GET /runs/{id}/result` back it, owner-only with admin read. Every single-turn workspace's result (status, times, exit code, final message, per-checkout changed files and diffstat, observed remote branch and PR URLs, transcript pointer) is kept in a new `runs` registry table after destroy, pruned by `WARREN_RUN_RETENTION_SECONDS` and `WARREN_RUN_MAX_PER_OWNER`; runs past their timeout end as `timed_out`. EBS-backed ECS runs record their own result in the task (ecs-base `warren-run-result`) and hold for the control plane to collect it over ECS Exec, falling back to the exit code alone. See docs/runs.md.
