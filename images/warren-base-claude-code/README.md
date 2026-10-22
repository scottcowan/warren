# warren-base-claude-code

An extension image layering the Claude Code CLI on top of `warren-docker-base`,
for a workspace template whose `app:` is `claude` instead of a plain shell.

**Not published by warren.** There's no CI workflow building or pushing this
image to GHCR, and `warren doctor` doesn't check for it. Build and tag it
yourself:

```sh
docker build -t my-warren-claude-code:latest images/warren-base-claude-code
```

Then point a project template's `docker_image:` at your own tag (see the
commented example in the project config `warren project add` generates).
