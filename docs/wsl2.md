# Local sandbox on Windows: WSL2 + bubblewrap

Native Windows has no local sandbox runtime. Run warren inside a WSL2 distro
(Ubuntu 22.04 or 24.04) and it uses the same bubblewrap runtime as any Linux host.

## Setup

1. Use WSL2, not WSL1. WSL1 has no Linux namespaces, so warren refuses bwrap and
   nsjail there. Check with `wsl -l -v` in PowerShell and convert with
   `wsl --set-version <distro> 2`.
2. Inside the distro: `sudo apt install bubblewrap git`, then install warren
   (e.g. `uv tool install warren`).
3. Run `warren doctor`. The "Linux sandbox" section shows the WSL version, whether
   AppArmor restricts user namespaces, a bwrap self-test, and any warren paths on
   a Windows drive.

### Ubuntu 24.04+: AppArmor blocks bwrap's user namespace

24.04 sets `kernel.apparmor_restrict_unprivileged_userns=1`, so bwrap fails with
`setting up uid map: Permission denied` unless an AppArmor profile allows it.
Doctor and `warren connect` detect this and print the fix:

```sh
sudo cp /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

If your release doesn't ship that profile, create `/etc/apparmor.d/bwrap` with:

```
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
```

and load it with `sudo apparmor_parser -r /etc/apparmor.d/bwrap`. Don't set the
sysctl to 0: that turns the restriction off for every program on the machine.

### Keep warren on the Linux filesystem

`/mnt/c` and the other drive mounts (drvfs, shown as `9p` in `/proc/mounts`)
don't enforce Unix permissions. Windows processes can read those files whatever
their mode, including with the drvfs `metadata` option. Config tokens, the secrets DB,
sandbox profiles and workspace state would have no protection. warren refuses to
provision a local workspace when `~/.warren`, its state dir, the workspace root or
the projects dir is on a drive mount. Keep them under `/home/<you>` (the default
when `$HOME` is the WSL home). The Linux filesystem is also much faster for git.

Clone code into the Linux filesystem too. A `local-path` folder under `/mnt/c` works,
but it is slow, and its permissions are whatever Windows says.

## Host credentials

Under WSL your AWS profiles and ssh keys usually live on the Windows side
(`%USERPROFILE%\.aws`, `%USERPROFILE%\.ssh`). warren in WSL reads the WSL-side
`~/.aws` and `~/.ssh`. It never looks at the Windows profile.

**AWS.** Set up the AWS CLI inside WSL (`aws configure sso`) so `~/.aws/config`
and the SSO token cache are on the Linux side. That keeps them on a filesystem
with working permissions. `aws.mode: export` (the default) is the
recommended mode: warren serves the template's one profile as short-lived
credentials from the host, and the workspace never sees `~/.aws`.
`aws.mode: sso` binds `~/.aws/config` and the SSO cache read-only into the
sandbox, and only for local runtimes.

If you need to share one config with Windows, copy it into WSL, or point a template at an
explicit file (`aws.config_file` / `aws.sso_cache`) rather than at `/mnt/c/Users/...`.
Such a file is still on drvfs and still unprotected.

**ssh.** Generate or copy keys into WSL's `~/.ssh` (mode 0600) and list them in the
template's `ssh.keys`, or run an ssh-agent inside WSL and set `ssh.agent: true`.
Windows' OpenSSH agent (`\\.\pipe\openssh-ssh-agent`) isn't reachable from WSL
without a relay such as `npiperelay` + `socat`. If you use one, point
`SSH_AUTH_SOCK` at the relay's Unix socket.

**Never bind the whole Windows user profile** (`/mnt/c/Users/<you>`) into a template
`mounts:` entry. It contains every credential, browser profile and token on the
machine, and it sits on drvfs. Mount only the specific paths a template needs.

## Optional: run `warren` from PowerShell

With warren also installed on the Windows side, you can make the Windows `warren`
forward to the WSL one. Add this to `%USERPROFILE%\.warren\config.toml`:

```toml
[windows]
forward_to_wsl = true
wsl_distro = "Ubuntu-24.04"   # optional; default distro if empty
```

The Windows `warren ...` then runs `wsl.exe -d <distro> -e sh -lc 'exec warren "$@"' warren ...`
and exits with its code. It forwards only when this is set, the Windows host has no
native local runtime (no Docker Desktop/podman machine), and `warren` is on the WSL
login shell's PATH. Otherwise it runs natively. `WARREN_WSL_FORWARD=1` / `=0`
turns forwarding on or off for one command. Arguments are passed through
unchanged, so use Linux paths (`/home/...`), not `C:\...`. Forwarding is off by
default.

## Testing

GitHub-hosted runners can't run WSL, so CI covers this with fake `/proc` files
and mount tables (`packages/warren-common/tests/test_wsl.py`,
`packages/warren-cli/tests/test_wsl2.py`). To verify on a real machine, run
`warren doctor` and the bubblewrap suite (`pytest packages/warren-common/tests/runtime/test_bubblewrap_runtime.py`)
inside WSL2 Ubuntu 22.04 and 24.04 (24.04 both with and without the AppArmor profile loaded).
