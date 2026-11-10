"""Names a user secret may not take, because it is delivered as an environment variable.

Secrets reach a workspace as exported environment variables, and the ECS entrypoint
and git-init export them as root. A secret named LD_PRELOAD, PATH, BASH_ENV, ENV,
IFS, GIT_* or WARREN_* would run attacker-chosen code in that root phase, or redirect
the decrypt helper (AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_ENDPOINT_URL_KMS). The
rule is enforced three times, on purpose:

  * at write time (PUT /secrets) so the user sees a clear 422,
  * where the server hands secrets to a runtime (podman env, the ECS file and KMS
    envelope encoders), for rows stored before the rule existed,
  * in the image's loader (images/ecs-base/warren-secrets.sh), which skips a denied
    name with a one-line notice. That shell copy MUST stay in step with this module;
    tests/unit/secrets/test_names.py runs both over one corpus.

Denied: any name equal to or prefixed by LD_, BASH_, AWS_, GIT_, WARREN_, and exactly
the names in DENIED_EXACT. Allowed despite that, because warren's own features and
user workloads need them: the five AWS credential/region variables, WARREN_GIT_SSH_KEY
(and WARREN_GIT_SSH_KEY_<suffix>, the per-repo deploy keys), and, only for warren's
own delivery, WARREN_GIT_TOKENS (INTERNAL_NAMES).
"""

from __future__ import annotations

import re

DENIED_PREFIXES = ("LD_", "BASH_", "AWS_", "GIT_", "WARREN_")
DENIED_EXACT = frozenset(
    "PATH IFS ENV SHELL HOME PWD OLDPWD USER LOGNAME TMPDIR HISTFILE CDPATH PS1 PS4 "
    "PROMPT_COMMAND NODE_OPTIONS PYTHONPATH PYTHONHOME PERL5LIB RUBYLIB".split()
)
# User workloads legitimately bring their own AWS credentials; the endpoint,
# credential-URI, profile and config-file variables stay blocked.
ALLOWED_AWS = frozenset(
    "AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_REGION AWS_DEFAULT_REGION".split()
)
_ALLOWED_WARREN = re.compile(r"^WARREN_GIT_SSH_KEY(_[A-Za-z0-9_]*)?$")
# Written by the control plane itself, never by a user (the user-facing check refuses it).
INTERNAL_NAMES = frozenset({"WARREN_GIT_TOKENS"})


def is_denied(name: str) -> bool:
    """True when a user may not have a secret called `name` delivered as an env var."""
    if name in ALLOWED_AWS or _ALLOWED_WARREN.match(name):
        return False
    return name in DENIED_EXACT or name.startswith(DENIED_PREFIXES)


def denied_message(name: str) -> str:
    return (
        f"secret name {name!r} is reserved: names starting {', '.join(DENIED_PREFIXES)} or equal "
        f"to PATH, IFS, HOME, ENV, SHELL ... would change how the workspace starts, so they cannot be "
        f"delivered as environment variables. Allowed exceptions: "
        f"{', '.join(sorted(ALLOWED_AWS))}, WARREN_GIT_SSH_KEY[_*]. Pick another name."
    )


def is_deliverable(name: str) -> bool:
    """For the server-side encoders: a denied user name never goes out, internal ones do."""
    return name in INTERNAL_NAMES or not is_denied(name)
