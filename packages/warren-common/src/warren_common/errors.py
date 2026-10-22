"""Error and warning types for warren-common."""


class ProjectNotFoundError(FileNotFoundError):
    pass


class TemplateNotFoundError(KeyError):
    pass


class SecretFilePermissionWarning(UserWarning):
    pass


class WorkspaceNeedsRecreate(RuntimeError):
    """The workspace's persisted state predates fields warren now needs and
    can't be rebuilt safely; the user must destroy and recreate it."""


class ProvisionError(Exception):
    """Base class for workspace provisioning failures.

    Subclasses expose a canonical `reason` string that goes on the wire
    (WS-01 wire taxonomy): image_unavailable | runtime_unreachable
    | capacity_exhausted | template_denied | secret_missing.
    """

    reason: str = "unknown"


class ImageUnavailable(ProvisionError):
    reason = "image_unavailable"


class RuntimeUnreachable(ProvisionError):
    reason = "runtime_unreachable"


class CapacityExhausted(ProvisionError):
    reason = "capacity_exhausted"


class TemplateDenied(ProvisionError):
    reason = "template_denied"


class SecretMissing(ProvisionError):
    reason = "secret_missing"
