"""Wave 0 RED: nsjail integration smoke test.

Skips when the nsjail binary is not installed. When present, it renders a
canonical NsjailConfig, writes it to a temp path, and runs
`nsjail --config <cfg> -- /bin/true` — asserting exit 0.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("warren_common.runtime.nsjail_config")


pytestmark = pytest.mark.skipif(
    shutil.which("nsjail") is None,
    reason="nsjail binary not installed",
)


def test_generated_config_boots_nsjail(tmp_path: Path):
    from warren_common.runtime.nsjail_config import MountEntry, NsjailConfig

    cfg = NsjailConfig(
        hostname="warren-smoke",
        cwd="/",
        mounts=[
            MountEntry(src="/bin", dst="/bin", rw=False),
            MountEntry(src="/lib", dst="/lib", rw=False, mandatory=False),
            MountEntry(src="/lib64", dst="/lib64", rw=False, mandatory=False),
            MountEntry(src="/usr", dst="/usr", rw=False),
        ],
    )
    cfg_path = tmp_path / "smoke.cfg"
    cfg_path.write_text(cfg.to_proto_text())

    proc = subprocess.run(
        ["nsjail", "--config", str(cfg_path), "--", "/bin/true"],
        capture_output=True,
        timeout=15,
    )
    assert proc.returncode == 0, (
        f"nsjail exited {proc.returncode}; stderr={proc.stderr!r}"
    )
