"""ImageResolver — [images] map lookup (D-26).

Pure resolver: canonical image name → override, else canonical.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ImageResolver:
    mapping: dict[str, str]

    @classmethod
    def from_config(cls, cfg: object) -> "ImageResolver":
        return cls(mapping=dict(getattr(cfg, "images", {}) or {}))

    def resolve(self, image: str) -> str:
        return self.mapping.get(image, image)
