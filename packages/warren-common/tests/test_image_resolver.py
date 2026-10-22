"""ImageResolver override + fallback (Plan 05b-02)."""

from __future__ import annotations

from types import SimpleNamespace


def test_override_from_config():
    from warren_common.images import ImageResolver

    r = ImageResolver(mapping={"ghcr.io/x": "registry.local/x:pinned"})
    assert r.resolve("ghcr.io/x") == "registry.local/x:pinned"


def test_fallback_to_canonical_when_no_override():
    from warren_common.images import ImageResolver

    r = ImageResolver(mapping={"other": "override"})
    assert r.resolve("ghcr.io/warren-base") == "ghcr.io/warren-base"


def test_from_config_reads_images_table():
    from warren_common.images import ImageResolver

    cfg = SimpleNamespace(images={"a": "b"})
    r = ImageResolver.from_config(cfg)
    assert r.resolve("a") == "b"

    # Missing attribute → empty mapping.
    r_empty = ImageResolver.from_config(SimpleNamespace())
    assert r_empty.resolve("x") == "x"


def test_resolve_is_pure():
    from warren_common.images import ImageResolver

    mapping = {"a": "b"}
    r = ImageResolver(mapping=mapping)
    _ = r.resolve("a")
    _ = r.resolve("z")
    assert mapping == {"a": "b"}
    assert r.resolve("a") == "b"
    assert r.resolve("a") == "b"
