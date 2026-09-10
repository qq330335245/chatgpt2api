from __future__ import annotations

from services.register import openai_register
from services.register_service import _normalize


def test_resolve_register_flow_platform():
    old = openai_register.config.get("register_flow")
    try:
        openai_register.config["register_flow"] = "platform"
        assert openai_register._resolve_register_flow() == "platform"
        openai_register.config["register_flow"] = "platform_oauth"
        assert openai_register._resolve_register_flow() == "platform"
        openai_register.config["register_flow"] = "passwordless"
        assert openai_register._resolve_register_flow() == "passwordless"
        openai_register.config["register_flow"] = "legacy"
        assert openai_register._resolve_register_flow() == "legacy"
    finally:
        openai_register.config["register_flow"] = old


def test_normalize_keeps_platform_flow():
    cfg = _normalize({"register_flow": "platform"})
    assert cfg["register_flow"] == "platform"
    cfg = _normalize({"register_flow": "passwordless"})
    assert cfg["register_flow"] == "passwordless"


def test_platform_registrar_importable():
    from services.register.platform_register import PlatformHarRegistrar

    assert PlatformHarRegistrar.FLOW_NAME == "platform"
