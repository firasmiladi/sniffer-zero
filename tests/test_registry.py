"""Tests for srt.core.registry module registration and discovery."""

from __future__ import annotations

from srt.core.registry import _MODULES, get, list_all


class TestRegistry:
    def test_get_registered_module(self):
        """After autodiscover (session fixture), we can get known modules."""
        # This relies on autodiscover having run in the session fixture
        cls = get("lora.anomaly_detector")
        assert cls.name == "lora.anomaly_detector"
        assert cls.protocol == "lora"

    def test_list_all_sorted(self):
        """list_all returns modules sorted by name."""
        modules = list_all()
        assert len(modules) > 0
        names = [m.name for m in modules]
        assert names == sorted(names)

    def test_autodiscover_populates_registry(self):
        """autodiscover finds more than 30 modules."""
        # autodiscover already ran via session fixture
        assert len(_MODULES) > 30

    def test_get_unknown_raises_keyerror(self):
        """get() with unknown name raises KeyError."""
        import pytest

        with pytest.raises(KeyError):
            get("nonexistent.module")
