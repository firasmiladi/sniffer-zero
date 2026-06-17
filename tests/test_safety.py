"""Tests for srt.core.safety authorization and whitelist loading."""

from __future__ import annotations

from textwrap import dedent

from srt.core.safety import load_authorization, load_whitelist


class TestLoadAuthorization:
    def test_killswitch_returns_not_ok(self, monkeypatch):
        monkeypatch.setenv("SRT_KILLSWITCH", "1")
        auth = load_authorization()
        assert auth.ok is False
        assert "kill-switch" in auth.reason

    def test_valid_yaml_returns_ok(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SRT_KILLSWITCH", raising=False)
        auth_yaml = dedent("""\
            authorization:
              client: "TestCorp"
              scope: "lab-only"
              start_date: "2024-01-01"
              end_date: "2025-12-31"
              signed_by: "John Doe"
              signed_doc_sha256: "abc123"
              authorized_bands_mhz:
                - "868"
                - "2400"
              shielded_environment: true
        """)
        p = tmp_path / "auth.yaml"
        p.write_text(auth_yaml)

        auth = load_authorization(path=p)
        assert auth.ok is True
        assert auth.client == "TestCorp"
        assert auth.signed_by == "John Doe"
        assert "868" in auth.authorized_bands_mhz

    def test_placeholder_returns_not_ok(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SRT_KILLSWITCH", raising=False)
        auth_yaml = dedent("""\
            authorization:
              client: "TestCorp"
              signed_by: "<fill in>"
        """)
        p = tmp_path / "auth.yaml"
        p.write_text(auth_yaml)

        auth = load_authorization(path=p)
        assert auth.ok is False
        assert "placeholder" in auth.reason

    def test_missing_file_returns_not_ok(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SRT_KILLSWITCH", raising=False)
        p = tmp_path / "nonexistent.yaml"
        auth = load_authorization(path=p)
        assert auth.ok is False


class TestLoadWhitelist:
    def test_valid_whitelist(self, tmp_path):
        whitelist_yaml = dedent("""\
            whitelist:
              wifi:
                - "AA:BB:CC:DD:EE:FF"
                - "11:22:33:44:55:66"
              ble:
                - "device-1"
        """)
        p = tmp_path / "whitelist.yaml"
        p.write_text(whitelist_yaml)

        wl = load_whitelist(path=p)
        assert "wifi" in wl
        assert len(wl["wifi"]) == 2
        assert "ble" in wl

    def test_missing_file_returns_empty(self, tmp_path):
        p = tmp_path / "nonexistent.yaml"
        wl = load_whitelist(path=p)
        assert wl == {}
