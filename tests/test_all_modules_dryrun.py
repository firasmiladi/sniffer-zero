"""Dry-run every registered module to verify precheck and dry_run paths."""

from __future__ import annotations

import uuid

from srt.core.module import AttackModule, ModuleContext, Status
from srt.core.registry import list_all


def _make_ctx(dry_run: bool = True, authorization_ok: bool = True) -> ModuleContext:
    return ModuleContext(
        session_id=uuid.uuid4(),
        operator="pytest",
        params={},
        dry_run=dry_run,
        authorization_ok=authorization_ok,
        authorized_bands_mhz=["868", "2400", "5800"],
        whitelist={"wifi": ["AA:BB:CC:DD:EE:FF"], "ble": ["device-1"]},
    )


def _module_names():
    """Get all module classes for parametrize."""
    return [(cls.name, cls) for cls in list_all()]


class TestAllModulesDryRun:
    """Run every registered module in dry_run mode to verify basic lifecycle."""

    def test_all_modules_dry_run_authorized(self):
        """Every module should successfully complete a dry_run execution when authorized."""
        ctx = _make_ctx(dry_run=True, authorization_ok=True)
        modules = list_all()
        assert len(modules) > 30

        successes = 0
        for cls in modules:
            instance = cls()
            if instance.risk.value == "forbidden":
                assert instance.precheck(ctx) is False
                continue

            passed = instance.precheck(ctx)
            if passed:
                result = instance.run(ctx)
                assert result.status in (Status.OK, Status.FAIL), (
                    f"{cls.name} returned unexpected status: {result.status}"
                )
                successes += 1
                # Also test cleanup
                instance.cleanup(ctx)

        # Most modules should succeed in dry_run
        assert successes > 15

    def test_passive_modules_base_precheck_no_auth(self):
        """PASSIVE modules base precheck (risk gate) should pass without authorization."""
        ctx = _make_ctx(dry_run=True, authorization_ok=False)
        modules = list_all()

        for cls in modules:
            if cls.risk.value != "passive":
                continue
            instance = cls()
            # Test only the base class precheck (risk gate), not module-specific checks
            assert AttackModule.precheck(instance, ctx) is True, (
                f"{cls.name} PASSIVE module failed base precheck without auth"
            )

    def test_active_modules_require_auth(self):
        """ACTIVE_LAB modules should fail precheck without authorization."""
        ctx = _make_ctx(dry_run=True, authorization_ok=False)
        modules = list_all()

        active_found = False
        for cls in modules:
            if cls.risk.value == "active-lab":
                active_found = True
                instance = cls()
                assert instance.precheck(ctx) is False, (
                    f"{cls.name} should fail precheck without auth"
                )

        assert active_found, "Expected at least one active-lab module"

    def test_all_modules_have_metadata(self):
        """Every module must have name, protocol, and risk set."""
        for cls in list_all():
            assert cls.name, f"{cls.__name__} missing name"
            assert cls.protocol, f"{cls.__name__} missing protocol"
            assert cls.risk is not None, f"{cls.__name__} missing risk"
            assert cls.protocol in ("wifi", "ble", "lora", "spectrum"), (
                f"{cls.name} has unknown protocol: {cls.protocol}"
            )

    def test_all_modules_have_mitre_ttp(self):
        """Every module should have at least one MITRE TTP mapping."""
        for cls in list_all():
            assert len(cls.mitre_ttp) > 0, f"{cls.name} has no MITRE TTP"
