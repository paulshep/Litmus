"""Unit tests for the Litmus engine orchestrator."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime

from litmus.controls.models import (
    Action, BehavioralTestCase, ControlSpec, ExpectedOutcome,
    Principal, Resource, Severity,
)
from litmus.engine.runner import EngineConfig, LitmusEngine
from litmus.probes.base import (
    BaseProbe, ObservedOutcome, ProbeObservation, ValidationResult, ValidationStatus,
)


def _make_spec(control_id, test_cases):
    return ControlSpec(
        control_id=control_id,
        control_family="Access Control",
        framework="nist-800-53-r5",
        title=f"Test Control {control_id}",
        description="Test",
        test_cases=test_cases,
    )


def _make_tc(tc_id, service="s3", operation="GetObject"):
    return BehavioralTestCase(
        id=tc_id,
        description="Test case",
        principal=Principal(type="iam_role", identifier="arn:aws:iam::123:role/test"),
        action=Action(service=service, operation=operation),
        resource=Resource(type="s3_bucket", identifier="test-bucket"),
        expected_outcome=ExpectedOutcome.DENY,
        severity=Severity.HIGH,
        rationale="Test",
    )


def _mock_probe(supports=True, outcome=ObservedOutcome.DENY):
    """Build a mock probe that returns the given outcome."""
    probe = MagicMock(spec=BaseProbe)
    probe.supports.return_value = supports

    observation = ProbeObservation(
        test_case_id="",
        observed_outcome=outcome,
        raw_response={},
        timestamp=datetime.utcnow(),
    )
    probe.probe = AsyncMock(return_value=observation)

    result = ValidationResult(
        test_case_id="",
        control_id="",
        status=ValidationStatus.PASS if outcome == ObservedOutcome.DENY else ValidationStatus.FAIL,
        observation=observation,
        expected_outcome=ExpectedOutcome.DENY,
        evidence_summary="Mock evidence",
    )
    probe.validate.return_value = result
    return probe


class TestLitmusEngine:

    @pytest.mark.asyncio
    async def test_assess_returns_run_with_results(self):
        tc = _make_tc("ac-3-aws-001")
        spec = _make_spec("ac-3", [tc])
        probe = _mock_probe(supports=True, outcome=ObservedOutcome.DENY)

        engine = LitmusEngine(probes=[probe])
        config = EngineConfig(system_name="test", system_id="sys-001")

        run = await engine.assess(specs=[spec], config=config)

        assert run.total == 1
        assert len(run.results) == 1

    @pytest.mark.asyncio
    async def test_assess_calls_probe_for_each_test_case(self):
        tcs = [_make_tc(f"ac-3-aws-00{i}") for i in range(3)]
        spec = _make_spec("ac-3", tcs)
        probe = _mock_probe(supports=True, outcome=ObservedOutcome.DENY)

        engine = LitmusEngine(probes=[probe])
        config = EngineConfig(system_name="test", system_id="sys-001")

        run = await engine.assess(specs=[spec], config=config)

        assert probe.probe.call_count == 3

    @pytest.mark.asyncio
    async def test_assess_emits_oscal_document(self):
        tc = _make_tc("ac-3-aws-001")
        spec = _make_spec("ac-3", [tc])
        probe = _mock_probe(supports=True)

        engine = LitmusEngine(probes=[probe])
        config = EngineConfig(system_name="MySystem", system_id="sys-001")

        run = await engine.assess(specs=[spec], config=config)

        assert "assessment-results" in run.oscal_document

    @pytest.mark.asyncio
    async def test_no_probe_found_returns_error_result(self):
        tc = _make_tc("ac-3-aws-001", service="unknown-service")
        spec = _make_spec("ac-3", [tc])
        probe = _mock_probe(supports=False)  # No probe supports this

        engine = LitmusEngine(probes=[probe])
        config = EngineConfig(system_name="test", system_id="sys-001")

        run = await engine.assess(specs=[spec], config=config)

        assert run.total == 1
        assert run.results[0].status == ValidationStatus.ERROR

    @pytest.mark.asyncio
    async def test_success_property_false_when_failures_exist(self):
        tc = _make_tc("ac-3-aws-001")
        spec = _make_spec("ac-3", [tc])
        probe = _mock_probe(supports=True, outcome=ObservedOutcome.ALLOW)  # Allow when Deny expected

        engine = LitmusEngine(probes=[probe])
        config = EngineConfig(system_name="test", system_id="sys-001")

        run = await engine.assess(specs=[spec], config=config)

        assert run.success is False

    @pytest.mark.asyncio
    async def test_multiple_specs_all_executed(self):
        spec1 = _make_spec("ac-2", [_make_tc("ac-2-aws-001", service="s3")])
        spec2 = _make_spec("ac-3", [_make_tc("ac-3-aws-001", service="s3")])
        probe = _mock_probe(supports=True)

        engine = LitmusEngine(probes=[probe])
        config = EngineConfig(system_name="test", system_id="sys-001")

        run = await engine.assess(specs=[spec1, spec2], config=config)

        assert run.total == 2
        assert probe.probe.call_count == 2
