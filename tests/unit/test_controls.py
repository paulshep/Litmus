"""Unit tests for control spec models."""

import pytest
from litmus.controls.models import (
    Action, BehavioralTestCase, ControlSpec, ExpectedOutcome,
    Principal, Resource, Severity,
)
from litmus.controls.nist_800_53.ac.ac_2 import AC2_SPEC
from litmus.controls.nist_800_53.ac.ac_3 import AC3_SPEC


def test_ac3_spec_has_required_fields():
    assert AC3_SPEC.control_id == "ac-3"
    assert AC3_SPEC.framework == "nist-800-53-r5"
    assert len(AC3_SPEC.test_cases) >= 2


def test_ac2_spec_has_required_fields():
    assert AC2_SPEC.control_id == "ac-2"
    assert len(AC2_SPEC.test_cases) >= 2


def test_all_ac3_test_cases_have_ids():
    for tc in AC3_SPEC.test_cases:
        assert tc.id, f"Test case missing id: {tc}"
        assert tc.id.startswith("ac-3-")


def test_all_test_cases_have_rationale():
    for spec in [AC2_SPEC, AC3_SPEC]:
        for tc in spec.test_cases:
            assert tc.rationale, f"{tc.id} missing rationale"


def test_deny_test_cases_exist():
    deny_cases = [tc for tc in AC3_SPEC.test_cases if tc.expected_outcome == ExpectedOutcome.DENY]
    assert len(deny_cases) >= 1, "AC-3 should have at least one DENY test case"


def test_critical_severity_test_cases_exist():
    critical = [tc for tc in AC3_SPEC.test_cases if tc.severity == Severity.CRITICAL]
    assert len(critical) >= 1, "AC-3 should have at least one CRITICAL severity test case"


def test_behavioral_test_case_construction():
    tc = BehavioralTestCase(
        id="test-001",
        description="Test case",
        principal=Principal(type="iam_role", identifier="arn:aws:iam::123:role/test"),
        action=Action(service="s3", operation="GetObject"),
        resource=Resource(type="s3_bucket", identifier="my-bucket"),
        expected_outcome=ExpectedOutcome.DENY,
        severity=Severity.HIGH,
        rationale="Test rationale",
    )
    assert tc.id == "test-001"
    assert tc.expected_outcome == ExpectedOutcome.DENY
    assert tc.tags == []  # default empty list
