"""Unit tests for the OSCAL assessment result emitter."""

import pytest
from datetime import datetime

from litmus.controls.models import ExpectedOutcome
from litmus.emitter.oscal import emit_assessment_results
from litmus.probes.base import ObservedOutcome, ProbeObservation, ValidationResult, ValidationStatus


def _make_result(test_case_id, control_id, status, expected=ExpectedOutcome.DENY, observed=ObservedOutcome.DENY):
    return ValidationResult(
        test_case_id=test_case_id,
        control_id=control_id,
        status=status,
        observation=ProbeObservation(
            test_case_id=test_case_id,
            observed_outcome=observed,
            raw_response={},
            timestamp=datetime.utcnow(),
            probe_target="s3://test-bucket",
            duration_ms=42.0,
        ),
        expected_outcome=expected,
        evidence_summary=f"Test evidence for {test_case_id}",
    )


class TestOSCALEmitter:

    def test_emits_valid_oscal_structure(self):
        results = [_make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS)]
        doc = emit_assessment_results(results, "test-system", "sys-001")

        assert "assessment-results" in doc
        ar = doc["assessment-results"]
        assert "uuid" in ar
        assert "metadata" in ar
        assert "results" in ar

    def test_metadata_contains_title(self):
        results = [_make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS)]
        doc = emit_assessment_results(results, "MySystem", "sys-001")

        title = doc["assessment-results"]["metadata"]["title"]
        assert "MySystem" in title
        assert "Litmus" in title

    def test_findings_count_matches_results(self):
        results = [
            _make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS),
            _make_result("ac-3-aws-002", "ac-3", ValidationStatus.FAIL, observed=ObservedOutcome.ALLOW),
            _make_result("ac-2-aws-001", "ac-2", ValidationStatus.ERROR),
        ]
        doc = emit_assessment_results(results, "test-system", "sys-001")
        findings = doc["assessment-results"]["results"][0]["findings"]
        assert len(findings) == 3

    def test_observations_count_matches_results(self):
        results = [
            _make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS),
            _make_result("ac-3-aws-002", "ac-3", ValidationStatus.PASS),
        ]
        doc = emit_assessment_results(results, "test-system", "sys-001")
        observations = doc["assessment-results"]["results"][0]["observations"]
        assert len(observations) == 2

    def test_pass_maps_to_satisfied(self):
        results = [_make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS)]
        doc = emit_assessment_results(results, "test-system", "sys-001")
        finding = doc["assessment-results"]["results"][0]["findings"][0]
        assert finding["target"]["status"]["state"] == "satisfied"

    def test_fail_maps_to_not_satisfied(self):
        results = [
            _make_result("ac-3-aws-001", "ac-3", ValidationStatus.FAIL, observed=ObservedOutcome.ALLOW)
        ]
        doc = emit_assessment_results(results, "test-system", "sys-001")
        finding = doc["assessment-results"]["results"][0]["findings"][0]
        assert finding["target"]["status"]["state"] == "not-satisfied"

    def test_summary_remarks_contains_counts(self):
        results = [
            _make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS),
            _make_result("ac-3-aws-002", "ac-3", ValidationStatus.FAIL, observed=ObservedOutcome.ALLOW),
        ]
        doc = emit_assessment_results(results, "test-system", "sys-001")
        remarks = doc["assessment-results"]["results"][0]["remarks"]
        assert "2" in remarks      # total
        assert "1" in remarks      # passed and failed

    def test_observation_includes_probe_metadata(self):
        results = [_make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS)]
        doc = emit_assessment_results(results, "test-system", "sys-001")
        obs = doc["assessment-results"]["results"][0]["observations"][0]

        props = {p["name"]: p["value"] for p in obs["relevant-evidence"][0]["props"]}
        assert props["observed-outcome"] == "deny"
        assert props["expected-outcome"] == "deny"
        assert props["probe-tool"] == "litmus"

    def test_all_uuids_are_strings(self):
        results = [_make_result("ac-3-aws-001", "ac-3", ValidationStatus.PASS)]
        doc = emit_assessment_results(results, "test-system", "sys-001")

        assert isinstance(doc["assessment-results"]["uuid"], str)
        assert len(doc["assessment-results"]["uuid"]) == 36  # UUID4 format
