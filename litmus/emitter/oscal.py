"""
OSCAL Assessment Result emitter.

Transforms Litmus ValidationResults into OSCAL-structured assessment
artifacts suitable for audit submission.

Spec: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from litmus.probes.base import ValidationResult, ValidationStatus


def emit_assessment_results(
    results: list[ValidationResult],
    system_name: str,
    system_id: str,
    assessor: str = "litmus-automated",
) -> dict[str, Any]:
    """
    Emit a complete OSCAL Assessment Results document from a list of
    Litmus ValidationResults.
    """
    now = datetime.now(timezone.utc).isoformat()

    findings = [_build_finding(r) for r in results]
    observations = [_build_observation(r) for r in results]

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Litmus Behavioral Control Assessment — {system_name}",
                "last-modified": now,
                "version": "1.0",
                "oscal-version": "1.1.2",
                "roles": [{"id": "assessor", "title": "Automated Assessor"}],
                "parties": [{
                    "uuid": str(uuid.uuid4()),
                    "type": "tool",
                    "name": assessor,
                    "remarks": "Behavioral control validation performed by Litmus"
                }]
            },
            "import-ap": {
                "href": "#",
                "remarks": "Assessment performed via behavioral probing by Litmus"
            },
            "results": [{
                "uuid": str(uuid.uuid4()),
                "title": f"Behavioral Assessment — {now}",
                "description": (
                    "Automated behavioral control validation. Each finding represents "
                    "the observed behavior of the environment under test conditions "
                    "derived from the referenced control requirements."
                ),
                "start": now,
                "end": now,
                "reviewed-controls": {
                    "control-selections": [
                        {
                            "include-controls": [
                                {"control-id": cid}
                                for cid in sorted({r.control_id for r in results})
                            ]
                        }
                    ]
                },
                "observations": observations,
                "findings": findings,
                "remarks": _summary_remarks(results),
            }]
        }
    }


def _build_observation(result: ValidationResult) -> dict[str, Any]:
    """Build an OSCAL observation from a validation result."""
    obs = result.observation
    return {
        "uuid": str(uuid.uuid4()),
        "title": f"Behavioral probe: {result.test_case_id}",
        "description": result.evidence_summary,
        "methods": ["TEST"],
        "types": ["finding"],
        "collected": obs.timestamp.isoformat(),
        "relevant-evidence": [{
            "description": f"Probe target: {obs.probe_target}",
            "props": [
                {"name": "observed-outcome", "value": obs.observed_outcome.value},
                {"name": "expected-outcome", "value": result.expected_outcome.value},
                {"name": "duration-ms", "value": str(obs.duration_ms)},
                {"name": "probe-tool", "value": "litmus"},
            ],
            "remarks": json.dumps(obs.raw_response, default=str)
        }]
    }


def _build_finding(result: ValidationResult) -> dict[str, Any]:
    """Build an OSCAL finding from a validation result."""
    status_map = {
        ValidationStatus.PASS: "satisfied",
        ValidationStatus.FAIL: "not-satisfied",
        ValidationStatus.ERROR: "other",
    }

    finding = {
        "uuid": str(uuid.uuid4()),
        "title": f"{result.control_id.upper()} — {result.test_case_id}",
        "description": result.evidence_summary,
        "target": {
            "type": "statement-id",
            "target-id": result.control_id,
            "status": {
                "state": status_map[result.status],
                "reason": result.status.value,
            }
        },
        "implementation-statement-uuid": str(uuid.uuid4()),
    }

    if result.remediation_guidance:
        finding["remarks"] = result.remediation_guidance

    return finding


def _summary_remarks(results: list[ValidationResult]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r.status == ValidationStatus.PASS)
    failed = sum(1 for r in results if r.status == ValidationStatus.FAIL)
    errors = sum(1 for r in results if r.status == ValidationStatus.ERROR)

    return (
        f"Litmus behavioral assessment complete. "
        f"{total} test cases executed: {passed} passed, {failed} failed, {errors} errors. "
        f"Pass rate: {(passed/total*100):.1f}%"
    )
