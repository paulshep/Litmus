"""
Probe result models and base probe interface.

A probe fires a real or simulated action against a live environment
and returns an observation of what actually happened.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from litmus.controls.models import BehavioralTestCase, ExpectedOutcome


class ObservedOutcome(Enum):
    DENY = "deny"
    ALLOW = "allow"
    ERROR = "error"           # Probe failed to execute cleanly
    INCONCLUSIVE = "inconclusive"


class ValidationStatus(Enum):
    PASS = "pass"             # Observed outcome matches expected
    FAIL = "fail"             # Observed outcome does not match expected
    ERROR = "error"           # Could not determine outcome


@dataclass
class ProbeObservation:
    """
    The raw result of firing a probe against a live environment.
    Records what actually happened, not what was expected.
    """
    test_case_id: str
    observed_outcome: ObservedOutcome
    raw_response: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    probe_target: str = ""           # The environment endpoint probed
    duration_ms: float = 0.0
    error_message: str | None = None


@dataclass
class ValidationResult:
    """
    The result of validating a probe observation against a test case expectation.
    This is what gets mapped to OSCAL.
    """
    test_case_id: str
    control_id: str
    status: ValidationStatus
    observation: ProbeObservation
    expected_outcome: ExpectedOutcome
    evidence_summary: str            # Human-readable explanation for auditors
    remediation_guidance: str = ""   # What to fix if status is FAIL


class BaseProbe(ABC):
    """
    Abstract base class for all environment probes.

    Subclasses implement environment-specific probe logic (AWS, Azure, GCP etc.)
    The interface is intentionally minimal — a probe receives a test case,
    fires against the environment, and returns an observation.
    """

    @abstractmethod
    async def probe(self, test_case: BehavioralTestCase, context: dict[str, Any]) -> ProbeObservation:
        """
        Fire the probe against the live environment.

        Args:
            test_case: The behavioral test case to probe
            context: Runtime context including resource identifiers,
                     credentials, and environment config

        Returns:
            ProbeObservation with the raw result of what happened
        """
        ...

    @abstractmethod
    def supports(self, test_case: BehavioralTestCase) -> bool:
        """Return True if this probe can handle the given test case."""
        ...

    def validate(self, test_case: BehavioralTestCase, observation: ProbeObservation) -> ValidationResult:
        """
        Validate an observation against the test case expectation.
        Default implementation — subclasses can override for nuanced logic.
        """
        expected = test_case.expected_outcome
        observed = observation.observed_outcome

        # Map observed to expected namespace for comparison
        outcome_map = {
            ObservedOutcome.DENY: ExpectedOutcome.DENY,
            ObservedOutcome.ALLOW: ExpectedOutcome.ALLOW,
        }

        if observation.observed_outcome == ObservedOutcome.ERROR:
            status = ValidationStatus.ERROR
            summary = f"Probe error: {observation.error_message}"
        elif outcome_map.get(observed) == expected:
            status = ValidationStatus.PASS
            summary = (
                f"Test {test_case.id} satisfied: "
                f"{test_case.description} — observed {observed.value} as expected."
            )
        else:
            status = ValidationStatus.FAIL
            summary = (
                f"Test {test_case.id} FAILED: "
                f"{test_case.description} — expected {expected.value} "
                f"but observed {observed.value}."
            )

        return ValidationResult(
            test_case_id=test_case.id,
            control_id=test_case.id.rsplit("-aws-", 1)[0],
            status=status,
            observation=observation,
            expected_outcome=expected,
            evidence_summary=summary,
        )
