"""
Litmus engine — orchestrates the full validation pipeline.

Wires together: control specs → probe selection → execution → validation → emission
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from litmus.controls.models import BehavioralTestCase, ControlSpec
from litmus.emitter.oscal import emit_assessment_results
from litmus.probes.base import BaseProbe, ValidationResult, ValidationStatus

logger = logging.getLogger(__name__)


@dataclass
class EngineConfig:
    """Runtime configuration for the Litmus engine."""
    system_name: str
    system_id: str
    context: dict[str, Any] = field(default_factory=dict)   # Template variable resolution
    assessor: str = "litmus-automated"
    concurrency: int = 5                                      # Max parallel probes
    fail_fast: bool = False                                   # Stop on first failure


@dataclass
class AssessmentRun:
    """The complete result of a Litmus assessment run."""
    config: EngineConfig
    results: list[ValidationResult] = field(default_factory=list)
    oscal_document: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == ValidationStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == ValidationStatus.FAIL)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == ValidationStatus.ERROR)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def success(self) -> bool:
        return self.failed == 0 and self.errors == 0


class LitmusEngine:
    """
    Orchestrates the full Litmus validation pipeline.

    Usage:
        engine = LitmusEngine(probes=[AWSS3Probe(), AWSIAMProbe()])
        run = await engine.assess(specs=[AC3_SPEC], config=config)
    """

    def __init__(self, probes: list[BaseProbe]):
        self.probes = probes
        self._semaphore: asyncio.Semaphore | None = None

    async def assess(
        self,
        specs: list[ControlSpec],
        config: EngineConfig,
    ) -> AssessmentRun:
        """Run behavioral assessment for the given control specs."""
        self._semaphore = asyncio.Semaphore(config.concurrency)
        run = AssessmentRun(config=config)

        # Flatten all test cases from all specs
        test_cases = [
            (spec, tc)
            for spec in specs
            for tc in spec.test_cases
        ]

        logger.info(f"Starting assessment: {len(test_cases)} test cases across {len(specs)} controls")

        tasks = [
            self._run_test_case(spec, tc, config)
            for spec, tc in test_cases
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Unhandled probe exception: {result}")
                continue
            run.results.append(result)
            if config.fail_fast and result.status == ValidationStatus.FAIL:
                logger.warning("fail_fast enabled — stopping after first failure")
                break

        run.oscal_document = emit_assessment_results(
            results=run.results,
            system_name=config.system_name,
            system_id=config.system_id,
            assessor=config.assessor,
        )

        logger.info(
            f"Assessment complete: {run.passed} passed, "
            f"{run.failed} failed, {run.errors} errors"
        )
        return run

    async def _run_test_case(
        self,
        spec: ControlSpec,
        test_case: BehavioralTestCase,
        config: EngineConfig,
    ) -> ValidationResult:
        """Find the right probe, execute, and validate."""
        async with self._semaphore:
            probe = self._find_probe(test_case)
            if probe is None:
                logger.warning(f"No probe found for test case {test_case.id} — skipping")
                from litmus.probes.base import ObservedOutcome, ProbeObservation
                from datetime import datetime
                observation = ProbeObservation(
                    test_case_id=test_case.id,
                    observed_outcome=ObservedOutcome.ERROR,
                    raw_response={},
                    timestamp=datetime.utcnow(),
                    error_message=f"No probe registered for service={test_case.action.service} "
                                  f"operation={test_case.action.operation}",
                )
                return ValidationResult(
                    test_case_id=test_case.id,
                    control_id=spec.control_id,
                    status=ValidationStatus.ERROR,
                    observation=observation,
                    expected_outcome=test_case.expected_outcome,
                    evidence_summary=f"No probe available for {test_case.id}",
                )

            logger.debug(f"Probing {test_case.id} with {probe.__class__.__name__}")
            observation = await probe.probe(test_case, config.context)
            result = probe.validate(test_case, observation)
            # Stamp control_id from the spec (probe doesn't know which spec it belongs to)
            result.control_id = spec.control_id
            return result

    def _find_probe(self, test_case: BehavioralTestCase) -> BaseProbe | None:
        """Return the first registered probe that supports this test case."""
        for probe in self.probes:
            if probe.supports(test_case):
                return probe
        return None
