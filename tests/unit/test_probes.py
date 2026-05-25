"""Unit tests for AWS probes using moto mocking."""

import pytest
import boto3
from moto import mock_aws
from unittest.mock import patch, MagicMock

from litmus.controls.models import (
    Action, BehavioralTestCase, ExpectedOutcome, Principal, Resource, Severity,
)
from litmus.probes.aws.s3_probe import AWSS3Probe, AWSIAMProbe
from litmus.probes.base import ObservedOutcome, ValidationStatus


def _make_tc(service, operation, principal_type="iam_role", principal_id="arn:aws:iam::123456789012:role/test"):
    return BehavioralTestCase(
        id=f"test-{service}-{operation.lower()}",
        description=f"Test {operation} on {service}",
        principal=Principal(type=principal_type, identifier=principal_id),
        action=Action(service=service, operation=operation),
        resource=Resource(type=f"{service}_bucket", identifier="test-bucket"),
        expected_outcome=ExpectedOutcome.DENY,
        severity=Severity.HIGH,
        rationale="Test rationale",
    )


class TestAWSS3ProbeSupports:
    def test_supports_get_object(self):
        probe = AWSS3Probe()
        tc = _make_tc("s3", "GetObject")
        assert probe.supports(tc) is True

    def test_supports_put_object(self):
        probe = AWSS3Probe()
        tc = _make_tc("s3", "PutObject")
        assert probe.supports(tc) is True

    def test_does_not_support_iam(self):
        probe = AWSS3Probe()
        tc = _make_tc("iam", "CreateUser")
        assert probe.supports(tc) is False

    def test_does_not_support_unknown_operation(self):
        probe = AWSS3Probe()
        tc = _make_tc("s3", "UnknownOp")
        assert probe.supports(tc) is False


class TestAWSIAMProbeSupports:
    def test_supports_create_user(self):
        probe = AWSIAMProbe()
        tc = _make_tc("iam", "CreateUser")
        assert probe.supports(tc) is True

    def test_does_not_support_s3(self):
        probe = AWSIAMProbe()
        tc = _make_tc("s3", "GetObject")
        assert probe.supports(tc) is False


@pytest.fixture
def aws_s3_bucket():
    """Fixture: mocked S3 bucket via moto."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        s3.put_bucket_acl(Bucket="test-bucket", ACL="private")
        yield s3


class TestAWSS3ProbeBehavior:

    @pytest.mark.asyncio
    async def test_list_bucket_allowed(self, aws_s3_bucket):
        probe = AWSS3Probe()
        tc = _make_tc("s3", "ListBucket")
        context = {"target_bucket": "test-bucket"}

        observation = await probe.probe(tc, context)
        assert observation.observed_outcome == ObservedOutcome.ALLOW

    @pytest.mark.asyncio
    async def test_get_object_not_found_is_error_not_deny(self, aws_s3_bucket):
        """HeadObject on non-existent key returns 404, which is not an access deny."""
        probe = AWSS3Probe()
        tc = _make_tc("s3", "GetObject")
        context = {"target_bucket": "test-bucket", "probe_key": "__nonexistent__"}

        observation = await probe.probe(tc, context)
        # 404 NoSuchKey is not an AccessDenied — should be ERROR
        assert observation.observed_outcome in (ObservedOutcome.ERROR, ObservedOutcome.ALLOW)

    @pytest.mark.asyncio
    async def test_put_object_allowed(self, aws_s3_bucket):
        probe = AWSS3Probe()
        tc = _make_tc("s3", "PutObject")
        context = {"target_bucket": "test-bucket"}

        observation = await probe.probe(tc, context)
        assert observation.observed_outcome == ObservedOutcome.ALLOW

    def test_resolve_template_variable(self):
        probe = AWSS3Probe()
        resolved = probe._resolve("{{target_bucket}}", {"target_bucket": "my-bucket"})
        assert resolved == "my-bucket"

    def test_resolve_multiple_variables(self):
        probe = AWSS3Probe()
        resolved = probe._resolve("{{account_id}}/{{bucket}}", {
            "account_id": "123456789012",
            "bucket": "my-bucket"
        })
        assert resolved == "123456789012/my-bucket"


class TestProbeValidation:
    """Test the base validate() logic."""

    def test_pass_when_deny_observed_and_deny_expected(self):
        from litmus.probes.base import ProbeObservation
        from datetime import datetime

        probe = AWSS3Probe()
        tc = _make_tc("s3", "GetObject")
        tc.expected_outcome = ExpectedOutcome.DENY

        obs = ProbeObservation(
            test_case_id=tc.id,
            observed_outcome=ObservedOutcome.DENY,
            raw_response={"Error": {"Code": "AccessDenied"}},
            timestamp=datetime.utcnow(),
        )

        result = probe.validate(tc, obs)
        assert result.status == ValidationStatus.PASS

    def test_fail_when_allow_observed_but_deny_expected(self):
        from litmus.probes.base import ProbeObservation
        from datetime import datetime

        probe = AWSS3Probe()
        tc = _make_tc("s3", "GetObject")
        tc.expected_outcome = ExpectedOutcome.DENY

        obs = ProbeObservation(
            test_case_id=tc.id,
            observed_outcome=ObservedOutcome.ALLOW,
            raw_response={},
            timestamp=datetime.utcnow(),
        )

        result = probe.validate(tc, obs)
        assert result.status == ValidationStatus.FAIL

    def test_error_when_probe_errors(self):
        from litmus.probes.base import ProbeObservation
        from datetime import datetime

        probe = AWSS3Probe()
        tc = _make_tc("s3", "GetObject")

        obs = ProbeObservation(
            test_case_id=tc.id,
            observed_outcome=ObservedOutcome.ERROR,
            raw_response={},
            timestamp=datetime.utcnow(),
            error_message="Connection timeout",
        )

        result = probe.validate(tc, obs)
        assert result.status == ValidationStatus.ERROR
