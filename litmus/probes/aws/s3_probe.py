"""
AWS probe implementations.

Fires real AWS API calls to observe actual environment behavior.
Uses boto3 with caller-supplied credentials — Litmus never stores credentials.
"""

import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from litmus.controls.models import BehavioralTestCase
from litmus.probes.base import BaseProbe, ObservedOutcome, ProbeObservation


class AWSS3Probe(BaseProbe):
    """Probes AWS S3 access control behavior."""

    SUPPORTED_OPERATIONS = {"GetObject", "PutObject", "DeleteObject", "ListBucket"}

    def supports(self, test_case: BehavioralTestCase) -> bool:
        return (
            test_case.action.service == "s3"
            and test_case.action.operation in self.SUPPORTED_OPERATIONS
        )

    async def probe(self, test_case: BehavioralTestCase, context: dict[str, Any]) -> ProbeObservation:
        """
        Attempt the S3 operation and observe whether it is allowed or denied.
        Uses dry-run / minimal-impact approach where possible.
        """
        bucket = self._resolve(test_case.resource.identifier, context)
        session = self._build_session(test_case.principal, context)
        s3 = session.client("s3")

        start = time.monotonic()
        try:
            result = await self._dispatch(s3, test_case.action.operation, bucket, context)
            duration = (time.monotonic() - start) * 1000

            return ProbeObservation(
                test_case_id=test_case.id,
                observed_outcome=ObservedOutcome.ALLOW,
                raw_response=result,
                probe_target=f"s3://{bucket}",
                duration_ms=duration,
            )

        except ClientError as e:
            duration = (time.monotonic() - start) * 1000
            code = e.response["Error"]["Code"]

            if code in ("AccessDenied", "403", "AllAccessDisabled"):
                return ProbeObservation(
                    test_case_id=test_case.id,
                    observed_outcome=ObservedOutcome.DENY,
                    raw_response=e.response,
                    probe_target=f"s3://{bucket}",
                    duration_ms=duration,
                )

            # Unexpected error — inconclusive
            return ProbeObservation(
                test_case_id=test_case.id,
                observed_outcome=ObservedOutcome.ERROR,
                raw_response=e.response,
                probe_target=f"s3://{bucket}",
                duration_ms=duration,
                error_message=str(e),
            )

    async def _dispatch(self, s3, operation: str, bucket: str, context: dict) -> dict:
        """Dispatch the correct boto3 call for the operation."""
        if operation == "GetObject":
            # Use HeadObject as a read probe — same auth check, no data transfer
            return s3.head_object(Bucket=bucket, Key=context.get("probe_key", "__litmus_probe__"))
        elif operation == "PutObject":
            # Write a minimal sentinel object
            return s3.put_object(
                Bucket=bucket,
                Key="__litmus_probe__",
                Body=b"litmus-probe",
                Tagging="litmus=true"
            )
        elif operation == "ListBucket":
            return s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
        elif operation == "DeleteObject":
            return s3.delete_object(Bucket=bucket, Key=context.get("probe_key", "__litmus_probe__"))
        else:
            raise ValueError(f"Unsupported S3 operation: {operation}")

    def _build_session(self, principal, context: dict) -> boto3.Session:
        """Build a boto3 session for the given principal."""
        if principal.type == "unauthenticated":
            return boto3.Session()  # No credentials = anonymous

        if principal.type == "iam_role":
            role_arn = self._resolve(principal.identifier, context)
            sts = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="litmus-probe"
            )["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

        # Default: use ambient credentials from environment
        return boto3.Session()

    def _resolve(self, value: str, context: dict) -> str:
        """Resolve template variables like {{target_bucket}} from context."""
        for key, val in context.items():
            value = value.replace(f"{{{{{key}}}}}", str(val))
        return value


class AWSIAMProbe(BaseProbe):
    """Probes AWS IAM access control behavior."""

    SUPPORTED_OPERATIONS = {"CreateUser", "AttachRolePolicy", "CreateRole", "DeleteUser"}

    def supports(self, test_case: BehavioralTestCase) -> bool:
        return (
            test_case.action.service == "iam"
            and test_case.action.operation in self.SUPPORTED_OPERATIONS
        )

    async def probe(self, test_case: BehavioralTestCase, context: dict[str, Any]) -> ProbeObservation:
        """
        Use IAM Policy Simulator to check whether the action would be allowed
        without making destructive changes to the environment.
        """
        session = self._build_session(test_case.principal, context)
        iam = session.client("iam")

        principal_arn = self._resolve(test_case.principal.identifier, context)
        resource_arn = self._resolve(test_case.resource.identifier, context)
        action = f"iam:{test_case.action.operation}"

        start = time.monotonic()
        try:
            response = iam.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=[action],
                ResourceArns=[resource_arn] if resource_arn != "*" else ["*"],
            )
            duration = (time.monotonic() - start) * 1000

            decision = response["EvaluationResults"][0]["EvalDecision"]
            outcome = ObservedOutcome.ALLOW if decision == "allowed" else ObservedOutcome.DENY

            return ProbeObservation(
                test_case_id=test_case.id,
                observed_outcome=outcome,
                raw_response=response,
                probe_target=f"iam://{principal_arn}",
                duration_ms=duration,
            )

        except ClientError as e:
            duration = (time.monotonic() - start) * 1000
            return ProbeObservation(
                test_case_id=test_case.id,
                observed_outcome=ObservedOutcome.ERROR,
                raw_response=e.response,
                probe_target=f"iam://{principal_arn}",
                duration_ms=duration,
                error_message=str(e),
            )

    def _build_session(self, principal, context: dict) -> boto3.Session:
        return boto3.Session()  # Use ambient credentials for IAM Simulator

    def _resolve(self, value: str, context: dict) -> str:
        for key, val in context.items():
            value = value.replace(f"{{{{{key}}}}}", str(val))
        return value
