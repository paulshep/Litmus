"""
NIST 800-53 Rev 5 — AC-3: Access Enforcement

Behavioral test cases for access enforcement controls.
Tests that the environment correctly enforces approved authorizations
for logical access to information and system resources.
"""

from litmus.controls.models import (
    Action, BehavioralTestCase, ControlSpec, ExpectedOutcome,
    Principal, Resource, Severity
)

AC3_SPEC = ControlSpec(
    control_id="ac-3",
    control_family="Access Control",
    framework="nist-800-53-r5",
    title="Access Enforcement",
    description=(
        "Enforce approved authorizations for logical access to information "
        "and system resources in accordance with applicable access control policies."
    ),
    references=[
        "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&family=AC"
    ],
    test_cases=[

        BehavioralTestCase(
            id="ac-3-aws-001",
            description="Unauthenticated principal must be denied S3 object read on private bucket",
            principal=Principal(
                type="unauthenticated",
                identifier="anonymous",
            ),
            action=Action(service="s3", operation="GetObject"),
            resource=Resource(
                type="s3_bucket",
                identifier="{{target_bucket}}",
                attributes={"expected_acl": "private"}
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.CRITICAL,
            rationale=(
                "AC-3 requires that access is enforced based on approved authorizations. "
                "Unauthenticated principals have no approved authorization and must be denied."
            ),
            tags=["s3", "unauthenticated", "public-access"],
        ),

        BehavioralTestCase(
            id="ac-3-aws-002",
            description="Principal without explicit S3 write permission must be denied PutObject",
            principal=Principal(
                type="iam_role",
                identifier="{{readonly_role_arn}}",
            ),
            action=Action(service="s3", operation="PutObject"),
            resource=Resource(
                type="s3_bucket",
                identifier="{{target_bucket}}",
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.HIGH,
            rationale=(
                "AC-3 requires that write access is only granted to principals with "
                "explicit authorization. A read-only role must not be able to write."
            ),
            tags=["s3", "write-access", "least-privilege"],
        ),

        BehavioralTestCase(
            id="ac-3-aws-003",
            description="Principal must not be able to escalate IAM privileges beyond their boundary",
            principal=Principal(
                type="iam_role",
                identifier="{{dev_role_arn}}",
            ),
            action=Action(service="iam", operation="AttachRolePolicy"),
            resource=Resource(
                type="iam_role",
                identifier="{{admin_role_arn}}",
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.CRITICAL,
            rationale=(
                "AC-3 requires enforcement of access control policies. A developer role "
                "must not be able to attach policies to admin roles — this would constitute "
                "unauthorized privilege escalation."
            ),
            tags=["iam", "privilege-escalation", "boundary"],
        ),

        BehavioralTestCase(
            id="ac-3-aws-004",
            description="Cross-account access must be denied without explicit trust policy",
            principal=Principal(
                type="iam_role",
                identifier="{{external_account_role_arn}}",
                attributes={"account_id": "{{external_account_id}}"}
            ),
            action=Action(service="s3", operation="GetObject"),
            resource=Resource(
                type="s3_bucket",
                identifier="{{target_bucket}}",
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.HIGH,
            rationale=(
                "AC-3 requires that cross-account access is explicitly authorized. "
                "Without an explicit trust policy permitting cross-account access, "
                "the request must be denied."
            ),
            tags=["s3", "cross-account", "trust-policy"],
        ),

    ]
)
