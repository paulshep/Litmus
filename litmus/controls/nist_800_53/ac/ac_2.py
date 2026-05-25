"""
NIST 800-53 Rev 5 — AC-2: Account Management

Behavioral test cases for account management controls.
Tests that the environment correctly manages system accounts including
establishing, activating, modifying, reviewing, disabling, and removing accounts.
"""

from litmus.controls.models import (
    Action, BehavioralTestCase, ControlSpec, ExpectedOutcome,
    Principal, Resource, Severity
)

AC2_SPEC = ControlSpec(
    control_id="ac-2",
    control_family="Access Control",
    framework="nist-800-53-r5",
    title="Account Management",
    description=(
        "Manage system accounts, including establishing, activating, modifying, "
        "reviewing, disabling, and removing accounts."
    ),
    references=[
        "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&family=AC"
    ],
    test_cases=[

        BehavioralTestCase(
            id="ac-2-aws-001",
            description="Disabled IAM user must be denied all API actions",
            principal=Principal(
                type="iam_user",
                identifier="{{disabled_user_arn}}",
                attributes={"status": "disabled"}
            ),
            action=Action(service="s3", operation="ListBuckets"),
            resource=Resource(
                type="aws_account",
                identifier="{{account_id}}",
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.CRITICAL,
            rationale=(
                "AC-2 requires that disabled accounts are prevented from accessing "
                "system resources. A disabled IAM user must be denied all actions."
            ),
            tags=["iam", "disabled-account", "account-lifecycle"],
        ),

        BehavioralTestCase(
            id="ac-2-aws-002",
            description="Non-admin principal must not be able to create new IAM users",
            principal=Principal(
                type="iam_role",
                identifier="{{developer_role_arn}}",
            ),
            action=Action(service="iam", operation="CreateUser"),
            resource=Resource(
                type="iam_user",
                identifier="*",
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.HIGH,
            rationale=(
                "AC-2 requires that account creation is restricted to authorized "
                "administrators. Non-admin principals must not be able to create accounts."
            ),
            tags=["iam", "account-creation", "least-privilege"],
        ),

        BehavioralTestCase(
            id="ac-2-aws-003",
            description="Service account must not be usable for interactive console login",
            principal=Principal(
                type="iam_user",
                identifier="{{service_account_arn}}",
                attributes={"account_type": "service"}
            ),
            action=Action(
                service="signin",
                operation="ConsoleLogin",
            ),
            resource=Resource(
                type="aws_console",
                identifier="{{account_id}}",
            ),
            expected_outcome=ExpectedOutcome.DENY,
            severity=Severity.MEDIUM,
            rationale=(
                "AC-2 requires that service accounts are managed distinctly from "
                "user accounts. Service accounts should not have console access."
            ),
            tags=["iam", "service-account", "console-access"],
        ),

    ]
)
