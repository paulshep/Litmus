"""
Core data models for Litmus control specifications and behavioral test cases.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExpectedOutcome(Enum):
    DENY = "deny"
    ALLOW = "allow"
    CONDITIONAL = "conditional"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Principal:
    """Represents the actor performing an action in a behavioral test."""
    type: str                          # e.g. "iam_role", "iam_user", "cedar_principal"
    identifier: str                    # e.g. "arn:aws:iam::123456789:role/ReadOnly"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Action:
    """Represents the action being attempted."""
    service: str                       # e.g. "s3", "iam", "avp"
    operation: str                     # e.g. "GetObject", "CreateUser"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Resource:
    """Represents the resource being acted upon."""
    type: str                          # e.g. "s3_bucket", "iam_role"
    identifier: str                    # e.g. "arn:aws:s3:::my-bucket"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralTestCase:
    """
    A single behavioral test case derived from a security control.

    Each test case expresses: given this principal attempting this action
    on this resource under these conditions, the environment MUST produce
    this outcome. Implementation doesn't matter — only observed behavior.
    """
    id: str
    description: str
    principal: Principal
    action: Action
    resource: Resource
    expected_outcome: ExpectedOutcome
    severity: Severity
    rationale: str                     # Why this behavior is required by the control
    tags: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlSpec:
    """
    Maps an OSCAL control to a set of behavioral test cases.

    This is the core unit of Litmus — the translation of a documented
    control requirement into executable, environment-agnostic test cases.
    """
    control_id: str                    # e.g. "ac-3"
    control_family: str                # e.g. "Access Control"
    framework: str                     # e.g. "nist-800-53-r5"
    title: str
    description: str
    test_cases: list[BehavioralTestCase] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
