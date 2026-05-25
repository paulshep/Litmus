# Contributing to Litmus

Litmus is community-driven. There are two equally valuable ways to contribute:

## 1. Control mappings (no code required)

The hardest and most valuable work is translating security controls into behavioral test cases. If you understand a control family and can express "given this principal, this action, this resource — what should happen?", you can contribute.

Control specs live in `litmus/controls/`. See `nist_800_53/ac/ac_3.py` for the pattern.

**Most needed right now:**
- NIST 800-53 AC family (AC-4 through AC-25)
- NIST 800-53 SC (System and Communications Protection)
- CIS AWS Foundations Benchmark mappings

## 2. Probe implementations

Probes are the environment-specific adapters that fire real actions and observe outcomes. If you know an AWS service well, adding probe coverage is high-value.

Probes live in `litmus/probes/`. See `probes/aws/s3_probe.py` for the pattern.

**Most needed right now:**
- AWS: RDS, Lambda, KMS, CloudTrail probes
- Azure: initial probe implementations
- GCP: initial probe implementations

## Getting started

```bash
git clone https://github.com/paulshep/litmus
cd litmus
pip install -e ".[dev]"
pytest
```

## Principles

- **Behavioral, not structural** — test what the environment does, not what config exists
- **Minimal blast radius** — probes should be read-only or use sentinel resources; never destructive
- **Evidence quality** — every test result must produce meaningful OSCAL evidence
- **Implementation agnostic** — controls shouldn't assume Cedar vs IAM vs SCP

## Pull request checklist

- [ ] New control specs include at least 2 test cases (positive and negative)
- [ ] New probes include unit tests using moto (AWS mocking)
- [ ] All tests pass: `pytest`
- [ ] Linting passes: `ruff check .`
