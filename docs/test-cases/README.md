# Test Cases as Code

Test-case records describe verification intent. Executable tests remain next
to their components in `control-plane/tests/`, `worker/tests/`,
`egress-proxy/tests/`, `tool-runner/tests/`, `frontend/tests/`, or `lab/`.

Each test-case document starts with:

```yaml
---
title: Test area
status: ready
risk: R2
owner: engineering
---
```

Each case has a unique `TC-<DOMAIN>-NNN` heading and must contain:

- `Requirements:` followed by requirement IDs;
- `Automated tests:` followed by repository-relative file paths;
- an objective and expected results.

The validation pipeline checks that referenced requirements and files exist
and that the executable test contains the referenced requirement ID.

