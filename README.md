
## Final Assessment

After remediation, the workload identity environment was reduced to:

- 1 total detected finding
- 0 open findings
- 1 accepted finding
- 0 open High findings
- 0 open Medium findings
- 0 open Low findings

The project did not force the assessment to return zero detected risk.

Instead, the remaining high-impact permission was formally evaluated and governed.

## Accepted Risk

### Autumn Graph Automation

**Permission:** `User.ReadWrite.All`

**Severity:** High

**Disposition:** Accepted

### Business Justification

The permission is required for automated Joiner, Mover, Leaver operations that create, update, and disable Microsoft Entra ID users.

### Technical Owner

Alex Morgan

### Compensating Controls

- Certificate-based workload authentication
- No client secret
- Dedicated application identity
- Named technical owner
- Reduced Microsoft Graph permission set
- Structured lifecycle audit logging

### Review Date

2026-12-05

This demonstrates that a high-impact permission can remain technically necessary while still being formally identified, governed, owned, and periodically reviewed.

## Assessment Outputs

The Python assessor generates:

- `reports/workload_identity_assessment.json`
- `reports/workload_identity_findings.csv`

The JSON output provides the complete structured assessment.

The CSV output provides a findings-oriented format suitable for review, reporting, remediation tracking, and downstream governance workflows.

## Portfolio Evidence

1. `01-Workload-Identity-Assessment-Baseline.png`
2. `02-Autumn-Graph-Automation-Stale-Secret-Before-Remediation.png`
3. `03-Workload-Identity-Assessment-After-Secret-Remediation.png`
4. `04-Workload-Identity-Assessment-After-Ownership-Remediation.png`
5. `05-Autumn-Graph-Automation-Permissions-Before-Least-Privilege.png`
6. `06-Least-Privilege-Token-Validation.png`
7. `07-Workload-Identity-Assessment-After-Least-Privilege.png`
8. `08-LedgerFlow-OIDC-Secret-Before-Rotation.png`
9. `09-LedgerFlow-OIDC-New-Secret-Validation.png`
10. `10-Workload-Identity-Assessment-Final-Open-Finding.png`
11. `11-Workload-Identity-Assessment-Governed-Final-State.png`
12. `12-IAM-05-Public-Portfolio-Case-Study.png`

## Security Design Decisions

### No Hard-Coded Secrets

The assessor does not contain client secrets, passwords, access tokens, private keys, or other reusable credentials.

### Read-Only Assessment Identity

The workload identity assessor uses Microsoft Graph read permissions for discovery and analysis.

Remediation actions are performed separately rather than granting the assessment application write access.

### Least Privilege

Application permissions were evaluated against actual workload requirements rather than removed simply because they were classified as high impact.

### Credential Validation Before Removal

Credentials were never removed solely because the assessor flagged them.

Dependencies were validated first.

### Formal Risk Acceptance

Required high-impact access remains visible in the assessment and is governed through:

- Business justification
- Technical ownership
- Compensating controls
- Review scheduling

## Key Outcomes

This project demonstrates:

- Workload identity security assessment
- Microsoft Graph application permission analysis
- Service principal governance
- Application ownership governance
- Credential lifecycle management
- Client secret rotation
- Certificate-based workload authentication
- Least-privilege remediation
- Python security automation
- JSON and CSV security reporting
- Risk acceptance and compensating controls
- IAM and GRC integration

The final state reduced the environment from **15 detected security findings to zero unresolved findings**, while retaining one documented and governed business-required high-impact permission.
