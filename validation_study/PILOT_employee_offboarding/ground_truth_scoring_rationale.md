# Ground-Truth Scoring Rationale (for the paper's methods section, not for experts)

This is the "official" risk record for the Employee Offboarding process —
the P/V/I/CE values a process owner would enter into the application, which
the system then turns into the framework's computed category. This is what
Task 2's holistic ratings and Task 1's ICC are compared against. Do not show
this file to participants before they complete Tasks 1 and 2.

Computed with the project's real `services/risk_service.py`
(`calculate_process_risk_metrics`), not hand-calculated or approximated:

| Subprocess | P | V | I | CE | Cost | Asset value | Potentiality | Risk level | Residual risk | Category | Priority |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Offboarding request submission | 2.0 | 2.0 | 2.0 | 0.50 | 2 | 6 | 3.00 | 6.00 | 3.00 | Low | Medium |
| Access inventory and revocation | 2.5 | 2.8 | 2.9 | 0.30 | 4 | 9 | 4.30 | 12.47 | 8.73 | High | Medium |
| Asset return and verification | 2.0 | 1.8 | 1.8 | 0.60 | 2 | 5 | 2.80 | 5.04 | 2.02 | Low | Medium |
| Knowledge transfer and handover | 2.2 | 2.0 | 2.2 | 0.35 | 3 | 6 | 3.20 | 7.04 | 4.58 | Medium | Medium |
| Compliance archival | 1.5 | 1.5 | 1.8 | 0.70 | 1 | 4 | 2.00 | 3.60 | 1.08 | Low | Medium |

## Rationale for these particular inputs

These values are the author's own reasoned judgment, informed by well-documented
patterns in the information-security literature on offboarding and insider
threat (orphaned/unrevoked accounts are consistently identified as a leading
access-control risk — see ISO/IEC 27001 Annex A control on access rights
review), not derived from a specific real organization. This is disclosed
explicitly because it matters for how the concordance result should be
interpreted: Task 2 is testing whether independent experts' gut judgment
agrees with *this* reasoned-but-single-author ground truth, not with an
audited real-world incident history. If you have access to real incident/audit
data for offboarding at a specific organization, replacing these ground-truth
values with that organization's own risk-register entry (and recomputing
`framework_categories.csv` accordingly) would make the comparison stronger.

**Access inventory and revocation** is the intended standout High-risk item:
probability and vulnerability are both rated high (SaaS/shared-account sprawl
makes complete revocation hard to verify), impact is high (unrevoked access is
a direct breach vector), and control effectiveness is the lowest of the five
(0.30 — typically a manual checklist, not automated deprovisioning). This
mirrors a well-established real-world pattern, so a validation result where
experts' Task 2 judgment also flags this subprocess as High would be a
meaningful (not circular) concordance signal.
