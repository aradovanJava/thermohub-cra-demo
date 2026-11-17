# Security policy – coordinated vulnerability disclosure

*CRA Annex I Part II (5) policy on coordinated vulnerability disclosure, (6) contact address,
(4) public disclosure of fixed vulnerabilities. Example policy for the fictitious ThermoHub product.*

## Reporting a vulnerability

- E-mail **security@thermohub.example** (PGP key: `/.well-known/pgp-key.txt`) or use the private
  vulnerability reporting form of this repository.
- Please include the affected version, steps to reproduce and the impact you observed.
- Do not include personal data of third parties.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement of your report | 2 business days |
| Triage and severity (CVSS v4) | 5 business days |
| Fix or mitigation for critical/high issues | 30 days |
| Coordinated publication (advisory, CSAF, CVE) | with the fix, or 90 days after the report |

If we learn that a vulnerability is **actively exploited**, we notify the coordinating CSIRT and ENISA via
the CRA Single Reporting Platform: early warning within 24 hours, notification within 72 hours, final report
within 14 days after a fix is available (CRA Article 14). Where appropriate we inform affected users directly.

## Safe harbour

We will not take legal action against good-faith research that respects this policy, avoids privacy
violations and service disruption, and gives us reasonable time to fix the issue before disclosure.

## Supported versions

Security updates are provided free of charge for the support period declared for each release
(at least 5 years, CRA Article 13(8)), separately from feature updates where technically feasible.

| Version | Supported until |
|---|---|
| 2.x | 2031-12-31 |
| 1.x | end of life |
