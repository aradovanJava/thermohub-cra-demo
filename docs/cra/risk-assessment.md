# Cybersecurity risk assessment (excerpt) – ThermoHub

*Article 13(2)–(3) CRA. The assessment decides which Annex I Part I (2) requirements apply and how.
This excerpt shows the format; a real assessment covers every asset, interface and use case.*

## Context

- **Product:** ThermoHub cloud back end – remote data processing solution of the ThermoHub thermostat.
  Without it the thermostat cannot be paired, controlled remotely or updated.
- **Intended use:** consumer homes in the EU; remote control via mobile app and CLI.
- **Reasonably foreseeable misuse:** account sharing, automated scripts against the API, insecure home networks.
- **Support period:** until 2031-12-31 (at least 5 years from placing on the market, Art. 13(8)).

## Threats and controls

| ID | Threat (STRIDE) | Asset | Likelihood × impact | Control | Annex I | Evidence |
|---|---|---|---|---|---|---|
| THREAT-01 | Customer reads/controls another customer's device (E) | device control | high × high | owner-scoped queries | (2)(d) | `a01_*` |
| THREAT-02 | Internal endpoints reveal secrets (I) | configuration | medium × high | actuator lock-down | (2)(b),(j) | `a02_*` |
| THREAT-03 | Vulnerable dependency exploited (T, E) | server | high × critical | SBOM + SCA gate, Dependabot | (2)(a); II (1),(2) | SBOM, Trivy |
| THREAT-04 | Password database leak cracked offline (I) | credentials | medium × high | bcrypt | (2)(e) | `a04_*` |
| THREAT-05 | Injection into SQL (T, I) | all data | medium × critical | bind parameters | (2)(a) | `a05_*`, SAST |
| THREAT-06 | Pairing code guessed, device hijacked (S) | device ownership | high × high | 40-bit code, 5 tries / 15 min | (2)(d),(h) | `a06_pairing*` |
| THREAT-07 | Heating driven to unsafe temperature (T) | **physical safety** | medium × high | `Setpoint` 5–30 °C invariant | Part I (1) | `a06_setpoint*` |
| THREAT-08 | Default or guessed admin password (S) | admin | high × critical | no defaults, policy, lockout | (2)(b),(d) | `a07_*` |
| THREAT-09 | Malicious firmware rolled out to fleet (T) | fleet | low × critical | Ed25519 signature, anti-rollback | (2)(f); II (7) | `a08_*` |
| THREAT-10 | Attack goes unnoticed, no 24 h report (R) | detection | medium × high | audit events, metrics, ECS logs | (2)(l); Art. 14 | `a09_*` |
| THREAT-11 | Error path grants access (E) | device control | medium × high | parse once, default deny | (2)(k) | `a10_*` |

## Accepted risks

| ID | Decision | Justification | Owner | Review |
|---|---|---|---|---|
| RISK-001 | CSRF protection disabled | Stateless API for devices and CLI, no cookies, no browser sessions | platform team | 2027-06-30 |
| RISK-002 | CRLF log-injection findings suppressed in the CRA module | All logs are ECS JSON, which escapes control characters; request values are allowlist-validated | platform team | 2027-06-30 |
| RISK-003 | Requirement (2)(m) data deletion not yet implemented | Planned for 2.6 (Q2 2027), before full application on 2027-12-11 | product owner | 2027-03-31 |
