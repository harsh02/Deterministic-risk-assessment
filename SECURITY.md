# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in the Deterministic Risk Assessment
Engine, please report it responsibly:

- **Preferred:** Open a [private security advisory](https://github.com/harsh02/Deterministic-risk-assessment/security/advisories/new)
  via GitHub (this keeps the report confidential until a fix is ready).
- **Email:** harsh.shrivastava08@gmail.com with the subject line
  `SECURITY: <short description>`.

Please include:
- A description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept if possible).
- Any suggested remediation.

**Please do not open a public GitHub issue for security vulnerabilities.**

## Response Targets

| Stage                 | Target            |
| --------------------- | ----------------- |
| Acknowledgement       | within 3 days     |
| Initial assessment    | within 7 days     |
| Fix or mitigation     | depends on severity |

## Disclosure

We follow a coordinated disclosure model. Once a fix is available, we will
publish a security advisory crediting the reporter (unless anonymity is
requested).

## Scope

This policy covers the application source code in this repository and its
build/release pipeline (CI/CD workflows, container images, and deployment
manifests). Vulnerabilities in third-party dependencies should be reported
upstream, though we welcome notice so we can pin or patch affected versions.
