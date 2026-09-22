# Security policy

## Supported versions

Until SimpleSCEP reaches 1.0, security fixes are provided only for the latest published release. Upgrade to the latest patch release before reporting an issue that may already be resolved.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/jacksongrow0/SimpleSCEP/security/advisories/new). Do not open a public issue for suspected vulnerabilities and do not include production private keys, credentials, enrollment secrets, certificates containing personal information, or database exports.

Include the affected version, impact, prerequisites, and minimal reproduction details. Reports are handled on a best-effort basis; this community project does not provide a response-time or remediation SLA. Please allow time to investigate and coordinate a fix before public disclosure.

If private vulnerability reporting is unavailable, open a public issue containing no sensitive or exploit details and ask the maintainer to establish a private channel.

## Scope

Reports about SimpleSCEP code and its default container build are in scope. Vulnerabilities in PostgreSQL, Google Cloud KMS, Azure Key Vault, Resend, browsers, operating systems, or deployment infrastructure should also be reported to the responsible upstream project or provider.
