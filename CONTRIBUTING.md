# Contributing

Thank you for improving SimpleSCEP. Use an issue to discuss significant behavior or protocol changes before investing in an implementation.

## Development

Install Go 1.25.5, Node.js 22.23.2, npm, and PostgreSQL 17. Then run:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run assets:build
go tool templ generate
go test ./...
docker build -t simplescep:test .
```

Tests marked `livedb` require a dedicated disposable PostgreSQL database and the variables described in `.env.example`.

Keep changes focused, add tests for behavior, and update public documentation and configuration examples. Never commit private keys, enrollment secrets, credentials, production certificates, database exports, or personal data.

## Pull requests and licensing

Explain the problem, the chosen behavior, and how it was verified. All contributions intentionally submitted to this repository are licensed under Apache License 2.0 under the standard inbound-equals-outbound model. The project does not require a CLA or Developer Certificate of Origin sign-off.

Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report security issues through [SECURITY.md](SECURITY.md), not a public issue.
