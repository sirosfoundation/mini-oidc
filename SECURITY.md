# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly via [GitHub Security Advisories](https://github.com/sirosfoundation/mini-oidc/security/advisories/new).

Do **not** open public issues for security vulnerabilities.

## Scope

This project is a **test/development tool** — it is not designed for production
authentication. The security surface is intentionally minimal:

- No real user credentials (dropdown selection, no passwords)
- In-memory storage (no persistent state)
- Client secrets in config are test-only values

## Supported Versions

Only the latest version on `main` is supported.
