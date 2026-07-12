# mini-oidc

[![CI](https://github.com/sirosfoundation/mini-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/mini-oidc/actions/workflows/ci.yml)
[![Security](https://github.com/sirosfoundation/mini-oidc/actions/workflows/security.yml/badge.svg)](https://github.com/sirosfoundation/mini-oidc/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/mini-oidc/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/mini-oidc)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/mini-oidc)](https://goreportcard.com/report/github.com/sirosfoundation/mini-oidc)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

A minimal OpenID Connect Provider (OP) and Relying Party (RP) for integration testing.
Designed as the authentication backend behind `vc-apigw`/`vc-issuer` and `vc-verifier`
in the SIROS ecosystem — **not** a replacement for those services.

Ships as a single container image (`ghcr.io/sirosfoundation/mini-oidc`) with both
binaries; select which to run via the command.

## Features

### OP (OpenID Provider, port 9005)

- OIDC Discovery (`/.well-known/openid-configuration`)
- Authorization Code flow with PKCE (S256, plain)
- Pushed Authorization Requests (`/par`, RFC 9126)
- Token endpoint with `client_secret_basic`, `client_secret_post`, and `none` auth
- Scope-based claim filtering (`profile` → name/birthdate, `email` → email)
- Configurable scopes including OID4VCI credential scopes (`pid`, `pid_1_5`, `pid_1_8`)
- Dynamic client registration (`/register`, RFC 7591)
- JWKS endpoint (ES256 keys, generated at startup)
- UserInfo endpoint (Bearer token validated)
- Pre-configured `apigw-oidc-client` for vc-apigw integration
- User authentication via dropdown selection from `users.yaml` (no passwords)

### RP (Relying Party, port 9006)

- Performs a full OIDC authorization code flow with PKCE against the OP
- Displays decoded ID token claims with validity status
- Shows UserInfo response
- Useful for verifying the OP works correctly end-to-end

## Quick Start

```bash
# Run locally (development config)
go run ./cmd/op &   # OP on :9005
go run ./cmd/rp &   # RP on :9006

# Or with Docker Compose (uses published image)
docker compose up
```

Visit http://localhost:9006 and click "Login with OIDC".

## Configuration

Configuration is loaded from a YAML file (`CONFIG_FILE` env var, defaults to `configs/config.yaml`).
Environment variables are expanded in string values using `${VAR}` or `${VAR:-default}` syntax.

### Config File Structure

```yaml
server:
  op_port: 9005
  rp_port: 9006
  issuer: "${ISSUER}"
  scopes_supported: [openid, profile, email, pid, pid_1_5, pid_1_8]

clients:
  - client_id: "mini-oidc-rp"
    client_name: "Built-in RP"
    redirect_uris: ["${RP_BASE_URL}/callback"]
    token_endpoint_auth_method: "none"

  - client_id: "${APIGW_CLIENT_ID:-apigw-oidc-client}"
    client_name: "VC API Gateway"
    client_secret: "${APIGW_CLIENT_SECRET:-test-secret}"
    redirect_uris: ["${APIGW_REDIRECT_URI}"]
    token_endpoint_auth_method: "client_secret_basic"

rp:
  base_url: "${RP_BASE_URL}"
  client_id: "mini-oidc-rp"
  op_issuer: "${ISSUER}"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_FILE` | `configs/config.yaml` | Path to configuration file |
| `USERS_FILE` | `users.yaml` | Path to users YAML file |
| `ISSUER` | `http://localhost:9005` | OP issuer URL |
| `RP_BASE_URL` | `http://localhost:9006` | RP externally reachable URL |
| `CLIENT_ID` | `mini-oidc-rp` | Client ID for the built-in RP |
| `APIGW_CLIENT_ID` | `apigw-oidc-client` | Client ID for vc-apigw |
| `APIGW_CLIENT_SECRET` | `test-secret` | Client secret for vc-apigw |
| `APIGW_REDIRECT_URI` | `http://localhost:8091/oidcrp/callback` | vc-apigw callback URI |

## Users

Edit `users.yaml` to define test users. Claims are filtered by requested OIDC scopes:

```yaml
users:
  - sub: "alice-001"
    given_name: "Alice"        # returned with scope: profile
    family_name: "Wonderland"  # returned with scope: profile
    name: "Alice Wonderland"   # returned with scope: profile
    email: "alice@example.com" # returned with scope: email
    birthdate: "1990-01-15"    # returned with scope: profile
    place_of_birth: "Stockholm"
    nationalities: ["SE"]
    issuing_authority: "Swedish Tax Agency"
    issuing_country: "SE"
```

## OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery document |
| `/authorize` | GET | Authorization (user selection UI) |
| `/par` | POST | Pushed Authorization Request (RFC 9126) |
| `/token` | POST | Token exchange (code → tokens) |
| `/userinfo` | GET | User claims (Bearer token) |
| `/jwks` | GET | Public key set |
| `/register` | POST | Dynamic client registration |
| `/health` | GET | Health check |

## Docker

```bash
# Run OP
docker run -p 9005:9005 \
  -e ISSUER=http://localhost:9005 \
  ghcr.io/sirosfoundation/mini-oidc:main \
  /usr/local/bin/op

# Run RP
docker run -p 9006:9006 \
  -e ISSUER=http://localhost:9005 \
  -e RP_BASE_URL=http://localhost:9006 \
  ghcr.io/sirosfoundation/mini-oidc:main \
  /usr/local/bin/rp
```

## sirosid-dev Integration

The OP acts as the authentication backend for `vc-apigw` (OID4VCI credential issuance)
and `vc-verifier` (operator authentication). It does **not** replace those services.

```bash
# From sirosid-dev directory:
docker compose -f docker-compose.yml \
  -f docker-compose.vc-services.yml up
```

The compose file uses the published image — no local build needed. Configure via environment:

```bash
MINI_OIDC_ISSUER=http://mini-oidc-op:9005
APIGW_CLIENT_ID=apigw-oidc-client
APIGW_CLIENT_SECRET=test-secret
APIGW_REDIRECT_URI=http://vc-apigw:8091/oidcrp/callback
```

## Development

```bash
make build        # Build both binaries to bin/
make test         # Run tests with race detector
make lint         # golangci-lint
make docker-build # Build local Docker image
make run-op       # Run OP locally
make run-rp       # Run RP locally
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).

