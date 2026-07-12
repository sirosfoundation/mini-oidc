# mini-oidc

[![CI](https://github.com/sirosfoundation/mini-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/mini-oidc/actions/workflows/ci.yml)
[![Security](https://github.com/sirosfoundation/mini-oidc/actions/workflows/security.yml/badge.svg)](https://github.com/sirosfoundation/mini-oidc/actions/workflows/security.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=sirosfoundation_mini-oidc&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=sirosfoundation_mini-oidc)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/mini-oidc/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/mini-oidc)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

A minimal OpenID Connect Provider (OP) and Relying Party (RP) for testing OIDC flows.
Ships as a single container image with both binaries — select which to run via the command.

## Features

- **OP** — Full OIDC authorization code flow with PKCE, dynamic client registration, discovery, JWKS
- **RP** — Performs login against the OP and displays the ID token claims + userinfo response
- **User selection** — Authentication is a dropdown of users defined in `users.yaml` (no passwords)
- **Config templating** — `${VAR}` and `${VAR:-default}` patterns in config YAML, similar to go-invite-op
- **Published image** — `ghcr.io/sirosfoundation/mini-oidc` — no local build needed in sirosid-dev

## Quick Start

```bash
# Run locally (development config)
go run ./cmd/op &   # OP on :9005
go run ./cmd/rp &   # RP on :9006

# Or with Docker Compose (uses published image)
docker compose up
```

Then visit http://localhost:9006 and click "Login with OIDC".

## Configuration

Configuration is loaded from a YAML file (`CONFIG_FILE` env var, defaults to `configs/config.yaml`).
Environment variables are expanded in config values using `${VAR}` or `${VAR:-default}` syntax.

### Config File Structure

```yaml
server:
  op_port: 9005
  rp_port: 9006
  issuer: "${ISSUER}"

clients:
  - client_id: "${CLIENT_ID:-mini-oidc-rp}"
    client_name: "Relying Party"
    redirect_uris:
      - "${RP_BASE_URL}/callback"
    token_endpoint_auth_method: "none"

rp:
  base_url: "${RP_BASE_URL}"
  client_id: "${CLIENT_ID:-mini-oidc-rp}"
  op_issuer: "${ISSUER}"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_FILE` | `configs/config.yaml` | Path to configuration file |
| `USERS_FILE` | `users.yaml` | Path to users YAML file |
| `ISSUER` | `http://localhost:9005` | OP issuer URL |
| `RP_BASE_URL` | `http://localhost:9006` | RP externally reachable URL |
| `CLIENT_ID` | `mini-oidc-rp` | Client ID for the RP |

## Users

Edit `users.yaml` to define test users:

```yaml
users:
  - sub: "alice-001"
    given_name: "Alice"
    family_name: "Wonderland"
    name: "Alice Wonderland"
    email: "alice@example.com"
    birthdate: "1990-01-15"
    place_of_birth: "Stockholm"
    nationalities: ["SE"]
    issuing_authority: "Swedish Tax Agency"
    issuing_country: "SE"
```

## Docker

The image is published to `ghcr.io/sirosfoundation/mini-oidc` on every push to `main` and on version tags.

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

Add to sirosid-dev compose setup:

```bash
docker compose -f docker-compose.yml -f ../mini-oidc/docker-compose.sirosid.yml up
```

Or in the Makefile when `VC=yes`:

```makefile
COMPOSE_FILES += -f ../mini-oidc/docker-compose.sirosid.yml
```

Uses published image from ghcr.io — no local build step required. Override the client/callback config via environment:

```bash
MINI_OIDC_ISSUER=http://mini-oidc-op:9005 \
MINI_OIDC_RP_URL=http://mini-oidc-rp:9006 \
MINI_OIDC_CLIENT_ID=wallet-rp \
docker compose -f ... up
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

