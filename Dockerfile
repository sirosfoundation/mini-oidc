FROM golang:1.26-alpine AS builder
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /op ./cmd/op
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /rp ./cmd/rp
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /healthcheck ./cmd/healthcheck

FROM gcr.io/distroless/static-debian12
COPY --from=builder /op /usr/local/bin/op
COPY --from=builder /rp /usr/local/bin/rp
COPY --from=builder /healthcheck /usr/local/bin/healthcheck
COPY users.yaml /etc/mini-oidc/users.yaml
COPY configs/ /etc/mini-oidc/configs/
USER 65532:65532
EXPOSE 9005 9006
ENTRYPOINT []
