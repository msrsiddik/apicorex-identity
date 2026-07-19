# syntax=docker/dockerfile:1

# ── Admin UI stage ─────────────────────────────────────────────────────────
# Statically export the Next.js platform-admin app to admin/out, which the Go
# build below embeds into the binary (see cmd/identity/admin.go).
FROM node:22-alpine AS admin
WORKDIR /admin

COPY cmd/identity/admin/package.json cmd/identity/admin/package-lock.json ./
RUN npm ci

COPY cmd/identity/admin/ ./
RUN npm run build

# ── Build stage ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Bring in the exported admin UI so //go:embed all:admin/out has content.
COPY --from=admin /admin/out ./cmd/identity/admin/out
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/identity ./cmd/identity

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM alpine:3.20
# postgresql-client provides pg_dump/psql for the DB backup & restore feature.
RUN apk add --no-cache ca-certificates wget postgresql-client && \
    adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /out/identity /app/identity

USER app
EXPOSE 50051

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD wget -qO- http://localhost:50051/_apicorex/health || exit 1

ENTRYPOINT ["/app/identity"]
