# syntax=docker/dockerfile:1

# ── Build stage ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/identity ./cmd/identity

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && \
    adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /out/identity /app/identity

USER app
EXPOSE 50051

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD wget -qO- http://localhost:50051/_apicorex/health || exit 1

ENTRYPOINT ["/app/identity"]
