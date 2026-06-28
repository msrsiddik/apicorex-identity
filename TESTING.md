# Testing

Two kinds of tests:

- **Unit tests** — pure logic, no database. Run anywhere:
  ```bash
  go test ./...
  ```
  Integration tests skip automatically when no container engine is reachable.

- **Integration tests** — spin a real PostgreSQL container with
  [testcontainers-go](https://golang.testcontainers.org/). They cover the
  schema-per-tenant flows that can't be meaningfully mocked: the registration
  saga, login/refresh, and plugin migrations.

  Files: `internal/migrator/*_integration_test.go`,
  `internal/tenant/*_integration_test.go`, `internal/auth/*_integration_test.go`.

---

## Running integration tests with Podman

testcontainers-go talks to a Docker-compatible socket. Podman exposes one; you
just point testcontainers at it.

### macOS (Podman Desktop / `podman machine`)

```bash
# 1. Start the Podman VM (once)
podman machine init      # if you don't have a machine yet
podman machine start

# 2. Find the socket and export it for testcontainers
export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"

# 3. Podman doesn't run the Ryuk reaper container the same way — disable it
export TESTCONTAINERS_RYUK_DISABLED=true

# 4. Run
go test ./...
```

### Linux (rootless Podman)

```bash
# Start the user socket
systemctl --user start podman.socket

export DOCKER_HOST="unix://${XDG_RUNTIME_DIR}/podman/podman.sock"
export TESTCONTAINERS_RYUK_DISABLED=true

go test ./...
```

### Remote Podman over SSH (engine on another machine)

This is the verified setup when your Podman VM runs on another host reachable
via SSH (`podman system connection list` shows an `ssh://` URI).

testcontainers can't parse the `ssh://…/socket` URI directly, so forward the
remote Podman socket to a **local** unix socket, then point testcontainers at it.
Because the container's mapped port lives on the *remote* host (not localhost),
set `TEST_DB_HOST` to the remote IP so the test connects to the right place.

```bash
# 1. Forward the remote Podman socket to a local one (background SSH tunnel)
ssh -fN -L /tmp/podman-remote.sock:/run/user/1000/podman/podman.sock \
    siddik@100.119.254.20

# 2. Point testcontainers at the local socket
export DOCKER_HOST="unix:///tmp/podman-remote.sock"
export TESTCONTAINERS_RYUK_DISABLED=true

# 3. The mapped port is on the remote host — tell the test its real DB host
export TEST_DB_HOST=100.119.254.20

# 4. Run
go test ./...

# 5. Clean up the tunnel when done
#    (find it with: ps aux | grep 'podman-remote.sock')
```

Replace `siddik@100.119.254.20` and the socket path with your own
(`podman system connection list` shows the exact URI).

---

## Notes

- The Postgres image is `postgres:16-alpine`; the first run pulls it.
- Each integration test gets a fresh container and terminates it on cleanup.
- If `DOCKER_HOST` is unset and no engine is found, integration tests **skip**
  (they do not fail), so `go test ./...` stays green in CI without a container
  engine.
- `TESTCONTAINERS_RYUK_DISABLED=true` is needed because Podman handles the
  cleanup-reaper container differently; container cleanup still happens via
  `t.Cleanup`.
