// Package dbbackup shells out to the PostgreSQL client tools (pg_dump / psql) to
// produce and restore SQL dumps. Backups are streamed to the caller and never
// written to the server's disk; restores read an uploaded dump from a reader.
//
// The tools must be on PATH (postgresql-client in the runtime image). Every
// operation authenticates with the same DATABASE_URL the plugin already owns —
// callers never supply connection details.
package dbbackup

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
)

// schemaName is validated before being passed to pg_dump so a crafted tenant
// slug can't inject extra shell/pg_dump arguments. Tenant schemas are always
// "tenant_<slug>" with a lowercase-alphanumeric slug.
var schemaName = regexp.MustCompile(`^tenant_[a-z0-9]+$`)

// Service runs pg_dump / psql against a fixed DSN.
type Service struct {
	dsn string
}

func New(dsn string) *Service { return &Service{dsn: dsn} }

// DumpSchema streams a plain-SQL dump of one tenant schema to w. The dump uses
// --clean --if-exists so restoring it drops and recreates that schema's objects
// without touching any other schema.
func (s *Service) DumpSchema(ctx context.Context, schema string, w io.Writer) error {
	if !schemaName.MatchString(schema) {
		return fmt.Errorf("invalid schema name %q", schema)
	}
	args := []string{
		"--dbname=" + s.dsn,
		"--schema=" + schema,
		"--clean", "--if-exists",
		"--no-owner", "--no-privileges",
		"--format=plain",
	}
	return s.run(ctx, "pg_dump", args, nil, w)
}

// DumpAll streams a plain-SQL dump of the entire database to w.
func (s *Service) DumpAll(ctx context.Context, w io.Writer) error {
	args := []string{
		"--dbname=" + s.dsn,
		"--clean", "--if-exists",
		"--no-owner", "--no-privileges",
		"--format=plain",
	}
	return s.run(ctx, "pg_dump", args, nil, w)
}

// Restore pipes a plain-SQL dump from r into psql. The dump is expected to be
// one produced by DumpSchema/DumpAll (it carries its own DROP/CREATE). --single-
// transaction makes the restore atomic: any error rolls the whole thing back so
// a half-applied dump can't leave the database in a mixed state. ON_ERROR_STOP
// turns the first SQL error into a non-zero exit.
func (s *Service) Restore(ctx context.Context, r io.Reader) error {
	args := []string{
		"--dbname=" + s.dsn,
		"--single-transaction",
		"--set=ON_ERROR_STOP=1",
		"--quiet",
	}
	return s.run(ctx, "psql", args, r, io.Discard)
}

// run executes tool with args, feeding stdin from in (may be nil) and stdout to
// out. Stderr is captured and surfaced in the error so a failed dump/restore
// explains itself.
func (s *Service) run(ctx context.Context, tool string, args []string, in io.Reader, out io.Writer) error {
	cmd := exec.CommandContext(ctx, tool, args...)
	if in != nil {
		cmd.Stdin = in
	}
	cmd.Stdout = out
	var stderr capWriter
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := stderr.String(); msg != "" {
			return fmt.Errorf("%s: %s", tool, msg)
		}
		return fmt.Errorf("%s: %w", tool, err)
	}
	return nil
}

// capWriter captures up to a few KB of stderr for error messages without
// unbounded buffering.
type capWriter struct {
	buf []byte
}

func (w *capWriter) Write(p []byte) (int, error) {
	const max = 4 << 10
	if len(w.buf) < max {
		room := max - len(w.buf)
		if room > len(p) {
			room = len(p)
		}
		w.buf = append(w.buf, p[:room]...)
	}
	return len(p), nil
}

func (w *capWriter) String() string { return string(w.buf) }
