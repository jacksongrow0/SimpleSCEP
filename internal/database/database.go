package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/joho/godotenv"
)

// Pool limits. Every authenticated request holds a transaction for its whole
// duration — that is what keeps the RLS settings scoped to it — so connections
// are held longer here than in a service that borrows one per query. An
// unbounded pool answers that by opening connections until Postgres refuses
// them, which fails worse and later than queueing does.
//
// Override with POSTGRES_MAX_CONNS where a deployment has measured something
// better; the default suits a single container against a small managed instance.
const (
	defaultMaxOpenConns = 25
	connMaxLifetime     = 30 * time.Minute
	connMaxIdleTime     = 5 * time.Minute
)

func OpenDB() (*sql.DB, error) {
	db, err := sql.Open("pgx", postgresURL())
	if err != nil {
		return nil, err
	}
	maxConns := defaultMaxOpenConns
	if v := os.Getenv("POSTGRES_MAX_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			db.Close()
			return nil, fmt.Errorf("POSTGRES_MAX_CONNS must be a positive integer, got %q", v)
		}
		maxConns = n
	}
	db.SetMaxOpenConns(maxConns)
	// Idle matches open: a pool that closes idle connections it is allowed to
	// keep just pays to reopen them under the next burst.
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func Migrations() {
	db, err := OpenDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		log.Fatal(err)
	}
}

func migrate(db *sql.DB) error {
	ctx := context.Background()
	if _, err := postgres.RawStatement("CREATE TABLE IF NOT EXISTS migrations (id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE)").
		ExecContext(ctx, db); err != nil {
		return err
	}
	_, _ = postgres.RawStatement("ALTER TABLE migrations RENAME COLUMN version TO name").ExecContext(ctx, db)
	applied := map[string]bool{}
	var migrations []struct{ Name string }
	err := postgres.SELECT(table.Migrations.Name.AS("Name")).FROM(table.Migrations).QueryContext(ctx, db, &migrations)
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		applied[migration.Name] = true
	}

	files, err := filepath.Glob("internal/database/migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	toRun := []string{}
	for _, file := range files {
		if name := filepath.Base(file); !applied[name] {
			toRun = append(toRun, file)
		}
	}
	if len(toRun) == 0 {
		return nil
	}

	if _, err := postgres.RawStatement("CREATE TABLE _lock (id SERIAL PRIMARY KEY)").ExecContext(ctx, db); err != nil {
		return err
	}
	defer func() { _, _ = postgres.RawStatement("DROP TABLE IF EXISTS _lock").ExecContext(ctx, db) }()

	for _, file := range toRun {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		stmt, err := os.ReadFile(file)
		if err != nil {
			tx.Rollback()
			return err
		}
		log.Println("executing migration", filepath.Base(file))
		if _, err := postgres.RawStatement(string(stmt)).ExecContext(ctx, tx); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := table.Migrations.INSERT(table.Migrations.Name).VALUES(filepath.Base(file)).ExecContext(ctx, tx); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func GenerateJet() {
	cmd := exec.Command("go", "tool", "jet", "-source=postgres", "-dsn="+postgresURL(), "-schema=public", "-path=.jet")
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	log.Fatal(cmd.Run())
}

func postgresURL() string {
	_ = godotenv.Load()
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(requiredEnv("POSTGRES_USER"), requiredEnv("POSTGRES_PASSWORD")),
		Host:   requiredEnv("POSTGRES_HOST"),
		Path:   requiredEnv("POSTGRES_DB"),
	}
	q := u.Query()
	q.Set("sslmode", requiredEnv("POSTGRES_SSL"))
	// Every connection runs in UTC, whatever the server was initialised with.
	//
	// Almost every timestamp column in this schema is `timestamp without time
	// zone`, and the expiry checks over them mix two clocks: Go writes
	// time.Now() into session.expires_at and its siblings, while the queries that
	// read them compare against LOCALTIMESTAMP, which is the *database's* wall
	// clock. Those are the same clock only by coincidence. A container running
	// UTC against a server initialised to America/New_York keeps every session,
	// invitation and half-finished login challenge valid for four hours past its
	// expiry; the other direction expires them on issue. Neither says anything in
	// a log.
	//
	// Pinning the session parameter here makes the coincidence a guarantee, and
	// AssertUTC refuses to start if it somehow did not take.
	q.Set("options", "-c timezone=UTC")
	u.RawQuery = q.Encode()
	return u.String()
}

func requiredEnv(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	log.Fatalf("%s is required", key)
	return ""
}

// insecureSSLModes are the libpq sslmode values that leave the link to Postgres
// in plaintext, or let it silently fall back to plaintext when the server
// declines TLS. "prefer" is in the list precisely because it looks safe: it
// tries TLS first and then connects anyway without it, so a misconfigured server
// downgrades every connection and nothing anywhere reports it.
var insecureSSLModes = map[string]bool{"disable": true, "allow": true, "prefer": true}

// AssertSSLMode refuses to start a deployment whose database link is not
// encrypted.
//
// This connection carries the tenancy boundary. Row level security is enforced
// by Postgres rather than by this process, so every isolation decision in the
// schema travels over this wire along with the password that opens it — and
// unlike the settings around it, sslmode had no floor at all: whatever
// POSTGRES_SSL said was handed to the driver.
//
// development is passed in rather than derived here. Whether a host names a
// developer's machine is a decision cmd/main.go already makes for the mail
// sender and the key provider, and it should be made in exactly one place.
//
// Note that "require" encrypts but does not authenticate the server: it accepts
// any certificate, so it stops passive capture and not an active attacker in
// front of the database. "verify-full" is the value a production deployment
// wants; this refuses only the modes that are not encrypted at all, because
// demanding verify-full needs a root certificate on disk and that is a
// deployment decision rather than something to fail a container start over.
func AssertSSLMode(development bool) error {
	_ = godotenv.Load()
	mode := strings.ToLower(strings.TrimSpace(requiredEnv("POSTGRES_SSL")))
	if !insecureSSLModes[mode] || development {
		return nil
	}
	return fmt.Errorf("POSTGRES_SSL=%s leaves the database connection in plaintext, and that "+
		"connection carries both the tenancy boundary and the password that opens it. "+
		"Use verify-full, or require if no root certificate is available", mode)
}
