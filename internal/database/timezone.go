package database

import (
	"context"
	"database/sql"
	"fmt"
)

// AssertUTC checks that connections really do run in UTC.
//
// postgresURL sets the session parameter, so reaching a failure here means
// something between the two dropped it — a pooler that rewrites connection
// options, or a driver change that stopped forwarding them. That is worth a
// refusal rather than a warning, because what it silently breaks is expiry: the
// queries behind session, email_invitation and login_challenge compare a
// `timestamp without time zone` against LOCALTIMESTAMP, so an offset here is an
// offset on how long a session and a half-finished login live.
//
// Called after OpenDB, alongside AssertRLSEnforced.
func AssertUTC(ctx context.Context, db *sql.DB) error {
	var zone string
	if err := db.QueryRowContext(ctx, "SHOW TimeZone").Scan(&zone); err != nil {
		return fmt.Errorf("reading the database time zone: %w", err)
	}
	if zone != "UTC" {
		return fmt.Errorf("database connections run in time zone %q, not UTC: every expiry "+
			"comparison in this schema is against a bare timestamp, so an offset here changes "+
			"how long sessions and login challenges live. Something dropped the "+
			"\"options=-c timezone=UTC\" this application sets on its own connection string", zone)
	}
	return nil
}
