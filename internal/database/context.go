package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/go-jet/jet/v2/qrm"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
)

type txKey struct{}

func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

func Tx(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(*sql.Tx)
	return tx, ok
}

func Queryable(ctx context.Context, db *sql.DB) qrm.Queryable {
	if tx, ok := Tx(ctx); ok {
		return tx
	}
	return db
}

func Executable(ctx context.Context, db *sql.DB) qrm.Executable {
	if tx, ok := Tx(ctx); ok {
		return tx
	}
	return db
}

func SetLocal(ctx context.Context, key, value string) error {
	tx, ok := Tx(ctx)
	if !ok {
		return sql.ErrTxDone
	}
	_, err := postgres.SELECT(postgres.Func("set_config", postgres.String(key), postgres.String(value), postgres.Bool(true))).
		ExecContext(ctx, tx)
	return err
}

// QueryError preserves the database/sql contract for repository callers while
// allowing Jet's mapper to populate single-row destinations directly.
func QueryError(err error) error {
	if errors.Is(err, qrm.ErrNoRows) {
		return sql.ErrNoRows
	}
	return err
}

// DuplicateKey reports whether a write lost a race against a unique constraint.
// Every repository that inserts a named row needs this to tell "somebody already
// took that name" apart from a real failure, so the SQLSTATE is decoded once
// here rather than in each of them.
func DuplicateKey(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// UUID turns an application UUID string into a typed Jet expression. Jet's
// postgres.String is deliberately text-typed; using it directly in a predicate
// against a UUID column produces PostgreSQL's "uuid = text" error.
func UUID(id string) postgres.StringExpression {
	return postgres.CAST(postgres.String(id)).AS_UUID()
}

// OrganizationIDs is the shared Jet query used by cross-tenant workers after
// they have explicitly entered the trusted auth flow.
func OrganizationIDs(ctx context.Context, db qrm.Queryable) ([]string, error) {
	var rows []struct{ ID string }
	err := postgres.SELECT(postgres.CAST(table.Organization.ID).AS_TEXT().AS("ID")).
		FROM(table.Organization).QueryContext(ctx, db, &rows)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
	}
	return ids, nil
}
