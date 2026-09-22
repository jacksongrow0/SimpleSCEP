package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/go-jet/jet/v2/postgres"
)

// AssertRLSEnforced checks at startup that the tenancy model is actually in
// force, rather than merely written down in the migrations.
//
// Two ways it can be silently absent:
//
//   - The connecting role is a superuser or holds BYPASSRLS. Row security is
//     skipped entirely for those roles. FORCE ROW LEVEL SECURITY closes the
//     table-owner exemption but has no effect on this one, so every policy in
//     the schema becomes decoration and every query sees every customer's rows.
//
//   - A table carrying organization_id or user_id was added without the two
//     ALTER TABLE lines that enable and force row security. This is the likelier
//     mistake by far: it is one forgotten line in one migration, and nothing else
//     in the system would notice.
//
// user_id is checked alongside organization_id because the second factor tables
// are scoped to a person rather than to a tenant, and are the most sensitive
// rows in the schema — a sealed TOTP secret and a set of recovery codes. They
// carry no organization_id on purpose, so the original check would have waved
// them through, and the leak they represent is worse than a cross-tenant one:
// it is one colleague reading another's second factor.
//
// Called after Migrations and OpenDB, never before — the checks read tables the
// migrations create.
func AssertRLSEnforced(ctx context.Context, db *sql.DB) error {
	roleName := postgres.StringColumn("rolname")
	roleSuper := postgres.BoolColumn("rolsuper")
	roleBypassRLS := postgres.BoolColumn("rolbypassrls")
	roles := postgres.NewTable("pg_catalog", "pg_roles", "", roleName, roleSuper, roleBypassRLS)
	var role struct {
		Superuser bool
		BypassRLS bool
	}
	err := postgres.SELECT(roleSuper.AS("Superuser"), roleBypassRLS.AS("BypassRLS")).FROM(roles).
		WHERE(roleName.EQ(postgres.RawString("current_user"))).QueryContext(ctx, db, &role)
	err = QueryError(err)
	if err != nil {
		return fmt.Errorf("checking database role privileges: %w", err)
	}
	if role.Superuser || role.BypassRLS {
		return fmt.Errorf("database role %s bypasses row level security (superuser=%t bypassrls=%t); "+
			"every tenancy policy in the schema is inert. Connect as a role with neither privilege",
			currentUser(ctx, db), role.Superuser, role.BypassRLS)
	}

	// DISTINCT because a table carrying both columns would otherwise be named
	// twice, which reads as two problems.
	relname := postgres.StringColumn("relname")
	reloid := postgres.IntegerColumn("oid")
	relnamespace := postgres.IntegerColumn("relnamespace")
	relkind := postgres.StringColumn("relkind")
	relrowsecurity := postgres.BoolColumn("relrowsecurity")
	relforcerowsecurity := postgres.BoolColumn("relforcerowsecurity")
	classes := postgres.NewTable("pg_catalog", "pg_class", "c", relname, reloid, relnamespace, relkind,
		relrowsecurity, relforcerowsecurity)
	nspoid := postgres.IntegerColumn("oid")
	nspname := postgres.StringColumn("nspname")
	namespaces := postgres.NewTable("pg_catalog", "pg_namespace", "n", nspoid, nspname)
	attrelid := postgres.IntegerColumn("attrelid")
	attname := postgres.StringColumn("attname")
	attnum := postgres.IntegerColumn("attnum")
	attisdropped := postgres.BoolColumn("attisdropped")
	attributes := postgres.NewTable("pg_catalog", "pg_attribute", "a", attrelid, attname, attnum, attisdropped)
	var rows []struct{ Name string }
	err = postgres.SELECT(relname.AS("Name")).DISTINCT().
		FROM(classes.INNER_JOIN(namespaces, nspoid.EQ(relnamespace)).INNER_JOIN(attributes, attrelid.EQ(reloid))).
		WHERE(nspname.EQ(postgres.String("public")).AND(relkind.EQ(postgres.String("r"))).
			AND(attname.IN(postgres.String("organization_id"), postgres.String("user_id"))).
			AND(attnum.GT(postgres.Int(0))).AND(attisdropped.IS_FALSE()).
			AND(postgres.NOT(relrowsecurity.AND(relforcerowsecurity)))).
		ORDER_BY(relname.ASC()).QueryContext(ctx, db, &rows)
	if err != nil {
		return fmt.Errorf("checking row level security: %w", err)
	}
	unprotected := make([]string, len(rows))
	for i := range rows {
		unprotected[i] = rows[i].Name
	}
	if len(unprotected) > 0 {
		return fmt.Errorf("tables carry organization_id or user_id without ENABLE and FORCE ROW LEVEL SECURITY: %s. "+
			"Any query against these returns every customer's, or every colleague's, rows",
			strings.Join(unprotected, ", "))
	}
	return nil
}

// currentUser is only for the error message above, so a failure to read it must
// not replace the diagnosis with a different one.
func currentUser(ctx context.Context, db *sql.DB) string {
	var result struct{ Name string }
	if err := postgres.SELECT(postgres.RawString("current_user").AS("Name")).QueryContext(ctx, db, &result); err != nil {
		return "(unknown)"
	}
	return result.Name
}
