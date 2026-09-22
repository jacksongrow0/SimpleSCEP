# PostgreSQL setup

SimpleSCEP must not connect as `postgres`, another superuser, or a role with
`BYPASSRLS`. PostgreSQL exempts those roles from row-level security, so the
application refuses to start with them.

## Fresh database

Connect with your PostgreSQL administrator account, not the account SimpleSCEP
will use:

```sh
psql -U postgres -d postgres
```

Create a dedicated login and make it the owner of a dedicated database. Replace
the example password with a generated secret:

```sql
CREATE ROLE simplescep WITH
    LOGIN
    PASSWORD 'replace-with-a-generated-password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    NOREPLICATION
    NOBYPASSRLS;

CREATE DATABASE simplescep OWNER simplescep;
```

Database ownership is intentional: SimpleSCEP applies its own migrations at
startup. `FORCE ROW LEVEL SECURITY` remains effective for a table owner, while
it would still be bypassed by a superuser or `BYPASSRLS` role.

Confirm the two attributes that startup enforces:

```sql
SELECT rolname, rolsuper, rolbypassrls
FROM pg_roles
WHERE rolname = 'simplescep';
```

Both `rolsuper` and `rolbypassrls` must be `false`. Configure the application:

```dotenv
POSTGRES_DB=simplescep
POSTGRES_USER=simplescep
POSTGRES_PASSWORD=replace-with-a-generated-password
POSTGRES_HOST=database.example.com:5432
POSTGRES_SSL=verify-full
```

For `verify-full`, also provide the database CA through `PGSSLROOTCERT`.

## Database already initialized by another role

If SimpleSCEP already applied its schema as a role such as `dev`, create the
dedicated role above and transfer the SimpleSCEP database and its objects while
connected as an administrator:

```sql
ALTER DATABASE simplescep OWNER TO simplescep;
\connect simplescep
REASSIGN OWNED BY dev TO simplescep;
ALTER SCHEMA public OWNER TO simplescep;
```

Replace `dev` with the role that currently owns the schema. Only use
`REASSIGN OWNED` in a database dedicated to SimpleSCEP; it transfers every
object owned by that role in the current database. Then update `POSTGRES_USER`
and `POSTGRES_PASSWORD` and restart SimpleSCEP.

Do not grant `simplescep` membership in an administrative role or later alter
it with `SUPERUSER` or `BYPASSRLS`.
