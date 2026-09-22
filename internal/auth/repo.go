package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/model"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

type Repository struct {
	db *sql.DB
}

type Organization struct {
	ID, Name string
	// CreatedAt is read rather than rendered from a constant. The Organization
	// page used to print "Created July 8, 2026" for every customer, because there
	// was no column to read — see migration 1787795271544.
	CreatedAt time.Time
}

// User is an alias to an anonymous row shape so go-jet maps aliased SELECT
// columns by field name. A defined struct here silently receives zero values;
// unlike generated model.User, it has no table metadata for Jet to match.
type User = struct {
	ID    string
	Name  string
	Email string
	Role  string
}

var ErrEmailExists = errors.New("email already exists")

func NewRepository(db *sql.DB) Repository {
	return Repository{db: db}
}

// OrganizationExists reports whether this deployment has already been set up.
// This is a single-org, self-hosted application: at most one organization row
// ever exists (see the organization_singleton index), so this is the whole of
// the check the /setup bootstrap and the boot-time log message need.
//
// Callers outside a session must run this inside AuthFlow — organization
// carries FORCE ROW LEVEL SECURITY, and its policy admits a row only under
// app.auth_flow or a matching app.organization_id, neither of which exists
// before the first admin has signed up.
func (r Repository) OrganizationExists(ctx context.Context) (bool, error) {
	var rows []struct{ Exists bool }
	err := postgres.SELECT(postgres.EXISTS(postgres.SELECT(table.Organization.ID).FROM(table.Organization)).AS("Exists")).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, sql.ErrNoRows
	}
	return rows[0].Exists, nil
}

func (r Repository) CreateOrganization(ctx context.Context, name string) (uuid.UUID, error) {
	var organizations []model.Organization
	err := table.Organization.INSERT(table.Organization.Name).VALUES(name).
		RETURNING(table.Organization.ID).
		QueryContext(ctx, database.Queryable(ctx, r.db), &organizations)
	if err != nil {
		return uuid.Nil, err
	}
	if len(organizations) == 0 {
		return uuid.Nil, sql.ErrNoRows
	}
	return organizations[0].ID, nil
}

func (r Repository) CreateUser(ctx context.Context, orgID uuid.UUID, email, name, role string) (model.User, error) {
	var user model.User
	err := table.User.INSERT(table.User.OrganizationID, table.User.Email, table.User.Name, table.User.Role).
		VALUES(orgID, email, name, role).
		RETURNING(table.User.ID, table.User.OrganizationID, table.User.Email, table.User.Name).
		QueryContext(ctx, database.Queryable(ctx, r.db), &user)
	return user, database.QueryError(err)
}

func (r Repository) UserByEmail(ctx context.Context, email string) (model.User, error) {
	var users []model.User
	err := postgres.SELECT(table.User.AllColumns).
		FROM(table.User).
		WHERE(table.User.Email.EQ(postgres.String(email))).
		LIMIT(1).
		QueryContext(ctx, database.Queryable(ctx, r.db), &users)
	if err != nil {
		return model.User{}, err
	}
	if len(users) > 0 {
		return users[0], nil
	}
	return model.User{}, sql.ErrNoRows
}

// CreateMagicLink stores the hash of an emailed token, never the token. The
// parameter is named for what it must be so that a caller passing the token
// itself reads as wrong at the call site rather than only in the schema.
func (r Repository) CreateMagicLink(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	stmt := table.MagicLink.
		INSERT(table.MagicLink.UserID, table.MagicLink.TokenHash, table.MagicLink.ExpiresAt).
		VALUES(userID, tokenHash, expiresAt)
	_, err := stmt.ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// UserByMagicToken takes the token as it arrived in the URL and hashes it here,
// so that no caller has to remember to. The DELETE ... USING ... RETURNING shape
// is unchanged and is what makes redemption single-use: the row is consumed in
// the same statement that reads it, so two clicks on the same link cannot both
// produce a login.
func (r Repository) UserByMagicToken(ctx context.Context, token string) (model.User, error) {
	var users []model.User
	err := table.MagicLink.DELETE().
		USING(table.User).
		WHERE(table.User.ID.EQ(table.MagicLink.UserID).
			AND(table.MagicLink.TokenHash.EQ(postgres.String(tokenHash(token)))).
			// LOCALTIMESTAMP, not time.Now(): every other expiry check in this
			// file asks the database for the time, and a magic link asking Go
			// instead made this the one row whose lifetime depended on the two
			// clocks agreeing. They now do — the connection is pinned to UTC — but
			// one clock is still better than two.
			AND(table.MagicLink.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		RETURNING(table.User.AllColumns).
		QueryContext(ctx, database.Queryable(ctx, r.db), &users)
	if err != nil {
		return model.User{}, err
	}
	if len(users) > 0 {
		return users[0], nil
	}
	return model.User{}, sql.ErrNoRows
}

// MagicLinkExists reports whether a row still holds this token.
//
// It exists to tell an expired link from a spent one after the fact.
// UserByMagicToken deletes the row it matched, and matches only rows that have
// not expired, so a token that redeemed nothing but is still in the table is
// one that timed out — and a token in no row at all was either used or never
// issued. That is the whole classification, and it is only ever used to choose
// which sentence /login greets the person with.
//
// It reads no user and returns no user: whoever holds the token already holds
// the answer to "does this address have an account", so there is nothing here
// to leak, and there is nothing to gain by widening it later either.
func (r Repository) MagicLinkExists(ctx context.Context, token string) (bool, error) {
	var links []model.MagicLink
	err := postgres.SELECT(table.MagicLink.UserID).
		FROM(table.MagicLink).
		WHERE(table.MagicLink.TokenHash.EQ(postgres.String(tokenHash(token)))).
		LIMIT(1).
		QueryContext(ctx, database.Queryable(ctx, r.db), &links)
	if err != nil {
		return false, database.QueryError(err)
	}
	return len(links) > 0, nil
}

// CreateVerifiedSession mints the session cookie's row.
//
// It is named for the precondition rather than for what it does, because the
// name is the only thing standing between a future caller and a session that
// skipped the second factor. A session row means both factors are complete;
// there is exactly one caller, and it is the code path that has just verified
// one. Anything that only holds a magic link creates a login_challenge instead.
func (r Repository) CreateVerifiedSession(ctx context.Context, user model.User, expiresAt time.Time) (uuid.UUID, error) {
	var sessions []model.Session
	err := table.Session.
		INSERT(table.Session.UserID, table.Session.OrganizationID, table.Session.ExpiresAt).
		VALUES(user.ID, uuidValue(user.OrganizationID), expiresAt).
		RETURNING(table.Session.ID).
		QueryContext(ctx, database.Queryable(ctx, r.db), &sessions)
	if err != nil {
		return uuid.Nil, err
	}
	if len(sessions) == 0 {
		return uuid.Nil, sql.ErrNoRows
	}
	return sessions[0].ID, nil
}

func (r Repository) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := table.Session.DELETE().WHERE(table.Session.ID.EQ(postgres.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// SetExpiryAlerts stores the organization's certificate-expiry notification
// preference. The window is bounded by a CHECK constraint as well as by the
// handler, so a value that reaches here out of range is refused by the database
// rather than stored.
func (r Repository) SetExpiryAlerts(ctx context.Context, orgID uuid.UUID, enabled bool, days int) error {
	_, err := table.Organization.UPDATE(
		table.Organization.ExpiryAlertsEnabled, table.Organization.ExpiryAlertDays).
		SET(postgres.Bool(enabled), postgres.Int(int64(days))).
		WHERE(table.Organization.ID.EQ(postgres.UUID(orgID))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return database.QueryError(err)
}

// sessionIdentityRow and sessionAccountRow are the scan destinations for the two
// halves of SessionByID.
//
// Both are type *aliases* to anonymous structs rather than defined types, and
// that is load-bearing. go-jet resolves a named struct destination against the
// tables in the result set; Session names no table, so every column went
// unmapped and the query returned a zero value with a nil error. The symptom was
// not an empty session — it was the *next* query failing with `invalid input
// syntax for type uuid: ""`, which names neither the column nor the query that
// actually came back empty. An alias keeps the underlying type anonymous, which
// the mapper matches on field names alone.
//
// Keep this operation in the same transaction as its audit event.
type sessionIdentityRow = struct {
	ID          string
	UserID      string
	OrgID       string
	SteppedUpAt *time.Time
}

type sessionAccountRow = struct {
	Name                string
	Email               string
	Role                string
	OrganizationName    string
	ExpiryAlertsEnabled bool
	ExpiryAlertDays     int
}

func (r Repository) SessionByID(ctx context.Context, id uuid.UUID) (Session, error) {
	var session Session
	var identity []sessionIdentityRow
	err := postgres.SELECT(
		postgres.CAST(table.Session.ID).AS_TEXT().AS("ID"),
		postgres.CAST(table.Session.UserID).AS_TEXT().AS("UserID"),
		postgres.COALESCE(postgres.CAST(table.Session.OrganizationID).AS_TEXT(), postgres.String("")).AS("OrgID"),
		table.Session.SteppedUpAt.AS("SteppedUpAt"),
	).FROM(table.Session).
		WHERE(table.Session.ID.EQ(postgres.UUID(id)).AND(table.Session.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &identity)
	err = database.QueryError(err)
	if err != nil {
		return Session{}, err
	}
	if len(identity) == 0 {
		return Session{}, sql.ErrNoRows
	}
	session.ID, session.UserID = identity[0].ID, identity[0].UserID
	session.OrgID, session.SteppedUpAt = identity[0].OrgID, identity[0].SteppedUpAt
	if err = database.SetLocal(ctx, "app.user_id", session.UserID); err != nil {
		return Session{}, err
	}
	if err = database.SetLocal(ctx, "app.organization_id", session.OrgID); err != nil {
		return Session{}, err
	}
	var account []sessionAccountRow
	err = postgres.SELECT(
		table.User.Name.AS("Name"), table.User.Email.AS("Email"), table.User.Role.AS("Role"),
		table.Organization.Name.AS("OrganizationName"),
		// Carried on the session so the account dialog can render the stored
		// state, rather than a switch that always shows off until saved.
		table.Organization.ExpiryAlertsEnabled.AS("ExpiryAlertsEnabled"),
		table.Organization.ExpiryAlertDays.AS("ExpiryAlertDays"),
	).FROM(
		table.User.INNER_JOIN(table.Organization, table.Organization.ID.EQ(table.User.OrganizationID)),
	).WHERE(table.User.ID.EQ(database.UUID(session.UserID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &account)
	if err = database.QueryError(err); err != nil {
		return Session{}, err
	}
	if len(account) == 0 {
		return Session{}, sql.ErrNoRows
	}
	session.Name, session.Email, session.Role = account[0].Name, account[0].Email, account[0].Role
	session.OrganizationName = account[0].OrganizationName
	session.ExpiryAlertsEnabled, session.ExpiryAlertDays = account[0].ExpiryAlertsEnabled, account[0].ExpiryAlertDays
	return session, nil
}

// CreateInvitation stores the hash of the emailed token, like CreateMagicLink,
// and for the same reason. It matters more here: an invitation is valid for
// seven days rather than fifteen minutes, so a leaked table is a week's worth of
// working sign-ups into other people's organizations.
func (r Repository) CreateInvitation(ctx context.Context, orgID uuid.UUID, email, name, role, tokenHash string, expiresAt time.Time) error {
	_, err := table.EmailInvitation.
		INSERT(table.EmailInvitation.OrganizationID, table.EmailInvitation.Email, table.EmailInvitation.Name,
			table.EmailInvitation.Role, table.EmailInvitation.TokenHash, table.EmailInvitation.ExpiresAt).
		VALUES(orgID, email, nullableString(name), role, tokenHash, expiresAt).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// nullableString keeps an empty form field out of the column as NULL rather than
// as "". The accept path distinguishes the two: NULL means nobody supplied a name
// and the email's local part is the fallback, where "" would be taken as a name
// and render a member with none.
func nullableString(v string) postgres.StringExpression {
	if strings.TrimSpace(v) == "" {
		return postgres.StringExp(postgres.NULL)
	}
	return postgres.String(strings.TrimSpace(v))
}

// Invitation is one pending invitation, for the team page.
type Invitation = struct {
	ID        string
	Email     string
	Name      string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PendingInvitations lists the invitations nobody has accepted yet.
//
// They were written and never shown. /users listed only real user rows, so an
// invitation sent to a mistyped address was a live seven-day token with no way to
// see it and no way to revoke it — and the failure toast on the send path told
// administrators to "remove it and invite them again", an action that did not
// exist.
//
// Expired ones are included on purpose. An administrator wondering why somebody
// never appeared needs to see that the invitation lapsed; hiding it leaves them
// with no evidence either way.
func (r Repository) PendingInvitations(ctx context.Context, orgID uuid.UUID) ([]Invitation, error) {
	var rows []Invitation
	err := postgres.SELECT(
		postgres.CAST(table.EmailInvitation.ID).AS_TEXT().AS("ID"),
		table.EmailInvitation.Email.AS("Email"),
		postgres.COALESCE(table.EmailInvitation.Name, postgres.String("")).AS("Name"),
		table.EmailInvitation.Role.AS("Role"),
		table.EmailInvitation.CreatedAt.AS("CreatedAt"),
		table.EmailInvitation.ExpiresAt.AS("ExpiresAt"),
	).FROM(table.EmailInvitation).
		WHERE(table.EmailInvitation.OrganizationID.EQ(postgres.UUID(orgID)).
			AND(table.EmailInvitation.AcceptedAt.IS_NULL())).
		ORDER_BY(table.EmailInvitation.CreatedAt.DESC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	return rows, database.QueryError(err)
}

// DeleteInvitation revokes a pending invitation, which is what makes the token in
// the email stop working. Scoped to the organization as well as the id: row
// security would refuse a cross-tenant delete anyway, but the caller should not
// depend on that being the only thing standing there.
func (r Repository) DeleteInvitation(ctx context.Context, orgID uuid.UUID, id uuid.UUID) error {
	result, err := table.EmailInvitation.DELETE().
		WHERE(table.EmailInvitation.ID.EQ(postgres.UUID(id)).
			AND(table.EmailInvitation.OrganizationID.EQ(postgres.UUID(orgID))).
			AND(table.EmailInvitation.AcceptedAt.IS_NULL())).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// InvitationByID reads one pending invitation so it can be resent. It returns the
// address and role to re-mint against, never the old token, which is not
// recoverable and must not be: a resend issues a new one and the old one stops
// working.
func (r Repository) InvitationByID(ctx context.Context, orgID uuid.UUID, id uuid.UUID) (Invitation, error) {
	var rows []Invitation
	err := postgres.SELECT(
		postgres.CAST(table.EmailInvitation.ID).AS_TEXT().AS("ID"),
		table.EmailInvitation.Email.AS("Email"),
		postgres.COALESCE(table.EmailInvitation.Name, postgres.String("")).AS("Name"),
		table.EmailInvitation.Role.AS("Role"),
		table.EmailInvitation.CreatedAt.AS("CreatedAt"),
		table.EmailInvitation.ExpiresAt.AS("ExpiresAt"),
	).FROM(table.EmailInvitation).
		WHERE(table.EmailInvitation.ID.EQ(postgres.UUID(id)).
			AND(table.EmailInvitation.OrganizationID.EQ(postgres.UUID(orgID))).
			AND(table.EmailInvitation.AcceptedAt.IS_NULL())).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err = database.QueryError(err); err != nil {
		return Invitation{}, err
	}
	if len(rows) == 0 {
		return Invitation{}, sql.ErrNoRows
	}
	return rows[0], nil
}

// AcceptInvitation takes the token from the URL and hashes it here, matching
// UserByMagicToken. The conditional UPDATE ... RETURNING is what makes an
// invitation single-use.
func (r Repository) AcceptInvitation(ctx context.Context, token string) (model.User, error) {
	var invitation model.EmailInvitation
	err := table.EmailInvitation.UPDATE().SET(table.EmailInvitation.AcceptedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.EmailInvitation.TokenHash.EQ(postgres.String(tokenHash(token))).
			AND(table.EmailInvitation.ExpiresAt.GT(postgres.LOCALTIMESTAMP())).
			AND(table.EmailInvitation.AcceptedAt.IS_NULL())).
		RETURNING(table.EmailInvitation.OrganizationID, table.EmailInvitation.Email,
			table.EmailInvitation.Name, table.EmailInvitation.Role).
		QueryContext(ctx, database.Queryable(ctx, r.db), &invitation)
	if err != nil {
		return model.User{}, database.QueryError(err)
	}

	var user model.User
	// The name the inviting administrator typed, when there is one. The local part
	// of the address is the fallback for rows created before the column existed —
	// it is what every invitation used to get, and it is why "Dana Whitfield"
	// appeared in the team list as "dana.w".
	name := strings.Split(invitation.Email, "@")[0]
	if invitation.Name != nil && strings.TrimSpace(*invitation.Name) != "" {
		name = strings.TrimSpace(*invitation.Name)
	}
	err = postgres.SELECT(table.User.ID, table.User.OrganizationID, table.User.Email, table.User.Name).
		FROM(table.User).
		WHERE(table.User.OrganizationID.EQ(postgres.UUID(invitation.OrganizationID)).
			AND(table.User.Email.EQ(postgres.String(invitation.Email)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &user)
	err = database.QueryError(err)
	if errors.Is(err, sql.ErrNoRows) {
		err = table.User.INSERT(table.User.OrganizationID, table.User.Email, table.User.Name, table.User.Role).
			VALUES(invitation.OrganizationID, invitation.Email, name, invitation.Role).
			RETURNING(table.User.ID, table.User.OrganizationID, table.User.Email, table.User.Name).
			QueryContext(ctx, database.Queryable(ctx, r.db), &user)
		err = database.QueryError(err)
	} else if err == nil {
		_, err = table.User.UPDATE(table.User.Role).
			SET(invitation.Role).
			WHERE(table.User.ID.EQ(postgres.UUID(user.ID))).
			ExecContext(ctx, database.Executable(ctx, r.db))
	}
	if err != nil {
		return model.User{}, err
	}
	return user, nil
}

func (r Repository) Organization(ctx context.Context, id uuid.UUID) (Organization, error) {
	var org Organization
	err := postgres.SELECT(table.Organization.ID.AS("Organization.ID"), table.Organization.Name.AS("Organization.Name"),
		table.Organization.CreatedAt.AS("Organization.CreatedAt")).
		FROM(table.Organization).WHERE(table.Organization.ID.EQ(postgres.UUID(id))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &org)
	return org, database.QueryError(err)
}

func (r Repository) UpdateOrganization(ctx context.Context, id uuid.UUID, name string) error {
	_, err := table.Organization.UPDATE(table.Organization.Name).SET(name).
		WHERE(table.Organization.ID.EQ(postgres.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) Users(ctx context.Context, orgID uuid.UUID) ([]User, error) {
	var users []User
	err := postgres.SELECT(table.User.ID.AS("ID"), table.User.Name.AS("Name"), table.User.Email.AS("Email"), table.User.Role.AS("Role")).
		FROM(table.User).WHERE(table.User.OrganizationID.EQ(postgres.UUID(orgID))).
		ORDER_BY(table.User.Name.ASC(), table.User.Email.ASC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &users)
	return users, err
}

// User reads one member of the organization. Callers that change or remove a
// user read them first so the audit log can name who it was rather than only
// their id, which stops meaning anything once the row is gone.
func (r Repository) User(ctx context.Context, orgID, userID uuid.UUID) (User, error) {
	var user User
	err := postgres.SELECT(table.User.ID.AS("ID"), table.User.Name.AS("Name"), table.User.Email.AS("Email"), table.User.Role.AS("Role")).
		FROM(table.User).WHERE(table.User.ID.EQ(postgres.UUID(userID)).
		AND(table.User.OrganizationID.EQ(postgres.UUID(orgID)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &user)
	return user, database.QueryError(err)
}

// UpdateUserName changes a user's display name. Scoped to one id because the
// only caller is the person themselves: a display name is not an authorisation
// decision, so there is no administrator path to rename a colleague, and the
// organization arm of user_rls already keeps the update inside one tenant.
func (r Repository) UpdateUserName(ctx context.Context, userID uuid.UUID, name string) error {
	result, err := table.User.UPDATE(table.User.Name).SET(name).
		WHERE(table.User.ID.EQ(postgres.UUID(userID))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) UpdateUserRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	result, err := table.User.UPDATE(table.User.Role).SET(role).
		WHERE(table.User.ID.EQ(postgres.UUID(userID)).AND(table.User.OrganizationID.EQ(postgres.UUID(orgID)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return err
}

func (r Repository) DeleteUser(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := table.Session.DELETE().WHERE(table.Session.UserID.EQ(postgres.UUID(userID)).
		AND(table.Session.OrganizationID.EQ(postgres.UUID(orgID)))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	result, err := table.User.DELETE().WHERE(table.User.ID.EQ(postgres.UUID(userID)).
		AND(table.User.OrganizationID.EQ(postgres.UUID(orgID)))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return err
}

// Challenge is a login that has proved one factor and not the second.
type Challenge struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	Stage    string
	Attempts int
	// PendingSecret is the sealed, unconfirmed TOTP secret of an enrolment in
	// progress. Empty on a verify challenge.
	PendingSecret []byte
}

// Challenge stages. A user in stageEnroll holds no confirmed factor and cannot
// reach a session by any route except registering one.
const (
	StageVerify = "verify"
	StageEnroll = "enroll"
)

// maxChallengeAttempts bounds guessing per challenge. Exhausting it does not
// lock the account — that would hand a denial of service to anyone who knows a
// customer's address — it spends this challenge, and a new one costs a fresh
// magic link, which costs mailbox access, which is the first factor.
//
// Five guesses at three-in-a-million each is not a threat; the counter exists so
// that "not a threat" does not depend on an in-process rate limiter that a
// second application instance would not share.
const maxChallengeAttempts = 5

// CreateChallenge opens a login challenge for a user who has just proved their
// first factor. stage says whether they already hold a second one.
func (r Repository) CreateChallenge(ctx context.Context, userID uuid.UUID, stage string, expiresAt time.Time) (uuid.UUID, error) {
	var challenges []model.LoginChallenge
	err := table.LoginChallenge.INSERT(table.LoginChallenge.UserID, table.LoginChallenge.Stage, table.LoginChallenge.ExpiresAt).
		VALUES(userID, stage, expiresAt).RETURNING(table.LoginChallenge.ID).
		QueryContext(ctx, database.Queryable(ctx, r.db), &challenges)
	if err != nil {
		return uuid.Nil, err
	}
	if len(challenges) == 0 {
		return uuid.Nil, sql.ErrNoRows
	}
	return challenges[0].ID, nil
}

// ChallengeByID reads a live challenge without spending an attempt. Used by the
// page render and by the QR endpoint, which are navigations rather than guesses.
func (r Repository) ChallengeByID(ctx context.Context, id uuid.UUID) (Challenge, error) {
	var rows []model.LoginChallenge
	err := postgres.SELECT(table.LoginChallenge.ID, table.LoginChallenge.UserID,
		table.LoginChallenge.Stage, table.LoginChallenge.Attempts, table.LoginChallenge.PendingTotpSecret).
		FROM(table.LoginChallenge).WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id)).
		AND(table.LoginChallenge.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	return challengeFrom(rows, database.QueryError(err))
}

// challengeFrom turns the mapped rows of either challenge query into the one
// Challenge the callers expect, or into the not-found they treat as "expired,
// spent, or gone".
//
// The rows are model.LoginChallenge and the destination is a slice, and both
// halves of that are load-bearing — for the reason documented on
// sessionIdentityRow above. These two queries scanned into the named Challenge
// struct, which names no table, so every column went unmapped and the lookup
// returned a zero value and a *nil error*. The symptom was not an error: it was
// a challenge whose UserID was the zero UUID, which the next query answered with
// no rows, which the handler read as an expired sign-in. A valid magic link
// therefore cleared the challenge cookie and redirected to /login, and the only
// visible evidence was that no cookie survived.
func challengeFrom(rows []model.LoginChallenge, err error) (Challenge, error) {
	if err != nil {
		return Challenge{}, err
	}
	if len(rows) == 0 {
		return Challenge{}, sql.ErrNoRows
	}
	c := Challenge{ID: rows[0].ID, UserID: rows[0].UserID, Stage: rows[0].Stage,
		Attempts: int(rows[0].Attempts)}
	if rows[0].PendingTotpSecret != nil {
		c.PendingSecret = *rows[0].PendingTotpSecret
	}
	return c, nil
}

// SpendChallengeAttempt reads the challenge and consumes one attempt in the same
// statement.
//
// The count is incremented before the guess is checked, and the bound is in the
// WHERE clause rather than in Go, so two submissions racing each other cannot
// both read "four attempts used" and both proceed. sql.ErrNoRows means the
// challenge is spent, expired, or gone — the caller treats all three the same
// way, by discarding it and sending the user back for a fresh magic link.
func (r Repository) SpendChallengeAttempt(ctx context.Context, id uuid.UUID) (Challenge, error) {
	var rows []model.LoginChallenge
	err := table.LoginChallenge.UPDATE().
		SET(table.LoginChallenge.Attempts.SET(table.LoginChallenge.Attempts.ADD(postgres.Int(1)))).
		WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id)).
			AND(table.LoginChallenge.ExpiresAt.GT(postgres.LOCALTIMESTAMP())).
			AND(table.LoginChallenge.Attempts.LT(postgres.Int(maxChallengeAttempts)))).
		RETURNING(table.LoginChallenge.ID, table.LoginChallenge.UserID,
			table.LoginChallenge.Stage, table.LoginChallenge.Attempts, table.LoginChallenge.PendingTotpSecret).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	return challengeFrom(rows, database.QueryError(err))
}

// SetPendingSecret stores the sealed secret of an enrolment in progress, so the
// page can be reloaded without invalidating what the user already scanned.
func (r Repository) SetPendingSecret(ctx context.Context, id uuid.UUID, sealed []byte) error {
	_, err := table.LoginChallenge.UPDATE(table.LoginChallenge.PendingTotpSecret).SET(sealed).
		WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// passkeyRow is the scan destination for Passkeys. A type alias to an anonymous
// struct, for the reason totpRow is one; Passkey itself cannot be the alias
// because it carries methods.
//
// This was a live bug rather than a precaution. Passkeys scanned into []Passkey,
// which mapped nothing and returned an empty slice with a nil error, so every
// caller saw an account with no credentials: the list rendered empty however
// many were registered, sign-in answered "no passkey is registered on this
// account", and registration excluded nothing and so let the same authenticator
// be enrolled twice.
type passkeyRow = struct {
	ID           uuid.UUID
	CredentialID []byte
	PublicKey    []byte
	Attestation  string
	AAGUID       []byte
	Transports   string
	SignCount    uint32
	BackupEli    bool
	BackupState  bool
	CloneWarning bool
	Label        string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// Passkeys lists a user's registered credentials, newest first.
func (r Repository) Passkeys(ctx context.Context, userID uuid.UUID) ([]Passkey, error) {
	var rows []passkeyRow
	err := postgres.SELECT(table.UserWebauthnCredential.ID.AS("ID"),
		table.UserWebauthnCredential.CredentialID.AS("CredentialID"), table.UserWebauthnCredential.PublicKey.AS("PublicKey"),
		table.UserWebauthnCredential.AttestationType.AS("Attestation"), table.UserWebauthnCredential.Aaguid.AS("AAGUID"),
		table.UserWebauthnCredential.Transports.AS("Transports"), table.UserWebauthnCredential.SignCount.AS("SignCount"),
		table.UserWebauthnCredential.BackupEligible.AS("BackupEli"), table.UserWebauthnCredential.BackupState.AS("BackupState"),
		table.UserWebauthnCredential.CloneWarning.AS("CloneWarning"), table.UserWebauthnCredential.Label.AS("Label"),
		table.UserWebauthnCredential.CreatedAt.AS("CreatedAt"), table.UserWebauthnCredential.LastUsedAt.AS("LastUsedAt")).
		FROM(table.UserWebauthnCredential).
		WHERE(table.UserWebauthnCredential.UserID.EQ(postgres.UUID(userID))).
		ORDER_BY(table.UserWebauthnCredential.CreatedAt.DESC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return nil, err
	}
	out := make([]Passkey, 0, len(rows))
	for _, row := range rows {
		out = append(out, Passkey(row))
	}
	return out, nil
}

// SavePasskey stores a newly registered credential. A duplicate credential_id
// is refused by the unique index rather than handled here: the same
// authenticator must not be registrable against two accounts, and the database
// is the only place that can see both.
func (r Repository) SavePasskey(ctx context.Context, userID uuid.UUID, p Passkey) error {
	_, err := table.UserWebauthnCredential.INSERT(table.UserWebauthnCredential.UserID,
		table.UserWebauthnCredential.CredentialID, table.UserWebauthnCredential.PublicKey,
		table.UserWebauthnCredential.AttestationType, table.UserWebauthnCredential.Aaguid,
		table.UserWebauthnCredential.Transports, table.UserWebauthnCredential.SignCount,
		table.UserWebauthnCredential.BackupEligible, table.UserWebauthnCredential.BackupState,
		table.UserWebauthnCredential.Label).
		VALUES(userID, p.CredentialID, p.PublicKey, p.Attestation, p.AAGUID, p.Transports,
			p.SignCount, p.BackupEli, p.BackupState, p.Label).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// AdvancePasskeyCounter records a successful assertion, and reports whether the
// signature counter moved forward.
//
// A counter that did not advance means the authenticator was cloned or a backup
// of it was restored — the one thing the counter exists to detect. The caller
// refuses the login on false rather than merely noting it, because accepting it
// would make the counter decorative.
//
// Authenticators that always report zero are exempt: the specification permits
// it, many passkey implementations do it, and treating a constant zero as a
// clone would lock out every one of them.
func (r Repository) AdvancePasskeyCounter(ctx context.Context, credentialID []byte, count uint32) (bool, error) {
	countExp := postgres.Int64(int64(count))
	result, err := table.UserWebauthnCredential.UPDATE().SET(
		table.UserWebauthnCredential.SignCount.SET(countExp),
		table.UserWebauthnCredential.LastUsedAt.SET(postgres.LOCALTIMESTAMP()),
	).WHERE(table.UserWebauthnCredential.CredentialID.EQ(postgres.Bytea(credentialID)).AND(
		countExp.GT(table.UserWebauthnCredential.SignCount).OR(
			countExp.EQ(postgres.Int64(0)).AND(table.UserWebauthnCredential.SignCount.EQ(postgres.Int64(0)))),
	)).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// FlagPasskeyClone marks a credential whose counter went backwards, so the
// refusal is visible afterwards rather than only in a log line.
func (r Repository) FlagPasskeyClone(ctx context.Context, credentialID []byte) error {
	_, err := table.UserWebauthnCredential.UPDATE(table.UserWebauthnCredential.CloneWarning).SET(true).
		WHERE(table.UserWebauthnCredential.CredentialID.EQ(postgres.Bytea(credentialID))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) DeletePasskey(ctx context.Context, userID, id uuid.UUID) error {
	result, err := table.UserWebauthnCredential.DELETE().WHERE(table.UserWebauthnCredential.ID.EQ(postgres.UUID(id)).
		AND(table.UserWebauthnCredential.UserID.EQ(postgres.UUID(userID)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetChallengeCeremony and SetSessionCeremony park a WebAuthn ceremony's state
// where the client cannot reach it. Login ceremonies belong to a challenge,
// registration ceremonies to a session; both are cleared on completion so a
// captured response cannot be replayed against a stale challenge.
//
// Both columns are jsonb, and both halves of that fact used to be got wrong in a
// way that made every passkey ceremony fail at its second step. Storing nil
// wrote the empty string, which jsonb refuses to parse; reading used
// COALESCE(jsonb, 'a text literal'), which Postgres refuses to type-check at all
// ("COALESCE types jsonb and text cannot be matched"). A registration therefore
// got as far as the browser creating the credential and then lost it. Clearing
// now writes NULL, and reading casts to text before defaulting.
func (r Repository) SetChallengeCeremony(ctx context.Context, id uuid.UUID, data []byte) error {
	_, err := table.LoginChallenge.UPDATE(table.LoginChallenge.WebauthnSession).
		SET(jsonbOrNull(data)).
		WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) ChallengeCeremony(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var result struct{ Data string }
	err := postgres.SELECT(ceremonyText(table.LoginChallenge.WebauthnSession)).
		FROM(table.LoginChallenge).WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id)).
		AND(table.LoginChallenge.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return []byte(result.Data), database.QueryError(err)
}

func (r Repository) SetSessionCeremony(ctx context.Context, sessionID uuid.UUID, data []byte) error {
	_, err := table.Session.UPDATE(table.Session.WebauthnSession).
		SET(jsonbOrNull(data)).
		WHERE(table.Session.ID.EQ(postgres.UUID(sessionID))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) SessionCeremony(ctx context.Context, sessionID uuid.UUID) ([]byte, error) {
	var result struct{ Data string }
	err := postgres.SELECT(ceremonyText(table.Session.WebauthnSession)).
		FROM(table.Session).WHERE(table.Session.ID.EQ(postgres.UUID(sessionID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return []byte(result.Data), database.QueryError(err)
}

// jsonbOrNull writes a ceremony, or clears the column. An empty value has to
// become SQL NULL: jsonb has no representation of "nothing", and the empty
// string is not valid JSON.
func jsonbOrNull(data []byte) postgres.Expression {
	if len(data) == 0 {
		return postgres.NULL
	}
	return postgres.CAST(postgres.String(string(data))).AS("jsonb")
}

// ceremonyText reads a ceremony column as text, defaulting to an empty object.
// The cast is what makes the COALESCE type-check — its two arms are jsonb and a
// text literal otherwise, which Postgres rejects outright rather than coercing.
func ceremonyText(column postgres.ColumnString) postgres.Projection {
	return postgres.COALESCE(postgres.CAST(column).AS_TEXT(), postgres.String("{}")).AS("Data")
}

// StampStepUp records that this session has just proved a second factor.
// Covered by session_rls's id = app.session_id arm, so a session can stamp its
// own row and no other's.
func (r Repository) StampStepUp(ctx context.Context, sessionID uuid.UUID) error {
	_, err := table.Session.UPDATE().SET(table.Session.SteppedUpAt.SET(postgres.NOW())).
		WHERE(table.Session.ID.EQ(postgres.UUID(sessionID))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// SetChallengeStage moves a challenge between verify and enroll, clearing any
// half-finished enrolment secret. Used when a recovery code is redeemed: the
// authenticator is gone, so the challenge stops asking for a code from it and
// starts asking for a replacement.
func (r Repository) SetChallengeStage(ctx context.Context, id uuid.UUID, stage string) error {
	_, err := table.LoginChallenge.UPDATE().SET(table.LoginChallenge.Stage.SET(postgres.String(stage)),
		table.LoginChallenge.PendingTotpSecret.SET(postgres.ByteaExp(postgres.NULL))).
		WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) DeleteChallenge(ctx context.Context, id uuid.UUID) error {
	_, err := table.LoginChallenge.DELETE().WHERE(table.LoginChallenge.ID.EQ(postgres.UUID(id))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// TOTPCredential is one confirmed authenticator. A user holds a set of these
// rather than a single one, so that a replacement device can be registered
// before the device it replaces is retired.
type TOTPCredential struct {
	ID          uuid.UUID
	Label       string
	Secret      []byte
	LastStep    int64
	ConfirmedAt time.Time
	LastUsedAt  *time.Time
}

// totpRow is the scan destination for TOTPCredentials, and it is a type *alias*
// to an anonymous struct for the reason documented on sessionIdentityRow above:
// go-jet resolves a named struct destination against the tables in the result
// set, so a named one maps nothing and returns an empty slice with a nil error.
// TOTPCredential cannot be the alias itself — it is returned to callers and
// wants a name — so the mapping is done here and converted.
type totpRow = struct {
	ID          uuid.UUID
	Label       string
	Secret      []byte
	LastStep    int64
	ConfirmedAt time.Time
	LastUsedAt  *time.Time
}

// TOTPCredentials returns every authenticator a user holds, oldest first so the
// list does not reorder itself as codes are used.
func (r Repository) TOTPCredentials(ctx context.Context, userID uuid.UUID) ([]TOTPCredential, error) {
	var rows []totpRow
	err := postgres.SELECT(
		table.UserTotpCredential.ID.AS("ID"), table.UserTotpCredential.Label.AS("Label"),
		table.UserTotpCredential.Secret.AS("Secret"), table.UserTotpCredential.LastStep.AS("LastStep"),
		table.UserTotpCredential.ConfirmedAt.AS("ConfirmedAt"),
		table.UserTotpCredential.LastUsedAt.AS("LastUsedAt")).
		FROM(table.UserTotpCredential).
		WHERE(table.UserTotpCredential.UserID.EQ(postgres.UUID(userID))).
		ORDER_BY(table.UserTotpCredential.ConfirmedAt.ASC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return nil, err
	}
	out := make([]TOTPCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, TOTPCredential(row))
	}
	return out, nil
}

// CountTOTPCredentials reports how many authenticators a user holds. It is what
// the enrolment stage of a login challenge turns on, and what the delete path
// checks before removing the last one.
func (r Repository) CountTOTPCredentials(ctx context.Context, userID uuid.UUID) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.UserTotpCredential.ID).AS("Count")).
		FROM(table.UserTotpCredential).
		WHERE(table.UserTotpCredential.UserID.EQ(postgres.UUID(userID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

// SaveTOTPCredential writes a newly confirmed factor and returns its id, which
// the caller needs to burn the code that confirmed it.
//
// A plain insert, not an upsert: a second authenticator joins the first rather
// than replacing it. last_step starts at zero because a new secret has no
// history, and carrying another credential's high-water mark onto it would
// refuse the first several codes the new device produces.
func (r Repository) SaveTOTPCredential(ctx context.Context, userID uuid.UUID, label string, sealed []byte) (uuid.UUID, error) {
	var rows []model.UserTotpCredential
	err := table.UserTotpCredential.
		INSERT(table.UserTotpCredential.UserID, table.UserTotpCredential.Label,
			table.UserTotpCredential.Secret, table.UserTotpCredential.LastStep,
			table.UserTotpCredential.ConfirmedAt).
		VALUES(userID, label, sealed, 0, postgres.LOCALTIMESTAMP()).
		RETURNING(table.UserTotpCredential.ID).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return uuid.Nil, err
	}
	if len(rows) == 0 {
		return uuid.Nil, sql.ErrNoRows
	}
	return rows[0].ID, nil
}

// AdvanceTOTPStep records that a code from this step was accepted by this
// credential, and reports whether it was this call that recorded it.
//
// The comparison is in the WHERE clause on purpose. Two requests submitting the
// same code at the same moment both read the same last_step, and both would
// otherwise be told to proceed; here exactly one updates a row and the other
// gets false. That is the difference between a replay guard and the appearance
// of one.
//
// Keyed by credential rather than by user, so each authenticator carries its own
// high-water mark. A shared one would mean using the phone in your pocket made
// the codes on your desk drawer's backup key look replayed.
func (r Repository) AdvanceTOTPStep(ctx context.Context, credentialID uuid.UUID, step int64) (bool, error) {
	stepExp := postgres.Int64(step)
	result, err := table.UserTotpCredential.UPDATE().SET(
		table.UserTotpCredential.LastStep.SET(stepExp),
		table.UserTotpCredential.LastUsedAt.SET(postgres.LOCALTIMESTAMP()),
	).WHERE(table.UserTotpCredential.ID.EQ(postgres.UUID(credentialID)).
		AND(table.UserTotpCredential.LastStep.LT(stepExp))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// DeleteTOTPCredential removes one authenticator, and refuses to remove the last
// one: an account with no second factor is below the floor the whole sign-in
// design rests on. sql.ErrNoRows means either "not yours" or "not there", which
// the caller reports as the same thing; ErrLastTOTPCredential means the row
// exists and was deliberately kept.
//
// The EXISTS arm is what makes the check a property of the statement rather than
// of a read the handler did first. Two deletes racing from the same account
// could in principle each see a sibling and both proceed — this is one person's
// own settings panel, and the alternative is locking the whole set on every
// removal — so the count is re-read afterwards and the transaction abandoned if
// it emptied.
func (r Repository) DeleteTOTPCredential(ctx context.Context, userID, id uuid.UUID) error {
	others := table.UserTotpCredential.AS("sibling")
	result, err := table.UserTotpCredential.DELETE().
		WHERE(table.UserTotpCredential.ID.EQ(postgres.UUID(id)).
			AND(table.UserTotpCredential.UserID.EQ(postgres.UUID(userID))).
			AND(postgres.EXISTS(postgres.SELECT(others.ID).FROM(others).
				WHERE(others.UserID.EQ(postgres.UUID(userID)).
					AND(others.ID.NOT_EQ(postgres.UUID(id))))))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		// Nothing was deleted. Either the row is not this user's, or it is theirs
		// and it is the only one; re-reading the set tells the two apart, so the
		// handler can say which without guessing.
		credentials, err := r.TOTPCredentials(ctx, userID)
		if err != nil {
			return err
		}
		for _, credential := range credentials {
			if credential.ID == id && len(credentials) == 1 {
				return ErrLastTOTPCredential
			}
		}
		return sql.ErrNoRows
	}
	return nil
}

// DeleteTOTPCredentials removes every authenticator a user holds. Used when a
// recovery code is redeemed: the user has just told us they no longer control
// any of them, so none of them is kept and the challenge moves to enrolment.
func (r Repository) DeleteTOTPCredentials(ctx context.Context, userID uuid.UUID) error {
	_, err := table.UserTotpCredential.DELETE().WHERE(table.UserTotpCredential.UserID.EQ(postgres.UUID(userID))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// SetPendingTOTP parks the sealed secret of an enrolment started from the
// settings panel, so reopening the panel re-renders the QR the user already
// scanned rather than minting a secret their authenticator does not hold. Nil
// clears it, which is what confirming or abandoning the enrolment does.
func (r Repository) SetPendingTOTP(ctx context.Context, sessionID uuid.UUID, sealed []byte, label string) error {
	_, err := table.Session.UPDATE(table.Session.PendingTotpSecret, table.Session.PendingTotpLabel).
		SET(sealed, label).
		WHERE(table.Session.ID.EQ(postgres.UUID(sessionID))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) PendingTOTP(ctx context.Context, sessionID uuid.UUID) (sealed []byte, label string, err error) {
	var rows []struct {
		Secret []byte
		Label  string
	}
	err = postgres.SELECT(
		postgres.COALESCE(table.Session.PendingTotpSecret, postgres.Bytea([]byte{})).AS("Secret"),
		postgres.COALESCE(table.Session.PendingTotpLabel, postgres.String("")).AS("Label")).
		FROM(table.Session).WHERE(table.Session.ID.EQ(postgres.UUID(sessionID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err = database.QueryError(err); err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", sql.ErrNoRows
	}
	return rows[0].Secret, rows[0].Label, nil
}

// ErrLastTOTPCredential is the refusal to remove an account's only
// authenticator. Second-factor enrolment is mandatory, so "remove the last one"
// is not a step towards having none — it is a request to leave the account below
// the floor, and it is refused rather than warned about.
var ErrLastTOTPCredential = errors.New("an account must keep at least one authenticator")

// ReplaceRecoveryCodes swaps a user's whole set atomically.
//
// The only caller is the enrolment that follows a login challenge — a first
// enrolment, or the re-enrolment a redeemed recovery code forces. There is
// deliberately no regeneration route: a set issued twice is a set the user has
// twice been told to write down, and the second telling is the one that gets
// ignored. Registering a further authenticator from the settings panel therefore
// does not touch these rows.
func (r Repository) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codes []RecoveryCode) error {
	db := database.Executable(ctx, r.db)
	if _, err := table.UserRecoveryCode.DELETE().WHERE(table.UserRecoveryCode.UserID.EQ(postgres.UUID(userID))).ExecContext(ctx, db); err != nil {
		return err
	}
	for _, code := range codes {
		if _, err := table.UserRecoveryCode.INSERT(table.UserRecoveryCode.UserID, table.UserRecoveryCode.Selector,
			table.UserRecoveryCode.VerifierHash).VALUES(userID, code.Selector, code.VerifierHash).ExecContext(ctx, db); err != nil {
			return err
		}
	}
	return nil
}

// RecoveryCodeBySelector finds the one unused row a submitted code could match.
// This is what keeps a guess to a single argon2id computation.
func (r Repository) RecoveryCodeBySelector(ctx context.Context, userID uuid.UUID, selector string) (id uuid.UUID, verifierHash string, err error) {
	var code model.UserRecoveryCode
	err = postgres.SELECT(table.UserRecoveryCode.ID, table.UserRecoveryCode.VerifierHash).
		FROM(table.UserRecoveryCode).WHERE(table.UserRecoveryCode.UserID.EQ(postgres.UUID(userID)).
		AND(table.UserRecoveryCode.Selector.EQ(postgres.String(selector))).
		AND(table.UserRecoveryCode.UsedAt.IS_NULL())).
		QueryContext(ctx, database.Queryable(ctx, r.db), &code)
	return code.ID, code.VerifierHash, database.QueryError(err)
}

// ConsumeRecoveryCode burns a code, and reports whether this call burned it.
// Called only after the verifier matched, so a wrong guess never spends a code;
// the used_at IS NULL predicate is what stops two simultaneous submissions of
// the same code from both succeeding.
func (r Repository) ConsumeRecoveryCode(ctx context.Context, id uuid.UUID) (bool, error) {
	result, err := table.UserRecoveryCode.UPDATE().SET(table.UserRecoveryCode.UsedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.UserRecoveryCode.ID.EQ(postgres.UUID(id)).AND(table.UserRecoveryCode.UsedAt.IS_NULL())).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// CountRecoveryCodes reports how many are left, for the warning in the account
// settings dialog.
func (r Repository) CountRecoveryCodes(ctx context.Context, userID uuid.UUID) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.UserRecoveryCode.ID).AS("Count")).FROM(table.UserRecoveryCode).
		WHERE(table.UserRecoveryCode.UserID.EQ(postgres.UUID(userID)).AND(table.UserRecoveryCode.UsedAt.IS_NULL())).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

// UserByID reads the user behind a challenge. Needed inside the auth flow, where
// there is no session and therefore no organization context.
func (r Repository) UserByID(ctx context.Context, id uuid.UUID) (model.User, error) {
	var user model.User
	err := postgres.SELECT(table.User.ID, table.User.OrganizationID, table.User.Email, table.User.Name).
		FROM(table.User).WHERE(table.User.ID.EQ(postgres.UUID(id))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &user)
	return user, database.QueryError(err)
}

// DeleteSessionsForUser signs a user out everywhere. Used when their second
// factor changes: a factor that was replaced because it may have been
// compromised is not much use if the sessions it authorised keep running.
func (r Repository) DeleteSessionsForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := table.Session.DELETE().WHERE(table.Session.UserID.EQ(postgres.UUID(userID))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) AuthFlow(ctx context.Context, fn func(context.Context) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	ctx = database.WithTx(ctx, tx)
	if err := database.SetLocal(ctx, "app.auth_flow", "true"); err != nil {
		tx.Rollback()
		return err
	}
	if err := fn(ctx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func uuidValue(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

func uuidString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
