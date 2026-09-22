package est

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

type Repository struct{ db *sql.DB }

func NewRepository(db *sql.DB) Repository { return Repository{db: db} }

func endpointStatement() postgres.SelectStatement {
	return postgres.SELECT(table.EstEndpoint.ID.AS("Endpoint.ID"), table.EstEndpoint.OrganizationID.AS("Endpoint.OrganizationID"),
		table.EstEndpoint.CertificateAuthorityID.AS("Endpoint.CAID"), table.EstEndpoint.Name.AS("Endpoint.Name"),
		table.EstEndpoint.Enabled.AS("Endpoint.Enabled"), table.EstEndpoint.ValidityDays.AS("Endpoint.ValidityDays"),
		table.EstEndpoint.RenewalWindowDays.AS("Endpoint.RenewalWindowDays"), table.EstEndpoint.AllowedEkus.AS("Endpoint.AllowedEKUs"),
		table.EstEndpoint.SubjectPattern.AS("Endpoint.SubjectPattern"), table.EstEndpoint.SanPattern.AS("Endpoint.SANPattern"),
		table.EstEndpoint.ReenrollRequiresSameKey.AS("Endpoint.ReenrollRequiresSameKey"),
		table.EstEndpoint.CreatedAt.AS("Endpoint.CreatedAt"), table.EstEndpoint.UpdatedAt.AS("Endpoint.UpdatedAt")).FROM(table.EstEndpoint)
}

// Endpoint looks up by ID for the public client path, where the organization is
// not yet known and RLS scopes the row through app.est_endpoint_id.
func (r Repository) Endpoint(ctx context.Context, id string) (Endpoint, error) {
	var endpoint Endpoint
	err := endpointStatement().WHERE(table.EstEndpoint.ID.EQ(database.UUID(id))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &endpoint)
	return endpoint, database.QueryError(err)
}

// EndpointByID resolves an endpoint for administration, scoped to the
// organization so another customer's ID is not found rather than served.
func (r Repository) EndpointByID(ctx context.Context, orgID, id string) (Endpoint, error) {
	var endpoint Endpoint
	err := endpointStatement().WHERE(table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.EstEndpoint.ID.EQ(database.UUID(id)))).QueryContext(ctx, database.Queryable(ctx, r.db), &endpoint)
	return endpoint, database.QueryError(err)
}

func (r Repository) Endpoints(ctx context.Context, orgID string) ([]Endpoint, error) {
	var out []Endpoint
	err := endpointStatement().WHERE(table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(postgres.LOWER(table.EstEndpoint.Name).ASC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// InsertEndpoint stores a new endpoint. A name collides case-insensitively
// within the organization, which the unique index reports as a duplicate key.
func (r Repository) InsertEndpoint(ctx context.Context, e Endpoint) error {
	_, err := table.EstEndpoint.INSERT(table.EstEndpoint.ID, table.EstEndpoint.OrganizationID,
		table.EstEndpoint.CertificateAuthorityID, table.EstEndpoint.Name, table.EstEndpoint.Enabled,
		table.EstEndpoint.ValidityDays, table.EstEndpoint.RenewalWindowDays, table.EstEndpoint.AllowedEkus,
		table.EstEndpoint.SubjectPattern, table.EstEndpoint.SanPattern, table.EstEndpoint.ReenrollRequiresSameKey).
		VALUES(e.ID, e.OrganizationID, e.CAID, e.Name, e.Enabled, e.ValidityDays, e.RenewalWindowDays,
			e.AllowedEKUs, e.SubjectPattern, e.SANPattern, e.ReenrollRequiresSameKey).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return fmt.Errorf("an endpoint called %q already exists; pick another name", e.Name)
	}
	return err
}

// DeleteEndpoint removes an endpoint and, by cascade, its credentials and
// enrollment log. Certificates it issued are untouched: they keep working until
// they expire, and there is then nothing left to renew them.
func (r Repository) DeleteEndpoint(ctx context.Context, orgID, id string) error {
	res, err := table.EstEndpoint.DELETE().WHERE(table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.EstEndpoint.ID.EQ(database.UUID(id)))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) SetEnabled(ctx context.Context, orgID, id string, enabled bool) error {
	res, err := table.EstEndpoint.UPDATE().SET(table.EstEndpoint.Enabled.SET(postgres.Bool(enabled)),
		table.EstEndpoint.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID)).AND(table.EstEndpoint.ID.EQ(database.UUID(id)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// PolicyUpdate is everything the issuance policy form can change, including the
// endpoint's name — the only mutable part of its identity.
type PolicyUpdate struct {
	Name, SubjectPattern, SANPattern, AllowedEKUs string
	ValidityDays, RenewalWindowDays               int
	ReenrollRequiresSameKey                       bool
}

func (r Repository) UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error {
	res, err := table.EstEndpoint.UPDATE().SET(table.EstEndpoint.Name.SET(postgres.String(p.Name)),
		table.EstEndpoint.ValidityDays.SET(postgres.Int(int64(p.ValidityDays))),
		table.EstEndpoint.RenewalWindowDays.SET(postgres.Int(int64(p.RenewalWindowDays))),
		table.EstEndpoint.SubjectPattern.SET(postgres.String(p.SubjectPattern)),
		table.EstEndpoint.SanPattern.SET(postgres.String(p.SANPattern)),
		table.EstEndpoint.AllowedEkus.SET(postgres.String(p.AllowedEKUs)),
		table.EstEndpoint.ReenrollRequiresSameKey.SET(postgres.Bool(p.ReenrollRequiresSameKey)),
		table.EstEndpoint.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID)).AND(table.EstEndpoint.ID.EQ(database.UUID(id)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return fmt.Errorf("an endpoint called %q already exists; pick another name", p.Name)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// EndpointSummary is one row of the endpoint list.
type EndpointSummary struct {
	ID, Name, CAID string
	Enabled        bool
	Credentials    int
	RecentIssued   int
}

// EndpointSummaries lists the organization's endpoints with the counts the list
// page shows, so rendering it costs one query rather than one per endpoint.
func (r Repository) EndpointSummaries(ctx context.Context, orgID string) ([]EndpointSummary, error) {
	c := table.EstCredential.AS("c")
	n := table.EstEnrollment.AS("n")
	credentialCount := postgres.SELECT(postgres.COUNT(c.ID)).FROM(c).
		WHERE(c.EstEndpointID.EQ(table.EstEndpoint.ID).AND(c.RevokedAt.IS_NULL()))
	recentIssued := postgres.SELECT(postgres.COUNT(n.ID)).FROM(n).WHERE(n.EstEndpointID.EQ(table.EstEndpoint.ID).
		AND(n.Status.EQ(postgres.String(StatusIssued))).
		AND(n.CreatedAt.GT(postgres.LOCALTIMESTAMP().SUB(postgres.INTERVAL(30, postgres.DAY)))))
	var out []EndpointSummary
	err := postgres.SELECT(table.EstEndpoint.ID.AS("EndpointSummary.ID"), table.EstEndpoint.Name.AS("EndpointSummary.Name"),
		table.EstEndpoint.CertificateAuthorityID.AS("EndpointSummary.CAID"), table.EstEndpoint.Enabled.AS("EndpointSummary.Enabled"),
		credentialCount.AS("EndpointSummary.Credentials"), recentIssued.AS("EndpointSummary.RecentIssued")).FROM(table.EstEndpoint).
		WHERE(table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(postgres.LOWER(table.EstEndpoint.Name).ASC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// LiveCertificateCount counts certificates this endpoint issued that are still
// usable — neither revoked nor expired. It is what the delete dialog puts in
// front of an administrator, because "12 devices are currently relying on this"
// is the number that makes the consequences concrete.
func (r Repository) LiveCertificateCount(ctx context.Context, endpointID string) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.EstEnrollment.ID).AS("Count")).
		FROM(table.EstEnrollment.INNER_JOIN(table.Certificate, table.Certificate.ID.EQ(table.EstEnrollment.CertificateID))).
		WHERE(table.EstEnrollment.EstEndpointID.EQ(database.UUID(endpointID)).
			AND(table.Certificate.Status.EQ(postgres.String("issued"))).
			AND(table.Certificate.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

func credentialStatement() postgres.SelectStatement {
	return postgres.SELECT(table.EstCredential.ID.AS("Credential.ID"), table.EstCredential.OrganizationID.AS("Credential.OrganizationID"),
		table.EstCredential.EstEndpointID.AS("Credential.EndpointID"), table.EstCredential.Label.AS("Credential.Label"),
		table.EstCredential.Username.AS("Credential.Username"), table.EstCredential.SecretHash.AS("Credential.SecretHash"),
		table.EstCredential.IdentifierPin.AS("Credential.IdentifierPin"), table.EstCredential.ExpiresAt.AS("Credential.ExpiresAt"),
		table.EstCredential.UsedAt.AS("Credential.UsedAt"), table.EstCredential.RevokedAt.AS("Credential.RevokedAt"),
		table.EstCredential.CreatedAt.AS("Credential.CreatedAt")).FROM(table.EstCredential)
}

func (r Repository) CreateCredential(ctx context.Context, c Credential) error {
	_, err := table.EstCredential.INSERT(table.EstCredential.ID, table.EstCredential.OrganizationID,
		table.EstCredential.EstEndpointID, table.EstCredential.Label, table.EstCredential.Username,
		table.EstCredential.SecretHash, table.EstCredential.IdentifierPin, table.EstCredential.ExpiresAt).
		VALUES(c.ID, c.OrganizationID, c.EndpointID, c.Label, c.Username, c.SecretHash, c.IdentifierPin, c.ExpiresAt).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return fmt.Errorf("a credential with the username %q already exists on this endpoint", c.Username)
	}
	return err
}

// CredentialByUsername resolves the credential a client authenticates as. The
// lookup is scoped to the endpoint, so a username minted for one endpoint cannot
// enroll against another even within the same organization.
//
// Revoked rows are excluded rather than left for Usable to reject. A username is
// reusable once revoked — that is how a secret is rotated — so several revoked
// rows may share one, and an unfiltered query would return whichever the planner
// reached first, failing authentication for a credential that is perfectly live.
// With this predicate the partial unique index guarantees at most one row. A
// revoked credential still answers exactly as an unknown one does: no row, so
// Authenticate spends its decoy hash and returns the same refusal.
func (r Repository) CredentialByUsername(ctx context.Context, endpointID, username string) (Credential, error) {
	var credential Credential
	err := credentialStatement().WHERE(table.EstCredential.EstEndpointID.EQ(database.UUID(endpointID)).
		AND(postgres.LOWER(table.EstCredential.Username).EQ(postgres.LOWER(postgres.String(username)))).
		AND(table.EstCredential.RevokedAt.IS_NULL())).QueryContext(ctx, database.Queryable(ctx, r.db), &credential)
	return credential, database.QueryError(err)
}

func (r Repository) Credentials(ctx context.Context, endpointID string) ([]Credential, error) {
	var out []Credential
	err := credentialStatement().WHERE(table.EstCredential.EstEndpointID.EQ(database.UUID(endpointID))).
		ORDER_BY(table.EstCredential.CreatedAt.DESC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// TouchCredential records that a credential was used. Unlike ACME's
// UseCredential this carries no rule in its predicate — an EST credential is
// reusable by design — so it is a last-seen timestamp for the administrator,
// not an enforcement point, and its failure must not fail the enrollment.
func (r Repository) TouchCredential(ctx context.Context, id string) error {
	_, err := table.EstCredential.UPDATE().SET(table.EstCredential.UsedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.EstCredential.ID.EQ(database.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// RevokeCredential withdraws a credential. Certificates it already enrolled keep
// working — revoking the password stops the next enrollment, not the fleet.
func (r Repository) RevokeCredential(ctx context.Context, orgID, endpointID, id string) error {
	res, err := table.EstCredential.UPDATE().SET(table.EstCredential.RevokedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.EstCredential.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.EstCredential.EstEndpointID.EQ(database.UUID(endpointID))).
			AND(table.EstCredential.ID.EQ(database.UUID(id))).AND(table.EstCredential.RevokedAt.IS_NULL())).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) CreateEnrollment(ctx context.Context, n Enrollment) error {
	if n.Status == "" {
		n.Status = StatusIssued
	}
	credential := postgres.CAST(postgres.NULLIF(postgres.String(n.CredentialID), postgres.String(""))).AS_UUID()
	certificate := postgres.CAST(postgres.NULLIF(postgres.String(n.CertificateID), postgres.String(""))).AS_UUID()
	_, err := table.EstEnrollment.INSERT(table.EstEnrollment.OrganizationID, table.EstEnrollment.EstEndpointID,
		table.EstEnrollment.EstCredentialID, table.EstEnrollment.CertificateID, table.EstEnrollment.Subject,
		table.EstEnrollment.Operation, table.EstEnrollment.Status, table.EstEnrollment.FailureReason).
		VALUES(n.OrganizationID, n.EndpointID, credential, certificate, n.Subject, n.Operation, n.Status, n.FailureReason).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// EnrollmentRecord is one row of the endpoint page's activity log, joined to the
// certificate so the log can show what is still live.
//
// Result is the enrollment's own outcome and CertificateStatus is the state of
// what it produced. They answer different questions — "did this device get in"
// against "is what it got still valid" — and a refused enrollment has only the
// first.
type EnrollmentRecord struct {
	Subject, Operation, Credential string
	Result, FailureReason          string
	Serial, CertificateStatus      string
	ExpiresAt                      *time.Time
	CreatedAt                      time.Time
}

func (r Repository) Enrollments(ctx context.Context, endpointID string, limit int) ([]EnrollmentRecord, error) {
	var out []EnrollmentRecord
	err := postgres.SELECT(table.EstEnrollment.Subject.AS("EnrollmentRecord.Subject"), table.EstEnrollment.Operation.AS("EnrollmentRecord.Operation"),
		postgres.COALESCE(table.EstCredential.Label, table.EstCredential.Username, postgres.String("")).AS("EnrollmentRecord.Credential"),
		table.EstEnrollment.Status.AS("EnrollmentRecord.Result"), table.EstEnrollment.FailureReason.AS("EnrollmentRecord.FailureReason"),
		postgres.COALESCE(table.Certificate.Serial, postgres.String("")).AS("EnrollmentRecord.Serial"),
		postgres.COALESCE(table.Certificate.Status, postgres.String("")).AS("EnrollmentRecord.CertificateStatus"),
		table.Certificate.ExpiresAt.AS("EnrollmentRecord.ExpiresAt"), table.EstEnrollment.CreatedAt.AS("EnrollmentRecord.CreatedAt")).
		FROM(table.EstEnrollment.LEFT_JOIN(table.EstCredential, table.EstCredential.ID.EQ(table.EstEnrollment.EstCredentialID)).
			LEFT_JOIN(table.Certificate, table.Certificate.ID.EQ(table.EstEnrollment.CertificateID))).
		WHERE(table.EstEnrollment.EstEndpointID.EQ(database.UUID(endpointID))).
		ORDER_BY(table.EstEnrollment.CreatedAt.DESC()).LIMIT(int64(limit)).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// RenewableCertificate finds the live certificate this credential already
// obtained from this endpoint for a subject. It is what stands in for the TLS
// client certificate RFC 7030 authenticates re-enrollment with.
//
// Three conditions, and the credential one is the load-bearing addition: a
// client may only re-enroll a subject **its own credential** enrolled, that this
// endpoint actually issued, and that is still live. Matching on the subject
// alone would let any holder of any credential on the endpoint renew any subject
// the endpoint had ever issued — with a key of their choosing — which is a
// weaker binding than the enrollment path it is supposed to be narrower than.
//
// The second arm of the credential test covers rotation. Revoking a credential
// and minting a replacement with the same username must not orphan every device
// it enrolled; est_credential_endpoint_username_key makes the username unique
// per endpoint, so this is exactly "same named identity, new secret" and widens
// nothing.
//
// The newest match wins, so a subject enrolled twice renews against whichever
// certificate expires last.
func (r Repository) RenewableCertificate(ctx context.Context, endpointID, credentialID, username, subject string) (RenewableCert, error) {
	var out RenewableCert
	previous := table.EstCredential.AS("prev")
	previousIdentity := postgres.EXISTS(postgres.SELECT(previous.ID).FROM(previous).
		WHERE(previous.ID.EQ(table.EstEnrollment.EstCredentialID).
			AND(previous.EstEndpointID.EQ(database.UUID(endpointID))).
			AND(postgres.LOWER(previous.Username).EQ(postgres.LOWER(postgres.String(username))))))
	err := postgres.SELECT(table.Certificate.ExpiresAt.AS("RenewableCert.ExpiresAt"), table.Certificate.CertificatePem.AS("RenewableCert.CertificatePEM")).
		FROM(table.EstEnrollment.INNER_JOIN(table.Certificate, table.Certificate.ID.EQ(table.EstEnrollment.CertificateID))).
		WHERE(table.EstEnrollment.EstEndpointID.EQ(database.UUID(endpointID)).
			AND(table.EstEnrollment.Subject.EQ(postgres.String(subject))).
			AND(table.Certificate.Status.EQ(postgres.String("issued"))).
			AND(table.Certificate.ExpiresAt.GT(postgres.LOCALTIMESTAMP())).
			AND(table.EstEnrollment.EstCredentialID.EQ(database.UUID(credentialID)).OR(previousIdentity))).
		ORDER_BY(table.Certificate.ExpiresAt.DESC()).LIMIT(1).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, database.QueryError(err)
}
