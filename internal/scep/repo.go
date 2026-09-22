package scep

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

type Repository struct{ db *sql.DB }

func NewRepository(db *sql.DB) Repository { return Repository{db: db} }

func endpointStatement() postgres.SelectStatement {
	return postgres.SELECT(table.ScepEndpoint.ID.AS("Endpoint.ID"), table.ScepEndpoint.OrganizationID.AS("Endpoint.OrganizationID"),
		table.ScepEndpoint.CertificateAuthorityID.AS("Endpoint.CAID"), table.ScepEndpoint.Name.AS("Endpoint.Name"),
		table.ScepEndpoint.Enabled.AS("Endpoint.Enabled"), table.ScepEndpoint.ValidityDays.AS("Endpoint.ValidityDays"),
		table.ScepEndpoint.AllowedEkus.AS("Endpoint.AllowedEKUs"), table.ScepEndpoint.SubjectPattern.AS("Endpoint.SubjectPattern"),
		table.ScepEndpoint.SanPattern.AS("Endpoint.SANPattern"), table.ScepEndpoint.AllowLegacyCrypto.AS("Endpoint.AllowLegacyCrypto"),
		table.ScepEndpoint.RenewalWindowDays.AS("Endpoint.RenewalWindowDays"), table.ScepEndpoint.RaCertificatePem.AS("Endpoint.RACertificatePEM"),
		table.ScepEndpoint.RaPrivateKeyCiphertext.AS("Endpoint.RAPrivateKeyCiphertext"),
		table.ScepEndpoint.CreatedAt.AS("Endpoint.CreatedAt"), table.ScepEndpoint.UpdatedAt.AS("Endpoint.UpdatedAt")).
		FROM(table.ScepEndpoint)
}

// Endpoint looks up by ID for the public device path, where the organization is
// not yet known and RLS scopes the row through app.scep_endpoint_id.
func (r Repository) Endpoint(ctx context.Context, id string) (Endpoint, error) {
	var endpoint Endpoint
	err := endpointStatement().WHERE(table.ScepEndpoint.ID.EQ(database.UUID(id))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &endpoint)
	return endpoint, database.QueryError(err)
}

// EndpointByID resolves an endpoint for administration, scoped to the
// organization so another customer's ID is not found rather than served.
func (r Repository) EndpointByID(ctx context.Context, orgID, id string) (Endpoint, error) {
	var endpoint Endpoint
	err := endpointStatement().WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.ScepEndpoint.ID.EQ(database.UUID(id)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &endpoint)
	return endpoint, database.QueryError(err)
}

func (r Repository) Endpoints(ctx context.Context, orgID string) ([]Endpoint, error) {
	var out []Endpoint
	err := endpointStatement().WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(postgres.LOWER(table.ScepEndpoint.Name).ASC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

func (r Repository) EndpointCount(ctx context.Context, orgID string) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.ScepEndpoint.ID).AS("Count")).FROM(table.ScepEndpoint).
		WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

// InsertEndpoint stores a new endpoint. A name collides case-insensitively
// within the organization, which the unique index reports as a duplicate key.
func (r Repository) InsertEndpoint(ctx context.Context, e Endpoint) error {
	_, err := table.ScepEndpoint.INSERT(table.ScepEndpoint.ID, table.ScepEndpoint.OrganizationID,
		table.ScepEndpoint.CertificateAuthorityID, table.ScepEndpoint.Name, table.ScepEndpoint.Enabled,
		table.ScepEndpoint.ValidityDays, table.ScepEndpoint.AllowedEkus, table.ScepEndpoint.SubjectPattern,
		table.ScepEndpoint.SanPattern, table.ScepEndpoint.AllowLegacyCrypto, table.ScepEndpoint.RenewalWindowDays,
		table.ScepEndpoint.RaCertificatePem, table.ScepEndpoint.RaPrivateKeyCiphertext).
		VALUES(e.ID, e.OrganizationID, e.CAID, e.Name, e.Enabled, e.ValidityDays, e.AllowedEKUs,
			e.SubjectPattern, e.SANPattern, e.AllowLegacyCrypto, e.RenewalWindowDays, e.RACertificatePEM,
			e.RAPrivateKeyCiphertext).ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return fmt.Errorf("an endpoint called %q already exists; pick another name", e.Name)
	}
	return err
}

// DeleteEndpoint removes an endpoint and, by cascade, its authentication
// methods, challenges, and transaction history. The service refuses to call
// this for an endpoint that has issued anything.
func (r Repository) DeleteEndpoint(ctx context.Context, orgID, id string) error {
	res, err := table.ScepEndpoint.DELETE().WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.ScepEndpoint.ID.EQ(database.UUID(id)))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// LiveCertificateCount counts certificates this endpoint issued that are still
// usable — neither revoked nor expired. It is what the delete dialog puts in
// front of an administrator, because "12 devices are currently relying on this"
// is the number that makes the consequences concrete.
func (r Repository) LiveCertificateCount(ctx context.Context, endpointID string) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.ScepTransaction.ID).AS("Count")).
		FROM(table.ScepTransaction.INNER_JOIN(table.Certificate, table.Certificate.ID.EQ(table.ScepTransaction.CertificateID))).
		WHERE(table.ScepTransaction.ScepEndpointID.EQ(database.UUID(endpointID)).
			AND(table.ScepTransaction.Status.EQ(postgres.String("issued"))).
			AND(table.Certificate.Status.EQ(postgres.String("issued"))).
			AND(table.Certificate.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

// EndpointSummary is one row of the endpoint list.
type EndpointSummary struct {
	ID, Name, CAID string
	Enabled        bool
	EnabledMethods int
	RecentIssued   int
}

// EndpointSummaries lists the organization's endpoints with the counts the list
// page shows, so rendering it costs one query rather than one per endpoint.
func (r Repository) EndpointSummaries(ctx context.Context, orgID string) ([]EndpointSummary, error) {
	m := table.ScepAuthMethod.AS("m")
	t := table.ScepTransaction.AS("t")
	enabledMethods := postgres.SELECT(postgres.COUNT(m.ID)).FROM(m).
		WHERE(m.ScepEndpointID.EQ(table.ScepEndpoint.ID).AND(m.Enabled.IS_TRUE()))
	recentIssued := postgres.SELECT(postgres.COUNT(t.ID)).FROM(t).
		WHERE(t.ScepEndpointID.EQ(table.ScepEndpoint.ID).
			AND(t.Status.EQ(postgres.String("issued"))).
			AND(t.CreatedAt.GT(postgres.LOCALTIMESTAMP().SUB(postgres.INTERVAL(30, postgres.DAY)))))
	var out []EndpointSummary
	err := postgres.SELECT(table.ScepEndpoint.ID.AS("EndpointSummary.ID"), table.ScepEndpoint.Name.AS("EndpointSummary.Name"),
		table.ScepEndpoint.CertificateAuthorityID.AS("EndpointSummary.CAID"), table.ScepEndpoint.Enabled.AS("EndpointSummary.Enabled"),
		enabledMethods.AS("EndpointSummary.EnabledMethods"), recentIssued.AS("EndpointSummary.RecentIssued")).FROM(table.ScepEndpoint).
		WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(postgres.LOWER(table.ScepEndpoint.Name).ASC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

func (r Repository) SetEnabled(ctx context.Context, orgID, id string, enabled bool) error {
	res, err := table.ScepEndpoint.UPDATE().SET(table.ScepEndpoint.Enabled.SET(postgres.Bool(enabled)),
		table.ScepEndpoint.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID)).AND(table.ScepEndpoint.ID.EQ(database.UUID(id)))).
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
	AllowLegacyCrypto                             bool
}

func (r Repository) UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error {
	res, err := table.ScepEndpoint.UPDATE().SET(table.ScepEndpoint.Name.SET(postgres.String(p.Name)),
		table.ScepEndpoint.ValidityDays.SET(postgres.Int(int64(p.ValidityDays))),
		table.ScepEndpoint.RenewalWindowDays.SET(postgres.Int(int64(p.RenewalWindowDays))),
		table.ScepEndpoint.SubjectPattern.SET(postgres.String(p.SubjectPattern)),
		table.ScepEndpoint.SanPattern.SET(postgres.String(p.SANPattern)),
		table.ScepEndpoint.AllowedEkus.SET(postgres.String(p.AllowedEKUs)),
		table.ScepEndpoint.AllowLegacyCrypto.SET(postgres.Bool(p.AllowLegacyCrypto)),
		table.ScepEndpoint.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID)).AND(table.ScepEndpoint.ID.EQ(database.UUID(id)))).
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

// authMethodStatement joins the organization-level Intune connection into each
// endpoint method row.
func authMethodStatement() postgres.SelectStatement {
	connected := postgres.EXISTS(postgres.SELECT(table.ScepIntuneConnection.OrganizationID).FROM(table.ScepIntuneConnection).
		WHERE(table.ScepIntuneConnection.OrganizationID.EQ(table.ScepAuthMethod.OrganizationID)))
	return postgres.SELECT(table.ScepAuthMethod.ID.AS("AuthMethod.ID"), table.ScepAuthMethod.OrganizationID.AS("AuthMethod.OrganizationID"),
		table.ScepAuthMethod.ScepEndpointID.AS("AuthMethod.EndpointID"), table.ScepAuthMethod.Method.AS("AuthMethod.Method"),
		table.ScepAuthMethod.Enabled.AS("AuthMethod.Enabled"), table.ScepAuthMethod.SecretHash.AS("AuthMethod.SecretHash"),
		table.ScepAuthMethod.Username.AS("AuthMethod.Username"), table.ScepAuthMethod.PasswordHash.AS("AuthMethod.PasswordHash"),
		table.ScepAuthMethod.ConfiguredAt.AS("AuthMethod.ConfiguredAt"), table.ScepAuthMethod.CreatedAt.AS("AuthMethod.CreatedAt"),
		table.ScepAuthMethod.UpdatedAt.AS("AuthMethod.UpdatedAt"), connected.AS("AuthMethod.IntuneConnected")).FROM(table.ScepAuthMethod)
}

// SeedAuthMethods creates the disabled placeholder row for every method so the
// admin page can render a complete list without special-casing missing rows.
func (r Repository) SeedAuthMethods(ctx context.Context, e Endpoint) error {
	for _, method := range Methods {
		if _, err := table.ScepAuthMethod.INSERT(table.ScepAuthMethod.OrganizationID,
			table.ScepAuthMethod.ScepEndpointID, table.ScepAuthMethod.Method).
			VALUES(e.OrganizationID, e.ID, method).
			ON_CONFLICT(table.ScepAuthMethod.ScepEndpointID, table.ScepAuthMethod.Method).DO_NOTHING().
			ExecContext(ctx, database.Executable(ctx, r.db)); err != nil {
			return err
		}
	}
	return nil
}

func (r Repository) AuthMethods(ctx context.Context, endpointID string) ([]AuthMethod, error) {
	var out []AuthMethod
	err := authMethodStatement().WHERE(table.ScepAuthMethod.ScepEndpointID.EQ(database.UUID(endpointID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

func (r Repository) AuthMethod(ctx context.Context, endpointID, method string) (AuthMethod, error) {
	var authMethod AuthMethod
	err := authMethodStatement().WHERE(table.ScepAuthMethod.ScepEndpointID.EQ(database.UUID(endpointID)).
		AND(table.ScepAuthMethod.Method.EQ(postgres.String(method)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &authMethod)
	return authMethod, database.QueryError(err)
}

func (r Repository) SetMethodEnabled(ctx context.Context, endpointID, method string, enabled bool) error {
	res, err := table.ScepAuthMethod.UPDATE().SET(table.ScepAuthMethod.Enabled.SET(postgres.Bool(enabled)),
		table.ScepAuthMethod.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.ScepAuthMethod.ScepEndpointID.EQ(database.UUID(endpointID)).
			AND(table.ScepAuthMethod.Method.EQ(postgres.String(method)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) UpsertStaticSecret(ctx context.Context, e Endpoint, hash string) error {
	_, err := table.ScepAuthMethod.INSERT(table.ScepAuthMethod.OrganizationID, table.ScepAuthMethod.ScepEndpointID,
		table.ScepAuthMethod.Method, table.ScepAuthMethod.SecretHash, table.ScepAuthMethod.ConfiguredAt).
		VALUES(e.OrganizationID, e.ID, AuthStatic, hash, postgres.LOCALTIMESTAMP()).
		ON_CONFLICT(table.ScepAuthMethod.ScepEndpointID, table.ScepAuthMethod.Method).
		DO_UPDATE(postgres.SET(table.ScepAuthMethod.SecretHash.SET(table.ScepAuthMethod.EXCLUDED.SecretHash),
			table.ScepAuthMethod.ConfiguredAt.SET(postgres.LOCALTIMESTAMP()),
			table.ScepAuthMethod.UpdatedAt.SET(postgres.LOCALTIMESTAMP()))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// IntuneConnection returns the organization's consented Entra directory, or
// sql.ErrNoRows when it has none.
func (r Repository) IntuneConnection(ctx context.Context, orgID string) (IntuneConnection, error) {
	var c IntuneConnection
	err := postgres.SELECT(table.ScepIntuneConnection.OrganizationID.AS("IntuneConnection.OrganizationID"),
		table.ScepIntuneConnection.TenantID.AS("IntuneConnection.TenantID"), table.ScepIntuneConnection.ConnectedAt.AS("IntuneConnection.ConnectedAt")).
		FROM(table.ScepIntuneConnection).WHERE(table.ScepIntuneConnection.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &c)
	return c, database.QueryError(err)
}

func (r Repository) IntuneConnected(ctx context.Context, orgID string) (bool, error) {
	var result struct{ Exists bool }
	err := postgres.SELECT(postgres.EXISTS(postgres.SELECT(table.ScepIntuneConnection.OrganizationID).FROM(table.ScepIntuneConnection).
		WHERE(table.ScepIntuneConnection.OrganizationID.EQ(database.UUID(orgID)))).AS("Exists")).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Exists, err
}

// ConnectIntuneTenant records the directory the organization consented to. A
// tenant backs at most one organization, enforced by a unique index that is
// evaluated outside RLS, so a collision here means another customer already
// connected it.
func (r Repository) ConnectIntuneTenant(ctx context.Context, orgID, tenantID string) error {
	_, err := table.ScepIntuneConnection.INSERT(table.ScepIntuneConnection.OrganizationID, table.ScepIntuneConnection.TenantID).
		VALUES(orgID, tenantID).ON_CONFLICT(table.ScepIntuneConnection.OrganizationID).
		DO_UPDATE(postgres.SET(table.ScepIntuneConnection.TenantID.SET(table.ScepIntuneConnection.EXCLUDED.TenantID),
			table.ScepIntuneConnection.ConnectedAt.SET(postgres.LOCALTIMESTAMP()),
			table.ScepIntuneConnection.UpdatedAt.SET(postgres.LOCALTIMESTAMP()))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return errors.New("that Microsoft Entra tenant is already connected to another SimpleSCEP organization")
	}
	return err
}

// DisconnectIntuneTenant unbinds the directory so it can be connected elsewhere,
// and switches the method off on every endpoint, because none of them can
// authorize an enrollment through Intune any more.
func (r Repository) DisconnectIntuneTenant(ctx context.Context, orgID string) error {
	exec := database.Executable(ctx, r.db)
	if _, err := table.ScepAuthMethod.UPDATE().SET(table.ScepAuthMethod.Enabled.SET(postgres.Bool(false)),
		table.ScepAuthMethod.ConfiguredAt.SET(postgres.TimestampExp(postgres.NULL)),
		table.ScepAuthMethod.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.ScepAuthMethod.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.ScepAuthMethod.Method.EQ(postgres.String(AuthIntune)))).ExecContext(ctx, exec); err != nil {
		return err
	}
	_, err := table.ScepIntuneConnection.DELETE().WHERE(table.ScepIntuneConnection.OrganizationID.EQ(database.UUID(orgID))).
		ExecContext(ctx, exec)
	return err
}

func (r Repository) UpsertJamf(ctx context.Context, e Endpoint, username, passwordHash string) error {
	_, err := table.ScepAuthMethod.INSERT(table.ScepAuthMethod.OrganizationID, table.ScepAuthMethod.ScepEndpointID,
		table.ScepAuthMethod.Method, table.ScepAuthMethod.Username, table.ScepAuthMethod.PasswordHash,
		table.ScepAuthMethod.ConfiguredAt).VALUES(e.OrganizationID, e.ID, AuthJamf, username, passwordHash, postgres.LOCALTIMESTAMP()).
		ON_CONFLICT(table.ScepAuthMethod.ScepEndpointID, table.ScepAuthMethod.Method).
		DO_UPDATE(postgres.SET(table.ScepAuthMethod.Username.SET(table.ScepAuthMethod.EXCLUDED.Username),
			table.ScepAuthMethod.PasswordHash.SET(table.ScepAuthMethod.EXCLUDED.PasswordHash),
			table.ScepAuthMethod.ConfiguredAt.SET(postgres.LOCALTIMESTAMP()),
			table.ScepAuthMethod.UpdatedAt.SET(postgres.LOCALTIMESTAMP()))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) CreateChallenge(ctx context.Context, c Challenge, lookup []byte) error {
	_, err := table.ScepChallenge.INSERT(table.ScepChallenge.ID, table.ScepChallenge.OrganizationID,
		table.ScepChallenge.ScepEndpointID, table.ScepChallenge.LookupDigest, table.ScepChallenge.SecretHash,
		table.ScepChallenge.ExpectedSubject, table.ScepChallenge.ExpectedSans, table.ScepChallenge.ExpectedEkus,
		table.ScepChallenge.ExternalID, table.ScepChallenge.ExpiresAt).
		VALUES(c.ID, c.OrganizationID, c.EndpointID, lookup, c.SecretHash, c.ExpectedSubject, c.ExpectedSANs,
			c.ExpectedEKUs, c.ExternalID, c.ExpiresAt).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) ChallengeForUpdate(ctx context.Context, endpointID string, lookup []byte) (Challenge, error) {
	var c Challenge
	err := postgres.SELECT(table.ScepChallenge.ID.AS("Challenge.ID"), table.ScepChallenge.OrganizationID.AS("Challenge.OrganizationID"),
		table.ScepChallenge.ScepEndpointID.AS("Challenge.EndpointID"), table.ScepChallenge.SecretHash.AS("Challenge.SecretHash"),
		table.ScepChallenge.ExpectedSubject.AS("Challenge.ExpectedSubject"), table.ScepChallenge.ExpectedSans.AS("Challenge.ExpectedSANs"),
		table.ScepChallenge.ExpectedEkus.AS("Challenge.ExpectedEKUs"), table.ScepChallenge.ExternalID.AS("Challenge.ExternalID"),
		table.ScepChallenge.ExpiresAt.AS("Challenge.ExpiresAt"), table.ScepChallenge.UsedAt.AS("Challenge.UsedAt")).
		FROM(table.ScepChallenge).WHERE(table.ScepChallenge.ScepEndpointID.EQ(database.UUID(endpointID)).
		AND(table.ScepChallenge.LookupDigest.EQ(postgres.Bytea(lookup)))).FOR(postgres.UPDATE()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &c)
	return c, database.QueryError(err)
}

func (r Repository) UseChallenge(ctx context.Context, id string) error {
	res, err := table.ScepChallenge.UPDATE().SET(table.ScepChallenge.UsedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.ScepChallenge.ID.EQ(database.UUID(id)).AND(table.ScepChallenge.UsedAt.IS_NULL()).
			AND(table.ScepChallenge.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func transactionStatement() postgres.SelectStatement {
	return postgres.SELECT(table.ScepTransaction.ScepEndpointID.AS("Transaction.EndpointID"),
		table.ScepTransaction.TransactionID.AS("Transaction.TransactionID"), table.ScepTransaction.CsrDigest.AS("Transaction.CSRDigest"),
		postgres.COALESCE(postgres.CAST(table.ScepTransaction.CertificateID).AS_TEXT(), postgres.String("")).AS("Transaction.CertificateID"),
		table.ScepTransaction.Status.AS("Transaction.Status"), table.ScepTransaction.MessageType.AS("Transaction.MessageType"),
		table.ScepTransaction.AuthorizationSource.AS("Transaction.AuthorizationSource"),
		table.ScepTransaction.FailureReason.AS("Transaction.FailureReason"),
		table.ScepTransaction.SignerKeyDigest.AS("Transaction.SignerKeyDigest"),
		table.ScepTransaction.CreatedAt.AS("Transaction.CreatedAt")).
		FROM(table.ScepTransaction)
}

func (r Repository) Transaction(ctx context.Context, endpointID, transactionID string) (Transaction, error) {
	var transaction Transaction
	err := transactionStatement().WHERE(table.ScepTransaction.ScepEndpointID.EQ(database.UUID(endpointID)).
		AND(table.ScepTransaction.TransactionID.EQ(postgres.String(transactionID)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &transaction)
	return transaction, database.QueryError(err)
}

func (r Repository) CreateTransaction(ctx context.Context, orgID string, t Transaction) error {
	certificateID := postgres.CAST(postgres.NULLIF(postgres.String(t.CertificateID), postgres.String(""))).AS_UUID()
	_, err := table.ScepTransaction.INSERT(table.ScepTransaction.OrganizationID, table.ScepTransaction.ScepEndpointID,
		table.ScepTransaction.TransactionID, table.ScepTransaction.CsrDigest, table.ScepTransaction.CertificateID,
		table.ScepTransaction.Status, table.ScepTransaction.MessageType, table.ScepTransaction.AuthorizationSource,
		table.ScepTransaction.FailureReason, table.ScepTransaction.SignerKeyDigest).
		VALUES(orgID, t.EndpointID, t.TransactionID, t.CSRDigest, certificateID, t.Status, t.MessageType,
			t.AuthorizationSource, t.FailureReason, t.SignerKeyDigest).
		ON_CONFLICT(table.ScepTransaction.ScepEndpointID, table.ScepTransaction.TransactionID).
		DO_UPDATE(postgres.SET(table.ScepTransaction.CsrDigest.SET(table.ScepTransaction.EXCLUDED.CsrDigest),
			table.ScepTransaction.CertificateID.SET(table.ScepTransaction.EXCLUDED.CertificateID),
			table.ScepTransaction.Status.SET(table.ScepTransaction.EXCLUDED.Status),
			table.ScepTransaction.MessageType.SET(table.ScepTransaction.EXCLUDED.MessageType),
			table.ScepTransaction.AuthorizationSource.SET(table.ScepTransaction.EXCLUDED.AuthorizationSource),
			table.ScepTransaction.FailureReason.SET(table.ScepTransaction.EXCLUDED.FailureReason),
			table.ScepTransaction.SignerKeyDigest.SET(table.ScepTransaction.EXCLUDED.SignerKeyDigest),
			table.ScepTransaction.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
			WHERE(table.ScepTransaction.Status.NOT_EQ(postgres.String("issued")))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) CertificateIssuedByEndpoint(ctx context.Context, endpointID, certificateID string) (bool, error) {
	return r.certificateIssued(ctx, table.ScepTransaction.ScepEndpointID.EQ(database.UUID(endpointID)), certificateID)
}

// CertificateIssuedByEndpoints is the same question across a set of endpoints,
// for the revocation worker: several endpoints on one issuing CA share a single
// Intune revocation queue, so a serial has to be matched against all of them
// before it can be reported back as not found.
//
// The IDs become individual Jet expressions rather than one array parameter.
// That keeps UUID typing in the generated IN predicate and avoids relying on
// driver-specific []string-to-uuid[] encoding.
func (r Repository) CertificateIssuedByEndpoints(ctx context.Context, endpointIDs []string, certificateID string) (bool, error) {
	ids := make([]postgres.Expression, 0, len(endpointIDs))
	for _, id := range endpointIDs {
		ids = append(ids, database.UUID(id))
	}
	if len(ids) == 0 {
		return false, nil
	}
	return r.certificateIssued(ctx, table.ScepTransaction.ScepEndpointID.IN(ids...), certificateID)
}

func (r Repository) certificateIssued(ctx context.Context, endpoints postgres.BoolExpression, certificateID string) (bool, error) {
	var result struct{ Exists bool }
	exists := postgres.EXISTS(postgres.SELECT(table.ScepTransaction.ID).FROM(table.ScepTransaction).
		WHERE(endpoints.AND(table.ScepTransaction.CertificateID.EQ(database.UUID(certificateID))).
			AND(table.ScepTransaction.Status.EQ(postgres.String("issued")))))
	err := postgres.SELECT(exists.AS("Exists")).QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Exists, err
}

func (r Repository) LockOrganization(ctx context.Context, orgID string) error {
	_, err := postgres.SELECT(postgres.Func("pg_advisory_xact_lock",
		postgres.Func("hashtextextended", postgres.String(orgID), postgres.Int(17)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// IntuneEndpoints lists endpoints the revocation worker should poll for.
func (r Repository) IntuneEndpoints(ctx context.Context, orgID string) ([]Endpoint, error) {
	methodExists := postgres.EXISTS(postgres.SELECT(table.ScepAuthMethod.ID).FROM(table.ScepAuthMethod).
		WHERE(table.ScepAuthMethod.ScepEndpointID.EQ(table.ScepEndpoint.ID).
			AND(table.ScepAuthMethod.Method.EQ(postgres.String(AuthIntune))).AND(table.ScepAuthMethod.Enabled.IS_TRUE())))
	connectionExists := postgres.EXISTS(postgres.SELECT(table.ScepIntuneConnection.OrganizationID).FROM(table.ScepIntuneConnection).
		WHERE(table.ScepIntuneConnection.OrganizationID.EQ(database.UUID(orgID))))
	var out []Endpoint
	err := endpointStatement().WHERE(table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.ScepEndpoint.Enabled.IS_TRUE()).AND(methodExists).AND(connectionExists)).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

func (r Repository) RecentTransactions(ctx context.Context, endpointID string, limit int) ([]Transaction, error) {
	var out []Transaction
	err := transactionStatement().WHERE(table.ScepTransaction.ScepEndpointID.EQ(database.UUID(endpointID))).
		ORDER_BY(table.ScepTransaction.CreatedAt.DESC()).LIMIT(int64(limit)).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}
