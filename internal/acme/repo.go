package acme

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

type Repository struct{ db *sql.DB }

func NewRepository(db *sql.DB) Repository { return Repository{db: db} }

func endpointStatement() postgres.SelectStatement {
	return postgres.SELECT(table.AcmeEndpoint.ID.AS("Endpoint.ID"), table.AcmeEndpoint.OrganizationID.AS("Endpoint.OrganizationID"),
		table.AcmeEndpoint.CertificateAuthorityID.AS("Endpoint.CAID"), table.AcmeEndpoint.Name.AS("Endpoint.Name"),
		table.AcmeEndpoint.Enabled.AS("Endpoint.Enabled"), table.AcmeEndpoint.ValidityDays.AS("Endpoint.ValidityDays"),
		table.AcmeEndpoint.AllowedEkus.AS("Endpoint.AllowedEKUs"), table.AcmeEndpoint.SubjectPattern.AS("Endpoint.SubjectPattern"),
		table.AcmeEndpoint.SanPattern.AS("Endpoint.SANPattern"), table.AcmeEndpoint.CreatedAt.AS("Endpoint.CreatedAt"),
		table.AcmeEndpoint.UpdatedAt.AS("Endpoint.UpdatedAt")).FROM(table.AcmeEndpoint)
}

// Endpoint looks up by ID for the public client path, where the organization is
// not yet known and RLS scopes the row through app.acme_endpoint_id.
func (r Repository) Endpoint(ctx context.Context, id string) (Endpoint, error) {
	var endpoint Endpoint
	err := endpointStatement().WHERE(table.AcmeEndpoint.ID.EQ(database.UUID(id))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &endpoint)
	return endpoint, database.QueryError(err)
}

// EndpointByID resolves an endpoint for administration, scoped to the
// organization so another customer's ID is not found rather than served.
func (r Repository) EndpointByID(ctx context.Context, orgID, id string) (Endpoint, error) {
	var endpoint Endpoint
	err := endpointStatement().WHERE(table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.AcmeEndpoint.ID.EQ(database.UUID(id)))).QueryContext(ctx, database.Queryable(ctx, r.db), &endpoint)
	return endpoint, database.QueryError(err)
}

func (r Repository) Endpoints(ctx context.Context, orgID string) ([]Endpoint, error) {
	var out []Endpoint
	err := endpointStatement().WHERE(table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(postgres.LOWER(table.AcmeEndpoint.Name).ASC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// InsertEndpoint stores a new endpoint. A name collides case-insensitively
// within the organization, which the unique index reports as a duplicate key.
func (r Repository) InsertEndpoint(ctx context.Context, e Endpoint) error {
	_, err := table.AcmeEndpoint.INSERT(table.AcmeEndpoint.ID, table.AcmeEndpoint.OrganizationID,
		table.AcmeEndpoint.CertificateAuthorityID, table.AcmeEndpoint.Name, table.AcmeEndpoint.Enabled,
		table.AcmeEndpoint.ValidityDays, table.AcmeEndpoint.AllowedEkus, table.AcmeEndpoint.SubjectPattern,
		table.AcmeEndpoint.SanPattern).VALUES(e.ID, e.OrganizationID, e.CAID, e.Name, e.Enabled,
		e.ValidityDays, e.AllowedEKUs, e.SubjectPattern, e.SANPattern).ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return fmt.Errorf("an endpoint called %q already exists; pick another name", e.Name)
	}
	return err
}

// DeleteEndpoint removes an endpoint and, by cascade, its credentials, accounts,
// orders, authorizations, and nonces.
func (r Repository) DeleteEndpoint(ctx context.Context, orgID, id string) error {
	res, err := table.AcmeEndpoint.DELETE().WHERE(table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.AcmeEndpoint.ID.EQ(database.UUID(id)))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) SetEnabled(ctx context.Context, orgID, id string, enabled bool) error {
	res, err := table.AcmeEndpoint.UPDATE().SET(table.AcmeEndpoint.Enabled.SET(postgres.Bool(enabled)),
		table.AcmeEndpoint.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID)).AND(table.AcmeEndpoint.ID.EQ(database.UUID(id)))).
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
	ValidityDays                                  int
}

func (r Repository) UpdatePolicy(ctx context.Context, orgID, id string, p PolicyUpdate) error {
	res, err := table.AcmeEndpoint.UPDATE().SET(table.AcmeEndpoint.Name.SET(postgres.String(p.Name)),
		table.AcmeEndpoint.ValidityDays.SET(postgres.Int(int64(p.ValidityDays))),
		table.AcmeEndpoint.SubjectPattern.SET(postgres.String(p.SubjectPattern)),
		table.AcmeEndpoint.SanPattern.SET(postgres.String(p.SANPattern)),
		table.AcmeEndpoint.AllowedEkus.SET(postgres.String(p.AllowedEKUs)),
		table.AcmeEndpoint.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID)).AND(table.AcmeEndpoint.ID.EQ(database.UUID(id)))).
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
	c := table.AcmeEabCredential.AS("c")
	o := table.AcmeOrder.AS("o")
	credentials := postgres.SELECT(postgres.COUNT(c.ID)).FROM(c).
		WHERE(c.AcmeEndpointID.EQ(table.AcmeEndpoint.ID).AND(c.RevokedAt.IS_NULL()))
	recentIssued := postgres.SELECT(postgres.COUNT(o.ID)).FROM(o).WHERE(o.AcmeEndpointID.EQ(table.AcmeEndpoint.ID).
		AND(o.Status.EQ(postgres.String(StatusValid))).
		AND(o.CreatedAt.GT(postgres.LOCALTIMESTAMP().SUB(postgres.INTERVAL(30, postgres.DAY)))))
	var out []EndpointSummary
	err := postgres.SELECT(table.AcmeEndpoint.ID.AS("EndpointSummary.ID"), table.AcmeEndpoint.Name.AS("EndpointSummary.Name"),
		table.AcmeEndpoint.CertificateAuthorityID.AS("EndpointSummary.CAID"), table.AcmeEndpoint.Enabled.AS("EndpointSummary.Enabled"),
		credentials.AS("EndpointSummary.Credentials"), recentIssued.AS("EndpointSummary.RecentIssued")).FROM(table.AcmeEndpoint).
		WHERE(table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(postgres.LOWER(table.AcmeEndpoint.Name).ASC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// LiveCertificateCount counts certificates this endpoint issued that are still
// usable — neither revoked nor expired. It is what the delete dialog puts in
// front of an administrator, because "12 services are currently relying on this"
// is the number that makes the consequences concrete.
func (r Repository) LiveCertificateCount(ctx context.Context, endpointID string) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.AcmeOrder.ID).AS("Count")).
		FROM(table.AcmeOrder.INNER_JOIN(table.Certificate, table.Certificate.ID.EQ(table.AcmeOrder.CertificateID))).
		WHERE(table.AcmeOrder.AcmeEndpointID.EQ(database.UUID(endpointID)).
			AND(table.AcmeOrder.Status.EQ(postgres.String(StatusValid))).
			AND(table.Certificate.Status.EQ(postgres.String("issued"))).
			AND(table.Certificate.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

func credentialStatement() postgres.SelectStatement {
	return postgres.SELECT(table.AcmeEabCredential.ID.AS("EABCredential.ID"), table.AcmeEabCredential.OrganizationID.AS("EABCredential.OrganizationID"),
		table.AcmeEabCredential.AcmeEndpointID.AS("EABCredential.EndpointID"), table.AcmeEabCredential.Label.AS("EABCredential.Label"),
		table.AcmeEabCredential.Kid.AS("EABCredential.KID"), table.AcmeEabCredential.MacKeyCiphertext.AS("EABCredential.MACKeyCiphertext"),
		table.AcmeEabCredential.IdentifierPin.AS("EABCredential.IdentifierPin"), table.AcmeEabCredential.SingleUse.AS("EABCredential.SingleUse"),
		table.AcmeEabCredential.ExpiresAt.AS("EABCredential.ExpiresAt"), table.AcmeEabCredential.UsedAt.AS("EABCredential.UsedAt"),
		table.AcmeEabCredential.RevokedAt.AS("EABCredential.RevokedAt"), table.AcmeEabCredential.CreatedAt.AS("EABCredential.CreatedAt")).
		FROM(table.AcmeEabCredential)
}

func (r Repository) CreateCredential(ctx context.Context, c EABCredential) error {
	_, err := table.AcmeEabCredential.INSERT(table.AcmeEabCredential.ID, table.AcmeEabCredential.OrganizationID,
		table.AcmeEabCredential.AcmeEndpointID, table.AcmeEabCredential.Label, table.AcmeEabCredential.Kid,
		table.AcmeEabCredential.MacKeyCiphertext, table.AcmeEabCredential.IdentifierPin,
		table.AcmeEabCredential.SingleUse, table.AcmeEabCredential.ExpiresAt).
		VALUES(c.ID, c.OrganizationID, c.EndpointID, c.Label, c.KID, c.MACKeyCiphertext, c.IdentifierPin,
			c.SingleUse, c.ExpiresAt).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// CredentialByKID resolves the credential a client's binding names. The lookup
// is scoped to the endpoint, so a kid minted for one directory cannot bind an
// account on another even within the same organization.
func (r Repository) CredentialByKID(ctx context.Context, endpointID, kid string) (EABCredential, error) {
	var credential EABCredential
	err := credentialStatement().WHERE(table.AcmeEabCredential.AcmeEndpointID.EQ(database.UUID(endpointID)).
		AND(table.AcmeEabCredential.Kid.EQ(postgres.String(kid)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &credential)
	return credential, database.QueryError(err)
}

func (r Repository) Credentials(ctx context.Context, endpointID string) ([]EABCredential, error) {
	var out []EABCredential
	err := credentialStatement().WHERE(table.AcmeEabCredential.AcmeEndpointID.EQ(database.UUID(endpointID))).
		ORDER_BY(table.AcmeEabCredential.CreatedAt.DESC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// UseCredential stamps a credential as spent. The predicate carries the
// single-use rule rather than trusting a check made earlier in the request: two
// clients racing on the same one-shot credential must not both succeed.
func (r Repository) UseCredential(ctx context.Context, id string) error {
	res, err := table.AcmeEabCredential.UPDATE().SET(table.AcmeEabCredential.UsedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeEabCredential.ID.EQ(database.UUID(id)).AND(table.AcmeEabCredential.RevokedAt.IS_NULL()).
			AND(table.AcmeEabCredential.ExpiresAt.IS_NULL().OR(table.AcmeEabCredential.ExpiresAt.GT(postgres.LOCALTIMESTAMP()))).
			AND(table.AcmeEabCredential.SingleUse.IS_FALSE().OR(table.AcmeEabCredential.UsedAt.IS_NULL()))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// RevokeCredential withdraws a credential and deactivates every account it
// bound. Revoking the key that let a client in should stop that client, not just
// stop the next one: an account whose credential is gone can no longer order.
func (r Repository) RevokeCredential(ctx context.Context, orgID, endpointID, id string) error {
	exec := database.Executable(ctx, r.db)
	res, err := table.AcmeEabCredential.UPDATE().SET(table.AcmeEabCredential.RevokedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeEabCredential.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.AcmeEabCredential.AcmeEndpointID.EQ(database.UUID(endpointID))).
			AND(table.AcmeEabCredential.ID.EQ(database.UUID(id))).AND(table.AcmeEabCredential.RevokedAt.IS_NULL())).
		ExecContext(ctx, exec)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	_, err = table.AcmeAccount.UPDATE().SET(table.AcmeAccount.Status.SET(postgres.String(StatusDeactivated)),
		table.AcmeAccount.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeAccount.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.AcmeAccount.EabCredentialID.EQ(database.UUID(id))).
			AND(table.AcmeAccount.Status.EQ(postgres.String(StatusValid)))).ExecContext(ctx, exec)
	return err
}

func accountStatement() postgres.SelectStatement {
	return postgres.SELECT(table.AcmeAccount.ID.AS("Account.ID"), table.AcmeAccount.OrganizationID.AS("Account.OrganizationID"),
		table.AcmeAccount.AcmeEndpointID.AS("Account.EndpointID"), table.AcmeAccount.JwkThumbprint.AS("Account.JWKThumbprint"),
		table.AcmeAccount.JwkJSON.AS("Account.JWKJSON"), table.AcmeAccount.Status.AS("Account.Status"),
		table.AcmeAccount.Contact.AS("Account.Contact"),
		postgres.COALESCE(postgres.CAST(table.AcmeAccount.EabCredentialID).AS_TEXT(), postgres.String("")).AS("Account.EABCredentialID"),
		table.AcmeAccount.IdentifierPin.AS("Account.IdentifierPin"), table.AcmeAccount.CreatedAt.AS("Account.CreatedAt"),
		table.AcmeAccount.UpdatedAt.AS("Account.UpdatedAt")).FROM(table.AcmeAccount)
}

func (r Repository) Account(ctx context.Context, endpointID, id string) (Account, error) {
	var account Account
	err := accountStatement().WHERE(table.AcmeAccount.AcmeEndpointID.EQ(database.UUID(endpointID)).
		AND(table.AcmeAccount.ID.EQ(database.UUID(id)))).QueryContext(ctx, database.Queryable(ctx, r.db), &account)
	return account, database.QueryError(err)
}

// AccountByThumbprint is how a client that still holds its key but has lost its
// account URL finds its way back, and how a repeated newAccount returns the same
// account rather than registering a second one.
func (r Repository) AccountByThumbprint(ctx context.Context, endpointID, thumbprint string) (Account, error) {
	var account Account
	err := accountStatement().WHERE(table.AcmeAccount.AcmeEndpointID.EQ(database.UUID(endpointID)).
		AND(table.AcmeAccount.JwkThumbprint.EQ(postgres.String(thumbprint)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &account)
	return account, database.QueryError(err)
}

func (r Repository) CreateAccount(ctx context.Context, a Account) error {
	credentialID := postgres.CAST(postgres.NULLIF(postgres.String(a.EABCredentialID), postgres.String(""))).AS_UUID()
	_, err := table.AcmeAccount.INSERT(table.AcmeAccount.ID, table.AcmeAccount.OrganizationID,
		table.AcmeAccount.AcmeEndpointID, table.AcmeAccount.JwkThumbprint, table.AcmeAccount.JwkJSON,
		table.AcmeAccount.Status, table.AcmeAccount.Contact, table.AcmeAccount.EabCredentialID,
		table.AcmeAccount.IdentifierPin).VALUES(a.ID, a.OrganizationID, a.EndpointID, a.JWKThumbprint,
		a.JWKJSON, a.Status, a.Contact, credentialID, a.IdentifierPin).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) UpdateAccount(ctx context.Context, endpointID, id, contact, status string) error {
	res, err := table.AcmeAccount.UPDATE().SET(table.AcmeAccount.Contact.SET(postgres.String(contact)),
		table.AcmeAccount.Status.SET(postgres.String(status)), table.AcmeAccount.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeAccount.AcmeEndpointID.EQ(database.UUID(endpointID)).AND(table.AcmeAccount.ID.EQ(database.UUID(id)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RekeyAccount swaps the key an account authenticates with (§7.3.5). The
// thumbprint moves with it, so the old key stops resolving to this account in
// the same statement the new one starts.
func (r Repository) RekeyAccount(ctx context.Context, endpointID, id, thumbprint, jwkJSON string) error {
	res, err := table.AcmeAccount.UPDATE().SET(table.AcmeAccount.JwkThumbprint.SET(postgres.String(thumbprint)),
		table.AcmeAccount.JwkJSON.SET(postgres.String(jwkJSON)), table.AcmeAccount.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeAccount.AcmeEndpointID.EQ(database.UUID(endpointID)).AND(table.AcmeAccount.ID.EQ(database.UUID(id)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if database.DuplicateKey(err) {
		return errors.New("that key already belongs to another account on this endpoint")
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func orderStatement() postgres.SelectStatement {
	return postgres.SELECT(table.AcmeOrder.ID.AS("Order.ID"), table.AcmeOrder.OrganizationID.AS("Order.OrganizationID"),
		table.AcmeOrder.AcmeEndpointID.AS("Order.EndpointID"), table.AcmeOrder.AcmeAccountID.AS("Order.AccountID"),
		table.AcmeOrder.Status.AS("Order.Status"), table.AcmeOrder.ExpiresAt.AS("Order.ExpiresAt"),
		table.AcmeOrder.NotBefore.AS("Order.NotBefore"), table.AcmeOrder.NotAfter.AS("Order.NotAfter"),
		postgres.COALESCE(postgres.CAST(table.AcmeOrder.CertificateID).AS_TEXT(), postgres.String("")).AS("Order.CertificateID"),
		table.AcmeOrder.ErrorType.AS("Order.ErrorType"), table.AcmeOrder.ErrorDetail.AS("Order.ErrorDetail"),
		table.AcmeOrder.CreatedAt.AS("Order.CreatedAt"), table.AcmeOrder.UpdatedAt.AS("Order.UpdatedAt")).FROM(table.AcmeOrder)
}

func (r Repository) Order(ctx context.Context, endpointID, id string) (Order, error) {
	var order Order
	err := orderStatement().WHERE(table.AcmeOrder.AcmeEndpointID.EQ(database.UUID(endpointID)).
		AND(table.AcmeOrder.ID.EQ(database.UUID(id)))).QueryContext(ctx, database.Queryable(ctx, r.db), &order)
	return order, database.QueryError(err)
}

// OrderForUpdate takes the row lock finalize needs. Two clients finalizing the
// same order must not both reach the issuer; the second waits here and then sees
// the status the first left behind.
func (r Repository) OrderForUpdate(ctx context.Context, endpointID, id string) (Order, error) {
	var order Order
	err := orderStatement().WHERE(table.AcmeOrder.AcmeEndpointID.EQ(database.UUID(endpointID)).
		AND(table.AcmeOrder.ID.EQ(database.UUID(id)))).FOR(postgres.UPDATE()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &order)
	return order, database.QueryError(err)
}

func (r Repository) CreateOrder(ctx context.Context, o Order) error {
	_, err := table.AcmeOrder.INSERT(table.AcmeOrder.ID, table.AcmeOrder.OrganizationID,
		table.AcmeOrder.AcmeEndpointID, table.AcmeOrder.AcmeAccountID, table.AcmeOrder.Status,
		table.AcmeOrder.ExpiresAt, table.AcmeOrder.NotBefore, table.AcmeOrder.NotAfter).
		VALUES(o.ID, o.OrganizationID, o.EndpointID, o.AccountID, o.Status, o.ExpiresAt, o.NotBefore, o.NotAfter).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// CompleteOrder records the certificate an order produced.
func (r Repository) CompleteOrder(ctx context.Context, id, certificateID string) error {
	certificate := postgres.CAST(postgres.NULLIF(postgres.String(certificateID), postgres.String(""))).AS_UUID()
	res, err := table.AcmeOrder.UPDATE().SET(table.AcmeOrder.Status.SET(postgres.String(StatusValid)),
		table.AcmeOrder.CertificateID.SET(certificate), table.AcmeOrder.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeOrder.ID.EQ(database.UUID(id))).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// FailOrder records why an order will never produce a certificate. The problem
// document is stored so a client polling the order afterwards is told the same
// thing the finalize call was, which is the only way an unattended client
// surfaces the reason to its operator.
func (r Repository) FailOrder(ctx context.Context, id, problemType, detail string) error {
	_, err := table.AcmeOrder.UPDATE().SET(table.AcmeOrder.Status.SET(postgres.String(StatusInvalid)),
		table.AcmeOrder.ErrorType.SET(postgres.String(problemType)), table.AcmeOrder.ErrorDetail.SET(postgres.String(detail)),
		table.AcmeOrder.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).WHERE(table.AcmeOrder.ID.EQ(database.UUID(id))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) Orders(ctx context.Context, endpointID string, limit int) ([]Order, error) {
	var out []Order
	err := orderStatement().WHERE(table.AcmeOrder.AcmeEndpointID.EQ(database.UUID(endpointID))).
		ORDER_BY(table.AcmeOrder.CreatedAt.DESC()).LIMIT(int64(limit)).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// authorizationColumns is aliased because the public lookup joins back through
// the order to scope itself to an endpoint, the way every other client-facing
// read is scoped.
// CertificateOrderedBy reports whether an account ordered a given certificate.
// It is what authorizes an account-signed revocation: holding an account on this
// endpoint is not authority over a certificate somebody else ordered.
func (r Repository) CertificateOrderedBy(ctx context.Context, accountID, certificateID string) (bool, error) {
	var result struct{ Exists bool }
	exists := postgres.EXISTS(postgres.SELECT(table.AcmeOrder.ID).FROM(table.AcmeOrder).
		WHERE(table.AcmeOrder.AcmeAccountID.EQ(database.UUID(accountID)).
			AND(table.AcmeOrder.CertificateID.EQ(database.UUID(certificateID))).
			AND(table.AcmeOrder.Status.EQ(postgres.String(StatusValid)))))
	err := postgres.SELECT(exists.AS("Exists")).QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Exists, err
}

func authorizationStatement() postgres.SelectStatement {
	return postgres.SELECT(table.AcmeAuthorization.ID.AS("Authorization.ID"), table.AcmeAuthorization.OrganizationID.AS("Authorization.OrganizationID"),
		table.AcmeAuthorization.AcmeOrderID.AS("Authorization.OrderID"), table.AcmeAuthorization.IdentifierType.AS("Authorization.IdentifierType"),
		table.AcmeAuthorization.IdentifierValue.AS("Authorization.IdentifierValue"), table.AcmeAuthorization.Status.AS("Authorization.Status"),
		table.AcmeAuthorization.ExpiresAt.AS("Authorization.ExpiresAt"), table.AcmeAuthorization.ValidatedAt.AS("Authorization.ValidatedAt")).
		FROM(table.AcmeAuthorization)
}

func (r Repository) Authorization(ctx context.Context, endpointID, id string) (Authorization, error) {
	var authorization Authorization
	err := postgres.SELECT(table.AcmeAuthorization.ID.AS("Authorization.ID"), table.AcmeAuthorization.OrganizationID.AS("Authorization.OrganizationID"),
		table.AcmeAuthorization.AcmeOrderID.AS("Authorization.OrderID"), table.AcmeAuthorization.IdentifierType.AS("Authorization.IdentifierType"),
		table.AcmeAuthorization.IdentifierValue.AS("Authorization.IdentifierValue"), table.AcmeAuthorization.Status.AS("Authorization.Status"),
		table.AcmeAuthorization.ExpiresAt.AS("Authorization.ExpiresAt"), table.AcmeAuthorization.ValidatedAt.AS("Authorization.ValidatedAt")).
		FROM(table.AcmeAuthorization.INNER_JOIN(table.AcmeOrder, table.AcmeOrder.ID.EQ(table.AcmeAuthorization.AcmeOrderID))).
		WHERE(table.AcmeOrder.AcmeEndpointID.EQ(database.UUID(endpointID)).AND(table.AcmeAuthorization.ID.EQ(database.UUID(id)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &authorization)
	return authorization, database.QueryError(err)
}

func (r Repository) Authorizations(ctx context.Context, orderID string) ([]Authorization, error) {
	var out []Authorization
	err := authorizationStatement().WHERE(table.AcmeAuthorization.AcmeOrderID.EQ(database.UUID(orderID))).
		ORDER_BY(table.AcmeAuthorization.IdentifierValue.ASC()).QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

func (r Repository) CreateAuthorization(ctx context.Context, a Authorization, c Challenge) error {
	exec := database.Executable(ctx, r.db)
	if _, err := table.AcmeAuthorization.INSERT(table.AcmeAuthorization.ID, table.AcmeAuthorization.OrganizationID,
		table.AcmeAuthorization.AcmeOrderID, table.AcmeAuthorization.IdentifierType,
		table.AcmeAuthorization.IdentifierValue, table.AcmeAuthorization.Status,
		table.AcmeAuthorization.ExpiresAt, table.AcmeAuthorization.ValidatedAt).
		VALUES(a.ID, a.OrganizationID, a.OrderID, a.IdentifierType, a.IdentifierValue, a.Status, a.ExpiresAt, a.ValidatedAt).
		ExecContext(ctx, exec); err != nil {
		return err
	}
	_, err := table.AcmeChallenge.INSERT(table.AcmeChallenge.ID, table.AcmeChallenge.OrganizationID,
		table.AcmeChallenge.AcmeAuthorizationID, table.AcmeChallenge.Type, table.AcmeChallenge.Token,
		table.AcmeChallenge.Status, table.AcmeChallenge.ValidatedAt).
		VALUES(c.ID, c.OrganizationID, c.AuthorizationID, c.Type, c.Token, c.Status, c.ValidatedAt).
		ExecContext(ctx, exec)
	return err
}

func challengeStatement() postgres.SelectStatement {
	return postgres.SELECT(table.AcmeChallenge.ID.AS("Challenge.ID"), table.AcmeChallenge.OrganizationID.AS("Challenge.OrganizationID"),
		table.AcmeChallenge.AcmeAuthorizationID.AS("Challenge.AuthorizationID"), table.AcmeChallenge.Type.AS("Challenge.Type"),
		table.AcmeChallenge.Token.AS("Challenge.Token"), table.AcmeChallenge.Status.AS("Challenge.Status"),
		table.AcmeChallenge.ValidatedAt.AS("Challenge.ValidatedAt")).FROM(table.AcmeChallenge)
}

func (r Repository) Challenge(ctx context.Context, endpointID, id string) (Challenge, error) {
	var challenge Challenge
	err := postgres.SELECT(table.AcmeChallenge.ID.AS("Challenge.ID"), table.AcmeChallenge.OrganizationID.AS("Challenge.OrganizationID"),
		table.AcmeChallenge.AcmeAuthorizationID.AS("Challenge.AuthorizationID"), table.AcmeChallenge.Type.AS("Challenge.Type"),
		table.AcmeChallenge.Token.AS("Challenge.Token"), table.AcmeChallenge.Status.AS("Challenge.Status"),
		table.AcmeChallenge.ValidatedAt.AS("Challenge.ValidatedAt")).
		FROM(table.AcmeChallenge.INNER_JOIN(table.AcmeAuthorization,
			table.AcmeAuthorization.ID.EQ(table.AcmeChallenge.AcmeAuthorizationID)).
			INNER_JOIN(table.AcmeOrder, table.AcmeOrder.ID.EQ(table.AcmeAuthorization.AcmeOrderID))).
		WHERE(table.AcmeOrder.AcmeEndpointID.EQ(database.UUID(endpointID)).AND(table.AcmeChallenge.ID.EQ(database.UUID(id)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &challenge)
	return challenge, database.QueryError(err)
}

func (r Repository) ChallengeFor(ctx context.Context, authorizationID string) (Challenge, error) {
	var challenge Challenge
	err := challengeStatement().WHERE(table.AcmeChallenge.AcmeAuthorizationID.EQ(database.UUID(authorizationID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &challenge)
	return challenge, database.QueryError(err)
}

// IssueNonce mints a replay nonce. The value is the primary key, so a collision
// would be a failure of crypto/rand rather than something to retry around.
func (r Repository) IssueNonce(ctx context.Context, orgID, endpointID string, value []byte) error {
	_, err := table.AcmeNonce.INSERT(table.AcmeNonce.Value, table.AcmeNonce.OrganizationID, table.AcmeNonce.AcmeEndpointID).
		VALUES(value, orgID, endpointID).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// ConsumeNonce spends a nonce, returning sql.ErrNoRows if it was never issued,
// has already been spent, or belongs to another endpoint.
//
// The delete is the check. Doing this as a SELECT followed by a DELETE would let
// two concurrent requests both pass the SELECT, which is exactly the replay the
// nonce exists to prevent.
func (r Repository) ConsumeNonce(ctx context.Context, endpointID string, value []byte) error {
	res, err := table.AcmeNonce.DELETE().WHERE(table.AcmeNonce.Value.EQ(postgres.Bytea(value)).
		AND(table.AcmeNonce.AcmeEndpointID.EQ(database.UUID(endpointID)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) DeleteExpiredNonces(ctx context.Context, before time.Time) (int64, error) {
	res, err := table.AcmeNonce.DELETE().WHERE(table.AcmeNonce.IssuedAt.LT(postgres.TimestampT(before))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ExpireOrders retires orders whose clients never came back, and the
// authorizations under them. An order that already produced a certificate is
// left alone: its expires_at governed how long there was to finalize, not how
// long the certificate is good for.
func (r Repository) ExpireOrders(ctx context.Context, orgID string) (int64, error) {
	exec := database.Executable(ctx, r.db)
	res, err := table.AcmeOrder.UPDATE().SET(table.AcmeOrder.Status.SET(postgres.String(StatusInvalid)),
		table.AcmeOrder.ErrorType.SET(postgres.String(ProblemMalformed)),
		table.AcmeOrder.ErrorDetail.SET(postgres.String("the order expired before it was finalized")),
		table.AcmeOrder.UpdatedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.AcmeOrder.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.AcmeOrder.Status.IN(postgres.String(StatusPending), postgres.String(StatusReady))).
			AND(table.AcmeOrder.ExpiresAt.LT(postgres.LOCALTIMESTAMP()))).ExecContext(ctx, exec)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := table.AcmeAuthorization.UPDATE(table.AcmeAuthorization.Status).SET(StatusExpired).
		WHERE(table.AcmeAuthorization.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.AcmeAuthorization.Status.EQ(postgres.String(StatusValid))).
			AND(table.AcmeAuthorization.ExpiresAt.LT(postgres.LOCALTIMESTAMP()))).ExecContext(ctx, exec); err != nil {
		return n, err
	}
	return n, nil
}

func (r Repository) LockOrganization(ctx context.Context, orgID string) error {
	_, err := postgres.SELECT(postgres.Func("pg_advisory_xact_lock",
		postgres.Func("hashtextextended", postgres.String(orgID), postgres.Int(17)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}
