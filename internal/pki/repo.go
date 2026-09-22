package pki

import (
	"context"
	"database/sql"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) Repository {
	return Repository{db: db}
}

func (r Repository) CreateCA(ctx context.Context, ca CertificateAuthority) (string, error) {
	var result struct{ ID string }
	err := table.CertificateAuthority.INSERT(table.CertificateAuthority.OrganizationID, table.CertificateAuthority.ParentID,
		table.CertificateAuthority.Name, table.CertificateAuthority.Type, table.CertificateAuthority.Status,
		table.CertificateAuthority.Subject, table.CertificateAuthority.Algorithm, table.CertificateAuthority.KmsKeyVersion,
		table.CertificateAuthority.CertificatePem, table.CertificateAuthority.ChainPem, table.CertificateAuthority.ExportPosture,
		table.CertificateAuthority.IssuanceEkus, table.CertificateAuthority.NotBefore, table.CertificateAuthority.NotAfter).
		VALUES(ca.OrganizationID, uuidOrNil(ca.ParentID), ca.Name, ca.Type, ca.Status, ca.Subject, ca.Algorithm,
			ca.KMSKeyVersion, ca.CertificatePEM, ca.ChainPEM, ca.ExportPosture, ca.IssuanceEKUs, ca.NotBefore, ca.NotAfter).
		RETURNING(table.CertificateAuthority.ID.AS("ID")).QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.ID, database.QueryError(err)
}

func caStatement() postgres.SelectStatement {
	return postgres.SELECT(table.CertificateAuthority.ID.AS("CertificateAuthority.ID"), table.CertificateAuthority.OrganizationID.AS("CertificateAuthority.OrganizationID"),
		postgres.COALESCE(postgres.CAST(table.CertificateAuthority.ParentID).AS_TEXT(), postgres.String("")).AS("CertificateAuthority.ParentID"),
		table.CertificateAuthority.Name.AS("CertificateAuthority.Name"), table.CertificateAuthority.Type.AS("CertificateAuthority.Type"),
		table.CertificateAuthority.Status.AS("CertificateAuthority.Status"), table.CertificateAuthority.Subject.AS("CertificateAuthority.Subject"),
		table.CertificateAuthority.Algorithm.AS("CertificateAuthority.Algorithm"), table.CertificateAuthority.KmsKeyVersion.AS("CertificateAuthority.KMSKeyVersion"),
		table.CertificateAuthority.CertificatePem.AS("CertificateAuthority.CertificatePEM"), table.CertificateAuthority.ChainPem.AS("CertificateAuthority.ChainPEM"),
		table.CertificateAuthority.ExportPosture.AS("CertificateAuthority.ExportPosture"), table.CertificateAuthority.IssuanceEkus.AS("CertificateAuthority.IssuanceEKUs"),
		table.CertificateAuthority.NotBefore.AS("CertificateAuthority.NotBefore"), table.CertificateAuthority.NotAfter.AS("CertificateAuthority.NotAfter"),
		table.CertificateAuthority.IssuedCount.AS("CertificateAuthority.IssuedCount"), table.CertificateAuthority.LastSignedAt.AS("CertificateAuthority.LastSignedAt"),
		table.CertificateAuthority.CreatedAt.AS("CertificateAuthority.CreatedAt")).FROM(table.CertificateAuthority)
}

func (r Repository) CA(ctx context.Context, orgID, id string) (CertificateAuthority, error) {
	var ca CertificateAuthority
	err := caStatement().WHERE(table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CertificateAuthority.ID.EQ(database.UUID(id))).
		AND(table.CertificateAuthority.Status.NOT_EQ(postgres.String(CAStatusDeleted)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &ca)
	return ca, database.QueryError(err)
}

func (r Repository) RootCA(ctx context.Context, orgID string) (CertificateAuthority, error) {
	var ca CertificateAuthority
	err := caStatement().WHERE(table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CertificateAuthority.Type.EQ(postgres.String(CATypeRoot))).
		AND(table.CertificateAuthority.Status.NOT_EQ(postgres.String(CAStatusDeleted)))).
		ORDER_BY(table.CertificateAuthority.CreatedAt.ASC()).LIMIT(1).
		QueryContext(ctx, database.Queryable(ctx, r.db), &ca)
	return ca, database.QueryError(err)
}

func (r Repository) CAs(ctx context.Context, orgID string) ([]CertificateAuthority, error) {
	var cas []CertificateAuthority
	err := caStatement().WHERE(table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CertificateAuthority.Status.NOT_EQ(postgres.String(CAStatusDeleted)))).
		ORDER_BY(table.CertificateAuthority.Type.DESC(), table.CertificateAuthority.CreatedAt.DESC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &cas)
	return cas, err
}

func (r Repository) UpdateCAStatus(ctx context.Context, orgID, id, status string) error {
	result, err := table.CertificateAuthority.UPDATE(table.CertificateAuthority.Status).SET(status).
		WHERE(table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.CertificateAuthority.ID.EQ(database.UUID(id))).
			AND(table.CertificateAuthority.Status.NOT_EQ(postgres.String(CAStatusDeleted)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repository) MarkCADeleted(ctx context.Context, orgID, id string) error {
	return requireRow(table.CertificateAuthority.UPDATE().SET(table.CertificateAuthority.Status.SET(postgres.String(CAStatusDeleted)),
		table.CertificateAuthority.DeletedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.CertificateAuthority.ID.EQ(database.UUID(id))).
			AND(table.CertificateAuthority.Status.NOT_EQ(postgres.String(CAStatusDeleted)))).
		ExecContext(ctx, database.Executable(ctx, r.db)))
}

// count is COUNT(*) over one table, and it has to be STAR rather than a literal.
//
// It was COUNT(Int(1)), which reads as the familiar COUNT(1) but is not: jet
// renders a literal as a bind parameter, so the statement went out as
// COUNT($1). Postgres has nowhere to infer that parameter's type from and
// refuses the whole statement with "could not determine data type of parameter
// $1" — every caller below, for every organization, every time.
//
// STAR carries no parameter and no type to resolve. Anything counted here must
// stay parameter-free for the same reason.
func (r Repository) count(ctx context.Context, from postgres.ReadableTable, where postgres.BoolExpression) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(postgres.STAR).AS("Count")).FROM(from).WHERE(where).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

func (r Repository) ActiveChildCount(ctx context.Context, orgID, id string) (int, error) {
	return r.count(ctx, table.CertificateAuthority, table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CertificateAuthority.ParentID.EQ(database.UUID(id))).
		AND(table.CertificateAuthority.Status.NOT_EQ(postgres.String(CAStatusDeleted))))
}

// IssuingCACount counts active and inactive issuing CAs. Retired CAs are
// end-of-life and excluded, so rotation's retire-and-replace swap stays flat.
func (r Repository) IssuingCACount(ctx context.Context, orgID string) (int, error) {
	return r.count(ctx, table.CertificateAuthority, table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CertificateAuthority.Type.EQ(postgres.String(CATypeIssuing))).
		AND(table.CertificateAuthority.Status.IN(postgres.String(CAStatusActive), postgres.String(CAStatusInactive))))
}

func (r Repository) EnabledSCEPEndpointCount(ctx context.Context, orgID, caID string) (int, error) {
	return r.count(ctx, table.ScepEndpoint, table.ScepEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.ScepEndpoint.CertificateAuthorityID.EQ(database.UUID(caID))).AND(table.ScepEndpoint.Enabled.IS_TRUE()))
}

func (r Repository) EnabledACMEEndpointCount(ctx context.Context, orgID, caID string) (int, error) {
	return r.count(ctx, table.AcmeEndpoint, table.AcmeEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.AcmeEndpoint.CertificateAuthorityID.EQ(database.UUID(caID))).AND(table.AcmeEndpoint.Enabled.IS_TRUE()))
}

func (r Repository) EnabledESTEndpointCount(ctx context.Context, orgID, caID string) (int, error) {
	return r.count(ctx, table.EstEndpoint, table.EstEndpoint.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.EstEndpoint.CertificateAuthorityID.EQ(database.UUID(caID))).AND(table.EstEndpoint.Enabled.IS_TRUE()))
}

func (r Repository) RecordCertificate(ctx context.Context, cert Certificate) (string, error) {
	var result struct{ ID string }
	err := table.Certificate.INSERT(table.Certificate.OrganizationID, table.Certificate.CertificateAuthorityID,
		table.Certificate.Serial, table.Certificate.Subject, table.Certificate.Sans, table.Certificate.Status,
		table.Certificate.Profile, table.Certificate.Ekus, table.Certificate.CsrDigest, table.Certificate.CertificatePem,
		table.Certificate.ChainPem, table.Certificate.IssuedAt, table.Certificate.ExpiresAt).
		VALUES(cert.OrganizationID, cert.CAID, cert.Serial, cert.Subject, cert.SANs, cert.Status, cert.Profile,
			cert.EKUs, cert.CSRDigest, cert.CertificatePEM, cert.ChainPEM, cert.IssuedAt, cert.ExpiresAt).
		RETURNING(table.Certificate.ID.AS("ID")).QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.ID, database.QueryError(err)
}

func certificateStatement() postgres.SelectStatement {
	return postgres.SELECT(table.Certificate.ID.AS("Certificate.ID"), table.Certificate.OrganizationID.AS("Certificate.OrganizationID"),
		table.Certificate.CertificateAuthorityID.AS("Certificate.CAID"), table.CertificateAuthority.Name.AS("Certificate.CAName"),
		table.Certificate.Serial.AS("Certificate.Serial"), table.Certificate.Subject.AS("Certificate.Subject"), table.Certificate.Sans.AS("Certificate.SANs"),
		table.Certificate.Status.AS("Certificate.Status"), table.Certificate.Profile.AS("Certificate.Profile"), table.Certificate.Ekus.AS("Certificate.EKUs"),
		table.Certificate.CsrDigest.AS("Certificate.CSRDigest"), table.Certificate.CertificatePem.AS("Certificate.CertificatePEM"),
		table.Certificate.ChainPem.AS("Certificate.ChainPEM"), table.Certificate.IssuedAt.AS("Certificate.IssuedAt"),
		table.Certificate.RevokedAt.AS("Certificate.RevokedAt"), table.Certificate.ExpiresAt.AS("Certificate.ExpiresAt")).
		FROM(table.Certificate.INNER_JOIN(table.CertificateAuthority,
			table.CertificateAuthority.ID.EQ(table.Certificate.CertificateAuthorityID)))
}

func (r Repository) Certificate(ctx context.Context, orgID, id string) (Certificate, error) {
	var cert Certificate
	err := certificateStatement().WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.Certificate.ID.EQ(database.UUID(id)))).QueryContext(ctx, database.Queryable(ctx, r.db), &cert)
	return cert, database.QueryError(err)
}

func (r Repository) Certificates(ctx context.Context, orgID string) ([]Certificate, error) {
	var certs []Certificate
	err := certificateStatement().WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(table.Certificate.IssuedAt.DESC()).QueryContext(ctx, database.Queryable(ctx, r.db), &certs)
	return certs, err
}

func (r Repository) CertificateBySerial(ctx context.Context, orgID, caID, serial string) (Certificate, error) {
	var cert Certificate
	err := certificateStatement().WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.Certificate.CertificateAuthorityID.EQ(database.UUID(caID))).
		AND(postgres.LOWER(table.Certificate.Serial).EQ(postgres.LOWER(postgres.String(serial))))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &cert)
	return cert, database.QueryError(err)
}

// revocationRow is deliberately an alias to an anonymous struct, and this is
// the one destination in the package that cannot use the "Type.Field" alias
// prefix the others do.
//
// Revocation embeds Certificate. go-jet does not flatten an embedded struct
// into its parent for column mapping — it reads it as a nested relation to
// populate, finds nothing addressed to it, and leaves the whole embedded value
// zero while cheerfully filling Reason and returning a nil error. Neither
// "Revocation.Serial" nor "Certificate.Serial" reaches it; measured both.
//
// So the row is scanned flat and assembled in Go. What that was costing: every
// revoked certificate came back with an empty serial and an empty PEM, and
// Revocations is what CRL generation and the revocation page are built from.
type revocationRow = struct {
	ID             string
	OrganizationID string
	CAID           string
	CAName         string
	Serial         string
	Subject        string
	SANs           string
	Status         string
	Profile        string
	EKUs           string
	CSRDigest      string
	CertificatePEM string
	ChainPEM       string
	IssuedAt       time.Time
	RevokedAt      *time.Time
	ExpiresAt      time.Time
	Reason         string
}

func (r Repository) Revocations(ctx context.Context, orgID string) ([]Revocation, error) {
	var rows []revocationRow
	err := postgres.SELECT(table.Certificate.ID.AS("ID"), table.Certificate.OrganizationID.AS("OrganizationID"),
		table.Certificate.CertificateAuthorityID.AS("CAID"), table.CertificateAuthority.Name.AS("CAName"),
		table.Certificate.Serial.AS("Serial"), table.Certificate.Subject.AS("Subject"), table.Certificate.Sans.AS("SANs"),
		table.Certificate.Status.AS("Status"), table.Certificate.Profile.AS("Profile"), table.Certificate.Ekus.AS("EKUs"),
		table.Certificate.CsrDigest.AS("CSRDigest"), table.Certificate.CertificatePem.AS("CertificatePEM"),
		table.Certificate.ChainPem.AS("ChainPEM"), table.Certificate.IssuedAt.AS("IssuedAt"),
		table.Certificate.RevokedAt.AS("RevokedAt"), table.Certificate.ExpiresAt.AS("ExpiresAt"),
		table.CertificateRevocation.Reason.AS("Reason")).
		FROM(table.Certificate.INNER_JOIN(table.CertificateAuthority,
			table.CertificateAuthority.ID.EQ(table.Certificate.CertificateAuthorityID)).
			INNER_JOIN(table.CertificateRevocation, table.CertificateRevocation.CertificateID.EQ(table.Certificate.ID))).
		WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.Certificate.Status.EQ(postgres.String(CertStatusRevoked)))).
		ORDER_BY(table.Certificate.RevokedAt.DESC()).QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return nil, err
	}
	out := make([]Revocation, 0, len(rows))
	for _, row := range rows {
		out = append(out, Revocation{
			Certificate: Certificate{
				ID: row.ID, OrganizationID: row.OrganizationID, CAID: row.CAID, CAName: row.CAName,
				Serial: row.Serial, Subject: row.Subject, SANs: row.SANs, Status: row.Status,
				Profile: row.Profile, EKUs: row.EKUs, CSRDigest: row.CSRDigest,
				CertificatePEM: row.CertificatePEM, ChainPEM: row.ChainPEM,
				IssuedAt: row.IssuedAt, RevokedAt: row.RevokedAt, ExpiresAt: row.ExpiresAt,
			},
			Reason: row.Reason,
		})
	}
	return out, nil
}

func (r Repository) CRLPublication(ctx context.Context, orgID, caID string) (CRLPublication, error) {
	var p CRLPublication
	err := postgres.SELECT(table.CrlPublication.OrganizationID.AS("CRLPublication.OrganizationID"),
		table.CrlPublication.CertificateAuthorityID.AS("CRLPublication.CAID"), table.CrlPublication.CrlDer.AS("CRLPublication.DER"),
		table.CrlPublication.CrlNumber.AS("CRLPublication.Number"), table.CrlPublication.ThisUpdate.AS("CRLPublication.ThisUpdate"),
		table.CrlPublication.NextUpdate.AS("CRLPublication.NextUpdate"), table.CrlPublication.PublishedAt.AS("CRLPublication.PublishedAt"),
		table.CrlPublication.LastAttemptAt.AS("CRLPublication.LastAttemptAt"), table.CrlPublication.LastError.AS("CRLPublication.LastError")).
		FROM(table.CrlPublication).WHERE(table.CrlPublication.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CrlPublication.CertificateAuthorityID.EQ(database.UUID(caID)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &p)
	return p, database.QueryError(err)
}

func (r Repository) LockCRL(ctx context.Context, caID string) error {
	_, err := postgres.SELECT(postgres.Func("pg_advisory_xact_lock",
		postgres.Func("hashtextextended", postgres.String(caID), postgres.Int(0)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) SaveCRL(ctx context.Context, p CRLPublication) error {
	_, err := table.CrlPublication.INSERT(table.CrlPublication.OrganizationID,
		table.CrlPublication.CertificateAuthorityID, table.CrlPublication.CrlDer, table.CrlPublication.CrlNumber,
		table.CrlPublication.ThisUpdate, table.CrlPublication.NextUpdate, table.CrlPublication.PublishedAt,
		table.CrlPublication.LastAttemptAt, table.CrlPublication.LastError).
		VALUES(p.OrganizationID, p.CAID, p.DER, p.Number, p.ThisUpdate, p.NextUpdate,
			postgres.LOCALTIMESTAMP(), postgres.LOCALTIMESTAMP(), "").
		ON_CONFLICT(table.CrlPublication.CertificateAuthorityID).
		DO_UPDATE(postgres.SET(table.CrlPublication.CrlDer.SET(table.CrlPublication.EXCLUDED.CrlDer),
			table.CrlPublication.CrlNumber.SET(table.CrlPublication.EXCLUDED.CrlNumber),
			table.CrlPublication.ThisUpdate.SET(table.CrlPublication.EXCLUDED.ThisUpdate),
			table.CrlPublication.NextUpdate.SET(table.CrlPublication.EXCLUDED.NextUpdate),
			table.CrlPublication.PublishedAt.SET(postgres.LOCALTIMESTAMP()),
			table.CrlPublication.LastAttemptAt.SET(postgres.LOCALTIMESTAMP()),
			table.CrlPublication.LastError.SET(postgres.String("")))).ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) SaveCRLError(ctx context.Context, orgID, caID, message string) error {
	_, err := table.CrlPublication.INSERT(table.CrlPublication.OrganizationID,
		table.CrlPublication.CertificateAuthorityID, table.CrlPublication.LastAttemptAt, table.CrlPublication.LastError).
		VALUES(orgID, caID, postgres.LOCALTIMESTAMP(), message).
		ON_CONFLICT(table.CrlPublication.CertificateAuthorityID).
		DO_UPDATE(postgres.SET(table.CrlPublication.LastAttemptAt.SET(postgres.LOCALTIMESTAMP()),
			table.CrlPublication.LastError.SET(table.CrlPublication.EXCLUDED.LastError))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func (r Repository) CachedOCSP(ctx context.Context, orgID, caID, serial string, hash int, status string, now time.Time) (OCSPCacheEntry, error) {
	var e OCSPCacheEntry
	err := postgres.SELECT(table.OcspResponseCache.ResponseDer.AS("OCSPCacheEntry.DER"),
		table.OcspResponseCache.CertificateStatus.AS("OCSPCacheEntry.Status"), table.OcspResponseCache.ThisUpdate.AS("OCSPCacheEntry.ThisUpdate"),
		table.OcspResponseCache.NextUpdate.AS("OCSPCacheEntry.NextUpdate")).FROM(table.OcspResponseCache).
		WHERE(table.OcspResponseCache.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.OcspResponseCache.CertificateAuthorityID.EQ(database.UUID(caID))).
			AND(postgres.LOWER(table.OcspResponseCache.Serial).EQ(postgres.LOWER(postgres.String(serial)))).
			AND(table.OcspResponseCache.HashAlgorithm.EQ(postgres.Int(int64(hash)))).
			AND(table.OcspResponseCache.CertificateStatus.EQ(postgres.String(status))).
			AND(table.OcspResponseCache.NextUpdate.GT(postgres.TimestampT(now)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &e)
	return e, database.QueryError(err)
}

func (r Repository) SaveOCSP(ctx context.Context, orgID, caID, serial string, hash int, e OCSPCacheEntry) error {
	_, err := table.OcspResponseCache.INSERT(table.OcspResponseCache.OrganizationID,
		table.OcspResponseCache.CertificateAuthorityID, table.OcspResponseCache.Serial,
		table.OcspResponseCache.HashAlgorithm, table.OcspResponseCache.CertificateStatus,
		table.OcspResponseCache.ResponseDer, table.OcspResponseCache.ThisUpdate, table.OcspResponseCache.NextUpdate).
		VALUES(orgID, caID, serial, hash, e.Status, e.DER, e.ThisUpdate, e.NextUpdate).
		ON_CONFLICT(table.OcspResponseCache.CertificateAuthorityID, table.OcspResponseCache.Serial,
			table.OcspResponseCache.HashAlgorithm).
		DO_UPDATE(postgres.SET(table.OcspResponseCache.CertificateStatus.SET(table.OcspResponseCache.EXCLUDED.CertificateStatus),
			table.OcspResponseCache.ResponseDer.SET(table.OcspResponseCache.EXCLUDED.ResponseDer),
			table.OcspResponseCache.ThisUpdate.SET(table.OcspResponseCache.EXCLUDED.ThisUpdate),
			table.OcspResponseCache.NextUpdate.SET(table.OcspResponseCache.EXCLUDED.NextUpdate))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// RevokeCertificate flips an issued certificate to revoked and records the
// reason. Revoking an already-revoked (or unknown) certificate returns
// sql.ErrNoRows.
func (r Repository) RevokeCertificate(ctx context.Context, orgID, id, reason string) error {
	if err := requireRow(table.Certificate.UPDATE().SET(table.Certificate.Status.SET(postgres.String(CertStatusRevoked)),
		table.Certificate.RevokedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID)).AND(table.Certificate.ID.EQ(database.UUID(id))).
			AND(table.Certificate.Status.EQ(postgres.String(CertStatusIssued)))).
		ExecContext(ctx, database.Executable(ctx, r.db))); err != nil {
		return err
	}
	_, err := table.CertificateRevocation.INSERT(table.CertificateRevocation.OrganizationID,
		table.CertificateRevocation.CertificateID, table.CertificateRevocation.Reason).
		VALUES(orgID, id, reason).ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	serial := postgres.SELECT(table.Certificate.Serial).FROM(table.Certificate).
		WHERE(table.Certificate.ID.EQ(database.UUID(id)))
	_, err = table.OcspResponseCache.DELETE().WHERE(table.OcspResponseCache.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.OcspResponseCache.Serial.EQ(postgres.StringExp(serial)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// identityExpression identifies what a certificate was issued to. Subject-less
// certificates fall back to their own row so each is counted separately.
//
// The empty string is RawString("”") rather than String(""), and that is not a
// style choice. String("") renders as a placeholder, and jet serialises this
// expression afresh at every position it appears in — so a statement that both
// selects and groups by it emits $1 in the select list and $5 in the GROUP BY.
// Postgres compares grouping expressions structurally and two distinct
// parameter nodes are not equal, so it rejects the whole statement with
// "column certificate.subject must appear in the GROUP BY clause".
//
// This is nastier to find than it sounds. DebugSql() inlines both parameters as
// ”::text, which makes them identical, so the debug output is valid SQL and
// pasting it into psql runs clean — the failure exists only in the
// parameterised form actually sent. A raw literal renders as the same text
// everywhere and the expressions match.
func identityExpression() postgres.StringExpression {
	return postgres.StringExp(postgres.COALESCE(
		postgres.StringExp(postgres.NULLIF(table.Certificate.Subject, postgres.RawString("''"))),
		postgres.CAST(table.Certificate.ID).AS_TEXT(),
	))
}

func liveCertificateCondition(orgID string) postgres.BoolExpression {
	return table.Certificate.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.Certificate.Status.EQ(postgres.String(CertStatusIssued))).
		AND(table.Certificate.ExpiresAt.GT(postgres.LOCALTIMESTAMP())).
		AND(table.Certificate.Profile.NOT_EQ(postgres.String(CertProfileInfrastructure)))
}

// ActiveIdentityCount reports distinct identities with a live certificate.
func (r Repository) ActiveIdentityCount(ctx context.Context, orgID string) (int, error) {
	var result struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(postgres.DISTINCT(identityExpression())).AS("Count")).FROM(table.Certificate).
		WHERE(liveCertificateCondition(orgID)).QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.Count, err
}

// ExpiringIdentityCount counts identities whose last certificate lapses within
// the given number of days. An identity that has already been renewed holds a
// certificate beyond the window and is not reported: the renewal is what the
// administrator would have been asked to do about it.
func (r Repository) ExpiringIdentityCount(ctx context.Context, orgID string, days int) (int, error) {
	identity := identityExpression()
	var identities []struct{ Identity string }
	err := postgres.SELECT(identity.AS("Identity")).FROM(table.Certificate).
		WHERE(liveCertificateCondition(orgID)).GROUP_BY(identity).
		HAVING(postgres.TimestampExp(postgres.MAX(table.Certificate.ExpiresAt)).LT_EQ(
			postgres.LOCALTIMESTAMP().ADD(postgres.INTERVAL(float64(days), postgres.DAY)))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &identities)
	return len(identities), err
}

// ExpiringCertificate is one certificate an alert would name.
type ExpiringCertificate struct {
	ID        string
	Subject   string
	Serial    string
	CAName    string
	ExpiresAt time.Time
}

// ExpiringCertificates lists live certificates lapsing within days that have not
// already been alerted on.
//
// It returns certificates rather than the identities ExpiringIdentityCount
// counts, and the difference is deliberate. The count answers "how much of the
// active identity count is about to fall", where a renewed identity is not interesting.
// An alert answers "what is about to stop working", and that is a specific
// certificate on a specific device, named by serial so the recipient can find
// it.
//
// expiry_notified_at is what stops the same certificate being named every day
// for the whole window.
func (r Repository) ExpiringCertificates(ctx context.Context, orgID string, days int) ([]ExpiringCertificate, error) {
	cutoff := postgres.LOCALTIMESTAMP().ADD(postgres.INTERVAL(float64(days), postgres.DAY))
	// Scanned into an anonymous struct: naming the type makes the mapper try to
	// resolve it against a table in the result set and quietly return nothing.
	var rows []struct {
		ID        string
		Subject   string
		Serial    string
		CAName    string
		ExpiresAt time.Time
	}
	err := postgres.SELECT(
		postgres.CAST(table.Certificate.ID).AS_TEXT().AS("ID"),
		table.Certificate.Subject.AS("Subject"),
		table.Certificate.Serial.AS("Serial"),
		postgres.COALESCE(table.CertificateAuthority.Name, postgres.String("")).AS("CAName"),
		table.Certificate.ExpiresAt.AS("ExpiresAt"),
	).FROM(table.Certificate.
		LEFT_JOIN(table.CertificateAuthority, table.CertificateAuthority.ID.EQ(table.Certificate.CertificateAuthorityID))).
		WHERE(liveCertificateCondition(orgID).
			AND(postgres.TimestampExp(table.Certificate.ExpiresAt).LT_EQ(cutoff)).
			AND(table.Certificate.ExpiryNotifiedAt.IS_NULL())).
		ORDER_BY(table.Certificate.ExpiresAt.ASC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return nil, database.QueryError(err)
	}
	out := make([]ExpiringCertificate, 0, len(rows))
	for _, row := range rows {
		out = append(out, ExpiringCertificate(row))
	}
	return out, nil
}

// MarkExpiryNotified stamps the certificates an alert named, so the next sweep
// passes over them.
//
// Called after the mail is accepted, never before. The other order loses an
// alert entirely whenever the provider is down, and a missed expiry warning is
// the failure this whole feature exists to prevent — a duplicate is merely
// annoying.
func (r Repository) MarkExpiryNotified(ctx context.Context, orgID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	values := make([]postgres.Expression, 0, len(ids))
	for _, id := range ids {
		values = append(values, database.UUID(id))
	}
	_, err := table.Certificate.UPDATE(table.Certificate.ExpiryNotifiedAt).
		SET(postgres.NOW()).
		WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.Certificate.ID.IN(values...))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return database.QueryError(err)
}

// ExpiryAlertSettings is an organization's alert preference.
type ExpiryAlertSettings struct {
	Enabled bool
	Days    int32
	Name    string
}

func (r Repository) ExpiryAlertSettings(ctx context.Context, orgID string) (ExpiryAlertSettings, error) {
	var rows []struct {
		Enabled bool
		Days    int32
		Name    string
	}
	err := postgres.SELECT(
		table.Organization.ExpiryAlertsEnabled.AS("Enabled"),
		table.Organization.ExpiryAlertDays.AS("Days"),
		table.Organization.Name.AS("Name"),
	).FROM(table.Organization).
		WHERE(table.Organization.ID.EQ(database.UUID(orgID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return ExpiryAlertSettings{}, database.QueryError(err)
	}
	if len(rows) == 0 {
		return ExpiryAlertSettings{}, sql.ErrNoRows
	}
	return ExpiryAlertSettings(rows[0]), nil
}

// SetExpiryAlerts stores the preference from the account settings dialog.
func (r Repository) SetExpiryAlerts(ctx context.Context, orgID string, enabled bool, days int) error {
	_, err := table.Organization.UPDATE(
		table.Organization.ExpiryAlertsEnabled, table.Organization.ExpiryAlertDays).
		SET(postgres.Bool(enabled), postgres.Int(int64(days))).
		WHERE(table.Organization.ID.EQ(database.UUID(orgID))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return database.QueryError(err)
}

// AlertRecipients is who an alert goes to: the organization's administrators.
//
// Not every member. An alert usually needs an administrator to coordinate a
// renewal or CA change; sending it
// to everyone is how a notification becomes something the whole team filters.
func (r Repository) AlertRecipients(ctx context.Context, orgID string) ([]string, error) {
	var rows []struct{ Email string }
	err := postgres.SELECT(table.User.Email.AS("Email")).FROM(table.User).
		WHERE(table.User.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.User.Role.EQ(postgres.String("administrator")))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return nil, database.QueryError(err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Email != "" {
			out = append(out, row.Email)
		}
	}
	return out, nil
}

func (r Repository) RecordSigning(ctx context.Context, orgID, caID, userID, keyVersion, csrDigest, serial, purpose string) error {
	_, err := table.CertificateSigningAudit.INSERT(table.CertificateSigningAudit.OrganizationID,
		table.CertificateSigningAudit.CertificateAuthorityID, table.CertificateSigningAudit.RequesterUserID,
		table.CertificateSigningAudit.KmsKeyVersion, table.CertificateSigningAudit.CsrDigest,
		table.CertificateSigningAudit.CertificateSerial, table.CertificateSigningAudit.Purpose).
		VALUES(orgID, caID, uuidOrNil(userID), keyVersion, csrDigest, serial, purpose).
		ExecContext(ctx, database.Executable(ctx, r.db))
	if err != nil {
		return err
	}
	_, err = table.CertificateAuthority.UPDATE().SET(
		table.CertificateAuthority.IssuedCount.SET(table.CertificateAuthority.IssuedCount.ADD(postgres.Int64(1))),
		table.CertificateAuthority.LastSignedAt.SET(postgres.LOCALTIMESTAMP())).
		WHERE(table.CertificateAuthority.ID.EQ(database.UUID(caID)).
			AND(table.CertificateAuthority.OrganizationID.EQ(database.UUID(orgID)))).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// RecordCAEvent writes an audit row for a CA lifecycle event (e.g. deletion)
// without touching the CA's signing counters.
func (r Repository) RecordCAEvent(ctx context.Context, orgID, caID, userID, keyVersion, purpose string) error {
	_, err := table.CertificateSigningAudit.INSERT(table.CertificateSigningAudit.OrganizationID,
		table.CertificateSigningAudit.CertificateAuthorityID, table.CertificateSigningAudit.RequesterUserID,
		table.CertificateSigningAudit.KmsKeyVersion, table.CertificateSigningAudit.CsrDigest,
		table.CertificateSigningAudit.CertificateSerial, table.CertificateSigningAudit.Purpose).
		VALUES(orgID, caID, uuidOrNil(userID), keyVersion, "", "", purpose).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

func caImportJobStatement() postgres.SelectStatement {
	return postgres.SELECT(table.CaImportJob.ID.AS("CAImportJob.ID"), table.CaImportJob.OrganizationID.AS("CAImportJob.OrganizationID"),
		postgres.COALESCE(postgres.CAST(table.CaImportJob.CreatedBy).AS_TEXT(), postgres.String("")).AS("CAImportJob.CreatedBy"),
		table.CaImportJob.CaName.AS("CAImportJob.CAName"), table.CaImportJob.CaType.AS("CAImportJob.CAType"),
		table.CaImportJob.Algorithm.AS("CAImportJob.Algorithm"), table.CaImportJob.CertificatePem.AS("CAImportJob.CertificatePEM"),
		table.CaImportJob.ChainPem.AS("CAImportJob.ChainPEM"), table.CaImportJob.KmsImportJob.AS("CAImportJob.KMSImportJob"),
		table.CaImportJob.KmsCryptoKey.AS("CAImportJob.KMSCryptoKey"), table.CaImportJob.KmsKeyVersion.AS("CAImportJob.KMSKeyVersion"),
		table.CaImportJob.WrappingMethod.AS("CAImportJob.WrappingMethod"), table.CaImportJob.WrappingPublicKeyPem.AS("CAImportJob.WrappingPublicKeyPEM"),
		table.CaImportJob.State.AS("CAImportJob.State"), table.CaImportJob.FailureReason.AS("CAImportJob.FailureReason"),
		postgres.COALESCE(postgres.CAST(table.CaImportJob.CertificateAuthorityID).AS_TEXT(), postgres.String("")).AS("CAImportJob.CertificateAuthorityID"),
		table.CaImportJob.ExpiresAt.AS("CAImportJob.ExpiresAt"), table.CaImportJob.CreatedAt.AS("CAImportJob.CreatedAt")).FROM(table.CaImportJob)
}

func (r Repository) CreateCAImportJob(ctx context.Context, job CAImportJob) (string, error) {
	var result struct{ ID string }
	err := table.CaImportJob.INSERT(table.CaImportJob.OrganizationID, table.CaImportJob.CreatedBy,
		table.CaImportJob.CaName, table.CaImportJob.CaType, table.CaImportJob.Algorithm,
		table.CaImportJob.CertificatePem, table.CaImportJob.ChainPem, table.CaImportJob.KmsImportJob,
		table.CaImportJob.KmsCryptoKey, table.CaImportJob.WrappingMethod,
		table.CaImportJob.WrappingPublicKeyPem, table.CaImportJob.State, table.CaImportJob.ExpiresAt).
		VALUES(job.OrganizationID, uuidOrNil(job.CreatedBy), job.CAName, job.CAType, job.Algorithm,
			job.CertificatePEM, job.ChainPEM, job.KMSImportJob, job.KMSCryptoKey, job.WrappingMethod,
			job.WrappingPublicKeyPEM, job.State, job.ExpiresAt).RETURNING(table.CaImportJob.ID.AS("ID")).
		QueryContext(ctx, database.Queryable(ctx, r.db), &result)
	return result.ID, database.QueryError(err)
}

func (r Repository) CAImportJob(ctx context.Context, orgID, id string) (CAImportJob, error) {
	var job CAImportJob
	err := caImportJobStatement().WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CaImportJob.ID.EQ(database.UUID(id)))).QueryContext(ctx, database.Queryable(ctx, r.db), &job)
	return job, database.QueryError(err)
}

func (r Repository) CAImportJobs(ctx context.Context, orgID string) ([]CAImportJob, error) {
	var jobs []CAImportJob
	err := caImportJobStatement().WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID))).
		ORDER_BY(table.CaImportJob.CreatedAt.DESC()).QueryContext(ctx, database.Queryable(ctx, r.db), &jobs)
	return jobs, err
}

func (r Repository) UpdateCAImportJobState(ctx context.Context, orgID, id, state, failureReason string) error {
	return requireRow(table.CaImportJob.UPDATE(table.CaImportJob.State, table.CaImportJob.FailureReason).
		SET(state, failureReason).WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CaImportJob.ID.EQ(database.UUID(id)))).ExecContext(ctx, database.Executable(ctx, r.db)))
}

func (r Repository) SetCAImportJobWrapping(ctx context.Context, orgID, id, state, wrappingPEM, method string, expiresAt time.Time) error {
	return requireRow(table.CaImportJob.UPDATE(table.CaImportJob.State, table.CaImportJob.WrappingPublicKeyPem,
		table.CaImportJob.WrappingMethod, table.CaImportJob.ExpiresAt).SET(state, wrappingPEM, method, expiresAt).
		WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID)).AND(table.CaImportJob.ID.EQ(database.UUID(id)))).
		ExecContext(ctx, database.Executable(ctx, r.db)))
}

func (r Repository) SetCAImportJobKeyVersion(ctx context.Context, orgID, id, keyVersion string) error {
	return requireRow(table.CaImportJob.UPDATE(table.CaImportJob.KmsKeyVersion, table.CaImportJob.State).
		SET(keyVersion, ImportStateImporting).WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CaImportJob.ID.EQ(database.UUID(id)))).ExecContext(ctx, database.Executable(ctx, r.db)))
}

func (r Repository) CancelCAImportJob(ctx context.Context, orgID, id, userID string) error {
	return requireRow(table.CaImportJob.UPDATE(table.CaImportJob.State, table.CaImportJob.FailureReason,
		table.CaImportJob.CancelledBy).SET("cancelled", "", uuidOrNil(userID)).
		WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID)).AND(table.CaImportJob.ID.EQ(database.UUID(id)))).
		ExecContext(ctx, database.Executable(ctx, r.db)))
}

func (r Repository) CompleteCAImportJob(ctx context.Context, orgID, id, caID string) error {
	return requireRow(table.CaImportJob.UPDATE(table.CaImportJob.State, table.CaImportJob.CertificateAuthorityID).
		SET(ImportStateCompleted, uuidOrNil(caID)).WHERE(table.CaImportJob.OrganizationID.EQ(database.UUID(orgID)).
		AND(table.CaImportJob.ID.EQ(database.UUID(id)))).ExecContext(ctx, database.Executable(ctx, r.db)))
}

func requireRow(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func uuidOrNil(id string) any {
	if id == "" {
		return nil
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil
	}
	return parsed
}

// clockSkew backdates notBefore so a client whose clock runs a little fast does
// not reject a certificate it was just issued. Device clocks drift, and a phone
// that has not yet synced NTP after a reboot is the common case; the failure it
// produces — "certificate not yet valid" seconds after enrolment — is one of the
// least obvious a fleet can hit.
//
// notAfter is deliberately not extended to match: that would quietly lengthen
// validity past the requested policy and past the issuer's own clamp.
const clockSkew = 5 * time.Minute

func DaysFromNow(days int) (time.Time, time.Time) {
	now := time.Now().UTC()
	return now.Add(-clockSkew), now.Add(time.Duration(days) * 24 * time.Hour)
}

// EnrollmentDay is one day's issuance for one enrollment method. Days on which
// a method issued nothing are absent rather than zero — the caller lays these
// rows onto a complete axis, and a day with no certificates at all produces no
// row here either.
type EnrollmentDay struct {
	Day     time.Time
	Profile string
	Count   int
}

// EnrollmentsByProfile counts certificates issued per day per enrollment
// method, from since to now.
//
// It counts issuance as it happened rather than what is live today: revoked and
// expired certificates are included, because a graph of the past whose bars move
// after the fact is not a record of anything. That is the opposite of
// ActiveIdentityCount above, which answers "how many identities are currently
// active" and must therefore only see live certificates. Infrastructure
// certificates are excluded for the reason they are excluded everywhere else —
// SimpleSCEP issued them to itself, and nobody enrolled anything.
//
// Certificates are counted, not identities: a renewal is an enrollment that
// happened, even though it creates no new identity.
func (r Repository) EnrollmentsByProfile(ctx context.Context, orgID string, since time.Time) ([]EnrollmentDay, error) {
	// The day bucket is a raw expression rather than jet's DATE_TRUNC with a
	// String("day") argument, and it has to be, for the reason set out at
	// identityExpression: jet renders a literal as a bind parameter and
	// serialises this expression afresh at each position, so the select list
	// would carry DATE_TRUNC($1, …) and the GROUP BY DATE_TRUNC($4, …).
	// Postgres compares grouping expressions structurally, two parameter nodes
	// are never equal, and it rejects the statement outright. A raw literal
	// renders as the same text in both places.
	day := postgres.RawTimestamp("DATE_TRUNC('day', certificate.issued_at)")
	// Anonymous struct with bare aliases: a named destination type sends the
	// mapper looking for "enrollmentday.day" and it silently returns nothing.
	// See internal/database/jetmapping_test.go, which fails on the other shape.
	var rows []struct {
		Day     time.Time
		Profile string
		Count   int
	}
	err := postgres.SELECT(day.AS("Day"), table.Certificate.Profile.AS("Profile"),
		postgres.COUNT(postgres.STAR).AS("Count")).
		FROM(table.Certificate).
		WHERE(table.Certificate.OrganizationID.EQ(database.UUID(orgID)).
			AND(table.Certificate.Profile.NOT_EQ(postgres.String(CertProfileInfrastructure))).
			AND(table.Certificate.IssuedAt.GT_EQ(postgres.TimestampT(since)))).
		GROUP_BY(day, table.Certificate.Profile).
		ORDER_BY(day.ASC()).
		QueryContext(ctx, database.Queryable(ctx, r.db), &rows)
	if err != nil {
		return nil, database.QueryError(err)
	}
	out := make([]EnrollmentDay, 0, len(rows))
	for _, row := range rows {
		out = append(out, EnrollmentDay(row))
	}
	return out, nil
}
