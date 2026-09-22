package audit

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/jacksongrow0/SimpleSCEP/.jet/simplescep/public/table"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) Repository {
	return Repository{db: db}
}

// Record writes one event. Recording is never allowed to fail the action it
// describes — a role change that succeeded has succeeded whether or not the log
// row landed — so callers log the error and carry on rather than reporting it
// against the change. Each package wraps this in its own record helper that
// does exactly that.
func (r Repository) Record(ctx context.Context, e Event) error {
	_, err := table.AuditEvent.INSERT(table.AuditEvent.OrganizationID, table.AuditEvent.ActorUserID,
		table.AuditEvent.ActorEmail, table.AuditEvent.Action, table.AuditEvent.Target, table.AuditEvent.Detail,
		table.AuditEvent.ActorIP, table.AuditEvent.ActorUserAgent, table.AuditEvent.ActorSessionID).
		VALUES(e.OrganizationID, actorID(e.ActorUserID), e.ActorEmail, e.Action, e.Target, e.Detail,
			e.ActorIP, truncate(e.ActorUserAgent, maxUserAgent), e.ActorSessionID).
		ExecContext(ctx, database.Executable(ctx, r.db))
	return err
}

// maxUserAgent bounds the stored user agent. It is attacker-controlled and
// unbounded on the wire, and an audit row is not the place to find that out.
const maxUserAgent = 500

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// defaultEventLimit bounds a read that asked for no limit of its own, so no
// caller can accidentally pull an organization's entire history into memory.
// The export sets its own, higher, cap.
const defaultEventLimit = 200

// Events returns the organization's log, newest first, narrowed by filter.
//
// The log is two tables — certificate_signing_audit and audit_event — merged
// here rather than in SQL, and that is what makes paging it more than a matter
// of adding OFFSET. An OFFSET pushed down into each query would skip rows within
// that table, not within the merged log: with 30 signing rows and 30 ordinary
// rows interleaved, page two of a 50-row page would ask each side to skip 50 of
// its own 30 and come back empty, and any narrower offset would step over rows
// the other side had not yet contributed. Both symptoms are silent — the page
// renders, the rows are simply not the right ones.
//
// So both sides are read to the same depth, offset+limit, and the skip is taken
// after the merge. That is correct rather than merely conservative: the first
// offset+limit events of the union can only be drawn from the first offset+limit
// of either side, because an event ranked above them in the merge is ranked
// above them in its own table too.
//
// The cost is that a deep page reads offset+limit rows from each table to return
// limit of them. Callers bound how deep a page may be; the CSV export is the way
// to take the whole log.
func (r Repository) Events(ctx context.Context, orgID string, f Filter) ([]Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultEventLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	depth := offset + limit
	signing, err := r.signingEvents(ctx, orgID, f, depth)
	if err != nil {
		return nil, err
	}
	ordinary, err := r.auditEvents(ctx, orgID, f, depth)
	if err != nil {
		return nil, err
	}
	out := mergePage(signing, ordinary, offset, limit)
	for i := range out {
		e := &out[i]
		e.OrganizationID = orgID
	}
	return out, nil
}

// mergePage interleaves the two sources into one ordered page. Split out from
// Events because it is the part with an argument to get wrong and the only part
// that can be checked without a database.
//
// Ordered by instant, then by id to break ties. The tiebreak is not decoration
// once these are pages: two events sharing an instant that sorted differently
// between two requests would appear on both pages or on neither, and each
// source query carries the same tiebreak in its own ORDER BY for the same
// reason.
func mergePage(signing, ordinary []Event, offset, limit int) []Event {
	out := append(signing, ordinary...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID > out[j].ID
	})
	if offset >= len(out) {
		return nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// CountMatching is how many events the filter selects, which is what the page
// needs to know how many pages there are. Count below answers a different
// question — how much is in the log at all — and the header reports both.
//
// Two counts rather than a count of the merged list, because the merge exists
// only to order the rows and ordering does not change how many there are.
func (r Repository) CountMatching(ctx context.Context, orgID string, f Filter) (int, error) {
	var signing, ordinary struct{ Count int }
	signingActor := postgres.StringExp(postgres.COALESCE(postgres.CAST(table.CertificateSigningAudit.RequesterUserID).AS_TEXT(), postgres.String("")))
	err := postgres.SELECT(postgres.COUNT(table.CertificateSigningAudit.ID).AS("Count")).
		FROM(table.CertificateSigningAudit).
		WHERE(table.CertificateSigningAudit.OrganizationID.EQ(database.UUID(orgID)).
			AND(eventFilter(signingActor, signingAction(), table.CertificateSigningAudit.SignedAt, f))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &signing)
	if err != nil {
		return 0, err
	}
	ordinaryActor := postgres.StringExp(postgres.COALESCE(postgres.CAST(table.AuditEvent.ActorUserID).AS_TEXT(), postgres.String("")))
	err = postgres.SELECT(postgres.COUNT(table.AuditEvent.ID).AS("Count")).FROM(table.AuditEvent).
		WHERE(table.AuditEvent.OrganizationID.EQ(database.UUID(orgID)).
			AND(eventFilter(ordinaryActor, table.AuditEvent.Action, table.AuditEvent.CreatedAt, f))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &ordinary)
	return signing.Count + ordinary.Count, err
}

// Count is how many events the organization has recorded in total, which the
// page reports separately from the filtered page of rows it shows.
func (r Repository) Count(ctx context.Context, orgID string) (int, error) {
	var signing, ordinary struct{ Count int }
	err := postgres.SELECT(postgres.COUNT(table.CertificateSigningAudit.ID).AS("Count")).
		FROM(table.CertificateSigningAudit).
		WHERE(table.CertificateSigningAudit.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &signing)
	if err != nil {
		return 0, err
	}
	err = postgres.SELECT(postgres.COUNT(table.AuditEvent.ID).AS("Count")).FROM(table.AuditEvent).
		WHERE(table.AuditEvent.OrganizationID.EQ(database.UUID(orgID))).
		QueryContext(ctx, database.Queryable(ctx, r.db), &ordinary)
	return signing.Count + ordinary.Count, err
}

// The column aliases below are prefixed with the destination type's name.
// go-jet resolves a field on a named destination struct as "<TypeName>.<Field>",
// so a bare alias like "ID" matches nothing on an []Event; every field then maps
// to no column, the mapper decides the row updated nothing, and the query
// returns zero rows and a nil error rather than an error naming the problem.
// That silence is why this has to stay in step: adding a column here without
// the prefix drops it, and renaming Event's fields without renaming the aliases
// empties the whole audit page.
func (r Repository) signingEvents(ctx context.Context, orgID string, f Filter, limit int) ([]Event, error) {
	actorID := postgres.StringExp(postgres.COALESCE(postgres.CAST(table.CertificateSigningAudit.RequesterUserID).AS_TEXT(), postgres.String("")))
	action := signingAction()
	where := table.CertificateSigningAudit.OrganizationID.EQ(database.UUID(orgID))
	where = where.AND(eventFilter(actorID, action, table.CertificateSigningAudit.SignedAt, f))
	detail := postgres.StringExp(postgres.CASE().
		WHEN(table.CertificateSigningAudit.CertificateSerial.EQ(postgres.String(""))).THEN(postgres.String("")).
		WHEN(table.Certificate.ID.IS_NULL()).THEN(postgres.CONCAT(postgres.String("serial "), table.CertificateSigningAudit.CertificateSerial)).
		ELSE(postgres.CONCAT(table.CertificateAuthority.Name, postgres.String(" · serial "), table.CertificateSigningAudit.CertificateSerial)))
	var out []Event
	err := postgres.SELECT(
		postgres.CAST(table.CertificateSigningAudit.ID).AS_TEXT().AS("Event.ID"),
		table.CertificateSigningAudit.SignedAt.AS("Event.At"), actorID.AS("Event.ActorUserID"),
		postgres.COALESCE(table.User.Name, postgres.String("")).AS("Event.ActorName"),
		postgres.COALESCE(table.User.Email, postgres.String("")).AS("Event.ActorEmail"),
		action.AS("Event.Action"), postgres.COALESCE(table.Certificate.Subject, table.CertificateAuthority.Name).AS("Event.Target"),
		detail.AS("Event.Detail"),
	).FROM(table.CertificateSigningAudit.
		INNER_JOIN(table.CertificateAuthority, table.CertificateAuthority.ID.EQ(table.CertificateSigningAudit.CertificateAuthorityID)).
		LEFT_JOIN(table.User, table.User.ID.EQ(table.CertificateSigningAudit.RequesterUserID)).
		LEFT_JOIN(table.Certificate, table.Certificate.OrganizationID.EQ(table.CertificateSigningAudit.OrganizationID).
			AND(table.Certificate.Serial.EQ(table.CertificateSigningAudit.CertificateSerial)))).
		WHERE(where).ORDER_BY(table.CertificateSigningAudit.SignedAt.DESC(), table.CertificateSigningAudit.ID.DESC()).LIMIT(int64(limit)).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

func (r Repository) auditEvents(ctx context.Context, orgID string, f Filter, limit int) ([]Event, error) {
	actorID := postgres.StringExp(postgres.COALESCE(postgres.CAST(table.AuditEvent.ActorUserID).AS_TEXT(), postgres.String("")))
	where := table.AuditEvent.OrganizationID.EQ(database.UUID(orgID)).
		AND(eventFilter(actorID, table.AuditEvent.Action, table.AuditEvent.CreatedAt, f))
	var out []Event
	err := postgres.SELECT(postgres.CAST(table.AuditEvent.ID).AS_TEXT().AS("Event.ID"), table.AuditEvent.CreatedAt.AS("Event.At"),
		actorID.AS("Event.ActorUserID"), postgres.COALESCE(table.User.Name, postgres.String("")).AS("Event.ActorName"),
		table.AuditEvent.ActorEmail.AS("Event.ActorEmail"), table.AuditEvent.Action.AS("Event.Action"),
		table.AuditEvent.Target.AS("Event.Target"), table.AuditEvent.Detail.AS("Event.Detail"),
		table.AuditEvent.ActorIP.AS("Event.ActorIP"), table.AuditEvent.ActorUserAgent.AS("Event.ActorUserAgent"),
		table.AuditEvent.ActorSessionID.AS("Event.ActorSessionID")).
		FROM(table.AuditEvent.LEFT_JOIN(table.User, table.User.ID.EQ(table.AuditEvent.ActorUserID))).
		WHERE(where).ORDER_BY(table.AuditEvent.CreatedAt.DESC(), table.AuditEvent.ID.DESC()).LIMIT(int64(limit)).
		QueryContext(ctx, database.Queryable(ctx, r.db), &out)
	return out, err
}

// eventFilter is shared by both sources, so `at` is whichever table's instant
// column this half of the union is narrowing. Both are TIMESTAMPTZ, and the
// bounds are built with TimestampzT to match: a bare timestamp literal would be
// resolved against the server's zone rather than the UTC day Day() parsed, which
// is how the date filter used to put events on the wrong side of midnight.
func eventFilter(actorID, action postgres.StringExpression, at postgres.TimestampzExpression, f Filter) postgres.BoolExpression {
	where := postgres.Bool(true)
	if f.Actor == SystemActor {
		where = where.AND(actorID.EQ(postgres.String("")))
	} else if f.Actor != "" {
		where = where.AND(actorID.EQ(postgres.String(f.Actor)))
	}
	if f.Action != "" {
		where = where.AND(action.EQ(postgres.String(f.Action)))
	}
	if f.From != nil {
		where = where.AND(at.GT_EQ(postgres.TimestampzT(*f.From)))
	}
	if f.To != nil {
		where = where.AND(at.LT(postgres.TimestampzT(*f.To)))
	}
	return where
}

func signingAction() postgres.StringExpression {
	return postgres.StringExp(postgres.CASE(table.CertificateSigningAudit.Purpose).
		WHEN(postgres.String("root_ca")).THEN(postgres.String("ca.root_created")).
		WHEN(postgres.String("issuing_ca")).THEN(postgres.String("ca.issuing_created")).
		WHEN(postgres.String("imported_ca")).THEN(postgres.String("ca.imported")).
		WHEN(postgres.String("deleted_ca")).THEN(postgres.String("ca.deleted")).
		WHEN(postgres.String("activated_ca")).THEN(postgres.String("ca.activated")).
		WHEN(postgres.String("deactivated_ca")).THEN(postgres.String("ca.deactivated")).
		WHEN(postgres.String("retired_ca")).THEN(postgres.String("ca.retired")).
		WHEN(postgres.String("rotated_ca")).THEN(postgres.String("ca.rotated")).
		WHEN(postgres.String("revoked_certificate")).THEN(postgres.String("certificate.revoked")).
		WHEN(postgres.String("server")).THEN(postgres.String("certificate.issued")).
		WHEN(postgres.String("client")).THEN(postgres.String("certificate.issued")).
		WHEN(postgres.String("csr")).THEN(postgres.String("certificate.issued")).
		WHEN(postgres.String("scep")).THEN(postgres.String("certificate.issued")).
		WHEN(postgres.String("scep_ra")).THEN(postgres.String("certificate.issued")).
		WHEN(postgres.String("acme")).THEN(postgres.String("certificate.issued")).
		WHEN(postgres.String("est")).THEN(postgres.String("certificate.issued")).
		ELSE(postgres.String("other")))
}

func actorID(id string) any {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	return id
}

// Day parses a yyyy-mm-dd form field into an instant, returning nil for an
// empty or unparseable value so a malformed filter widens rather than errors.
// end shifts to the following midnight, so "to" includes its whole day.
func Day(raw string, end bool) *time.Time {
	at, err := time.Parse("2006-01-02", strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	if end {
		at = at.AddDate(0, 0, 1)
	}
	return &at
}
