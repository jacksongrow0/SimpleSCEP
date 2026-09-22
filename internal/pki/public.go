package pki

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"golang.org/x/crypto/ocsp"
)

// errTooManyRequests is the one failure publicError renders as 429. It is a
// sentinel rather than a status because publicContext returns only an error, and
// the two callers render their refusals in different formats — bytes for the CRL,
// a signed OCSP response for OCSP.
var errTooManyRequests = errors.New("too many requests")

func (h Handler) publicContext(r *http.Request, fn func(context.Context) error) error {
	orgID, caID := r.PathValue("orgID"), r.PathValue("caID")
	if _, err := uuid.Parse(orgID); err != nil {
		return sql.ErrNoRows
	}
	if _, err := uuid.Parse(caID); err != nil {
		return sql.ErrNoRows
	}
	// Keyed by CA and caller, before the transaction opens. These routes are the
	// only unauthenticated surface that can reach a KMS signing operation, and
	// unlike SCEP, ACME and EST — each of which limits its own endpoint — they had
	// no budget at all. The CA id is public: it is printed into the
	// crlDistributionPoints of every certificate issued under it.
	if h.limiter != nil && !h.limiter.Allow(caID+"|"+clientip.ClientIP(r)) {
		return errTooManyRequests
	}
	if h.db == nil {
		return fn(r.Context())
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	ctx := database.WithTx(r.Context(), tx)
	defer tx.Rollback()
	if err := database.SetLocal(ctx, "app.organization_id", orgID); err != nil {
		return err
	}
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

func (h Handler) publicIssuer(w http.ResponseWriter, r *http.Request) {
	err := h.publicContext(r, func(ctx context.Context) error {
		ca, err := h.repo.CA(ctx, r.PathValue("orgID"), r.PathValue("caID"))
		if err != nil || ca.Type != CATypeIssuing {
			return sql.ErrNoRows
		}
		block, _ := pem.Decode([]byte(ca.CertificatePEM))
		if block == nil {
			return errors.New("invalid issuer certificate")
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, err = w.Write(block.Bytes)
		return err
	})
	publicError(w, err)
}

func (h Handler) publicCRL(w http.ResponseWriter, r *http.Request) {
	err := h.publicContext(r, func(ctx context.Context) error {
		p, err := h.service.EnsureFreshCRL(ctx, r.PathValue("orgID"), r.PathValue("caID"))
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", "public, max-age="+maxAge(p.NextUpdate))
		_, err = w.Write(p.DER)
		return err
	})
	publicError(w, err)
}

func (h Handler) publicOCSP(w http.ResponseWriter, r *http.Request) {
	requestDER, err := ocspRequestBytes(w, r)
	if err != nil {
		writeOCSP(w, ocsp.MalformedRequestErrorResponse, time.Now().Add(time.Minute))
		return
	}
	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		writeOCSP(w, ocsp.MalformedRequestErrorResponse, time.Now().Add(time.Minute))
		return
	}
	var response []byte
	var next time.Time
	err = h.publicContext(r, func(ctx context.Context) error {
		var err error
		response, next, err = h.service.OCSPResponse(ctx, r.PathValue("orgID"), r.PathValue("caID"), req)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		writeOCSP(w, ocsp.UnauthorizedErrorResponse, time.Now().Add(time.Minute))
		return
	}
	// Everything else, the rate-limit refusal included, is TryLater rather than a
	// status code: an OCSP client reads the response body and not the HTTP status,
	// and tryLater is the registered way to say "ask again". A bare 429 would be
	// reported as an unparseable response.
	if err != nil {
		writeOCSP(w, ocsp.TryLaterErrorResponse, time.Now().Add(time.Minute))
		return
	}
	writeOCSP(w, response, next)
}

func ocspRequestBytes(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		return io.ReadAll(r.Body)
	}
	raw := strings.TrimPrefix(r.PathValue("request"), "/")
	if len(raw) > 32<<10 {
		return nil, errors.New("request too large")
	}
	if der, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return der, nil
	}
	return base64.StdEncoding.DecodeString(raw)
}

func writeOCSP(w http.ResponseWriter, der []byte, next time.Time) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "public, max-age="+maxAge(&next))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

func maxAge(next *time.Time) string {
	if next == nil {
		return "0"
	}
	seconds := int(time.Until(*next).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return strconv.Itoa(seconds)
}

func publicError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, errTooManyRequests) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	http.Error(w, "revocation service unavailable", http.StatusServiceUnavailable)
}
