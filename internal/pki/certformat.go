package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

// certDownloadFormat resolves the "format" query parameter accepted by every
// plain certificate download endpoint. "pem" and "crt" name the same bytes —
// the PEM text these endpoints already produce — under the extension callers
// commonly expect; DER, unlike PEM, holds exactly one certificate, so "cer"
// drops any chain and encodes only the leaf.
type certDownloadFormat struct {
	ext, contentType string
	der              bool
}

var certDownloadFormats = map[string]certDownloadFormat{
	"":    {ext: "pem", contentType: "application/x-pem-file"},
	"pem": {ext: "pem", contentType: "application/x-pem-file"},
	"crt": {ext: "crt", contentType: "application/x-pem-file"},
	"cer": {ext: "cer", contentType: "application/pkix-cert", der: true},
}

// WriteCertificateDownload writes certPEM, followed by chainPEM for the text
// encodings, to w as an attachment named after name. The request's "format"
// query parameter picks the encoding: "pem" (the default) or "crt" for the
// PEM text as-is, "cer" for binary DER of the leaf certificate alone.
//
// Nothing is written to w until the certificate to send has been parsed
// successfully, so a malformed format value or a decode failure leaves the
// response untouched for the caller to report.
func WriteCertificateDownload(w http.ResponseWriter, r *http.Request, name, certPEM, chainPEM string) error {
	format, ok := certDownloadFormats[r.URL.Query().Get("format")]
	if !ok {
		return fmt.Errorf("unsupported certificate format %q", r.URL.Query().Get("format"))
	}
	var body []byte
	suffix := ""
	if format.der {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return fmt.Errorf("no certificate to encode")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("parse certificate: %w", err)
		}
		body = block.Bytes
	} else {
		body = []byte(certPEM + chainPEM)
		suffix = "-chain"
	}
	base := pemSlug(name)
	if base == "" {
		base = "certificate"
	}
	w.Header().Set("Content-Type", format.contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s.%s"`, base, suffix, format.ext))
	_, err := w.Write(body)
	return err
}
