package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

// signedRequest builds a PKCSReq for csr, signed by the given throwaway signer,
// and returns it in the state Service.issue sees it: parsed, with SignerCert
// filled from the CMS signer the way PKIOperation fills it.
func signedRequest(t *testing.T, raCert *x509.Certificate, raKey *rsa.PrivateKey,
	signerCert *x509.Certificate, signerKey *rsa.PrivateKey, csr *x509.CertificateRequest,
	transactionID string) *scep.PKIMessage {
	t.Helper()
	request, err := scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq, Recipients: []*x509.Certificate{raCert},
		SignerCert: signerCert, SignerKey: signerKey, TransactionID: scep.TransactionID(transactionID)})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := scep.ParsePKIMessage(request.Raw)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := pkcs7.Parse(request.Raw)
	if err != nil {
		t.Fatal(err)
	}
	msg.SignerCert = outer.GetOnlySigner()
	if err := msg.DecryptPKIEnvelope(raCert, raKey); err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestReplayIsBoundToTheOriginalSigningKey covers the check that makes the
// idempotent-retry path safe.
//
// Service.issue answers a repeated transaction id with the certificate it already
// issued, before authorize runs, so that a device whose response was lost can
// retry after its one-time challenge password has been spent. Matching on the CSR
// alone made that reachable by anyone: a CSR travels over SCEP in the clear and
// the transaction id is conventionally derived from the key inside it, so an
// observer could rebuild both and collect the certificate with no credential.
//
// The digest recorded on the transaction is what separates the two. A genuine
// retry signs with the key it used the first time and matches; an observer holds
// the CSR but not that private key.
func TestReplayIsBoundToTheOriginalSigningKey(t *testing.T) {
	raCert, raKey := selfSigned(t, "SimpleSCEP RA")
	deviceSigner, deviceSignerKey := selfSigned(t, "SCEP Protocol Certificate")

	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "device7"}}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	const txID = "tx-replay"
	first := signedRequest(t, raCert, raKey, deviceSigner, deviceSignerKey, csr, txID)
	recorded := signerKeyDigest(first.SignerCert)
	if recorded == "" {
		t.Fatal("no digest was derived from the signer of the original request")
	}

	// The same device retrying: same key, and — because SCEP signers are throwaway
	// wrappers — not necessarily the same certificate around it.
	retrySigner, retrySignerKey := reSelfSign(t, deviceSignerKey, "SCEP Protocol Certificate")
	retry := signedRequest(t, raCert, raKey, retrySigner, retrySignerKey, csr, txID)
	if got := signerKeyDigest(retry.SignerCert); got != recorded {
		t.Errorf("an honest retry stopped matching its own transaction:\n got %s\nwant %s", got, recorded)
	}

	// An observer replaying the identical CSR under the identical transaction id,
	// signing with a key of its own — which is all it can do.
	attackerSigner, attackerKey := selfSigned(t, "SCEP Protocol Certificate")
	replay := signedRequest(t, raCert, raKey, attackerSigner, attackerKey, csr, txID)
	if got := signerKeyDigest(replay.SignerCert); got == recorded {
		t.Error("a replay signed by a different key matched the recorded transaction")
	}
}

func TestSignerKeyDigestOfNoSignerMatchesNothing(t *testing.T) {
	if got := signerKeyDigest(nil); got != "" {
		t.Errorf("signerKeyDigest(nil) = %q, want the empty string", got)
	}
}

// reSelfSign wraps an existing key in a fresh self-signed certificate, which is
// what a device does when it rebuilds its throwaway SCEP signer between attempts.
// The key is what the digest is over, so this must not change the answer.
func reSelfSign(t *testing.T, key *rsa.PrivateKey, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
