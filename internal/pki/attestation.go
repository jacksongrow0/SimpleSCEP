package pki

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type attestationMetadata struct {
	CertificateAuthority string `json:"certificateAuthority"`
	KeyVersion           string `json:"keyVersion"`
	Format               string `json:"format"`
	Example              bool   `json:"example"`
}

// attestationZip keeps the raw HSM statement intact and places each provider
// verification artifact beside it without transforming signed data.
func attestationZip(ca CertificateAuthority, attestation KeyAttestation) ([]byte, error) {
	var output bytes.Buffer
	zw := zip.NewWriter(&output)
	files := []struct {
		name string
		data []byte
	}{
		{name: "attestation.dat", data: attestation.Content},
	}
	metadata, err := json.MarshalIndent(attestationMetadata{
		CertificateAuthority: ca.Name,
		KeyVersion:           redactKeyVersionPath(ca.KMSKeyVersion),
		Format:               attestation.Format,
		Example:              attestation.Example,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	files = append(files, struct {
		name string
		data []byte
	}{name: "metadata.json", data: append(metadata, '\n')})
	artifactNames := make([]string, 0, len(attestation.Artifacts))
	for name := range attestation.Artifacts {
		artifactNames = append(artifactNames, name)
	}
	sort.Strings(artifactNames)
	for _, name := range artifactNames {
		data := attestation.Artifacts[name]
		if strings.Contains(name, "/") || strings.Contains(name, "\\") || name == "" {
			return nil, fmt.Errorf("invalid attestation artifact name %q", name)
		}
		files = append(files, struct {
			name string
			data []byte
		}{name: name, data: data})
	}
	for _, chain := range []struct {
		name  string
		certs []string
	}{
		{name: "cavium-cert-chain.pem", certs: attestation.CaviumCerts},
		{name: "google-card-cert-chain.pem", certs: attestation.GoogleCardCerts},
		{name: "google-partition-cert-chain.pem", certs: attestation.GooglePartitionCerts},
	} {
		if len(chain.certs) > 0 {
			files = append(files, struct {
				name string
				data []byte
			}{name: chain.name, data: []byte(strings.Join(chain.certs, "\n"))})
		}
	}
	for _, file := range files {
		entry, err := zw.Create(file.name)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(file.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func exampleKeyAttestation(keyVersion, mode string) KeyAttestation {
	return KeyAttestation{
		Format:  "EXAMPLE_NOT_HSM_ATTESTATION",
		Example: true,
		Content: []byte("SimpleSCEP example key attestation\n\n" +
			"This is not a cryptographic attestation and cannot prove HSM residency.\n" +
			"Certificate mode: " + mode + "\n" +
			"Key version: " + keyVersion + "\n"),
	}
}

// redactKeyVersionPath strips the "projects/<id>/locations/<loc>/" prefix
// from a Cloud KMS resource name, since that portion identifies the caller's
// GCP project and has no place in a file handed to outside parties. It
// leaves the key ring, key, and version segments, which are what actually
// identify the attested key.
func redactKeyVersionPath(version string) string {
	_, rest, ok := strings.Cut(version, "/keyRings/")
	if !ok {
		return version
	}
	return strings.Replace(rest, "/cryptoKeys/", "/", 1)
}

func attestationFilename(name string) string {
	base := pemSlug(name)
	if base == "" {
		base = "certificate-authority"
	}
	return base + "-attestation.zip"
}
