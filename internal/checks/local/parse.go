package local

import "crypto/x509"

// parseCertificate returns just the Subject string of a DER-encoded
// certificate, matching the shape loadPublicSubjects needs.
func parseCertificate(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return cert.Subject.String(), nil
}
