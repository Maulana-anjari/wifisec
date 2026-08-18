// Package tls implements the wifisec "tls"-layer active check (spec
// §6.2): tls.cert_issuer.
package tls

import (
	crypto_tls "crypto/tls"
	"crypto/sha256"
	"crypto/x509"
	stdcontext "context"
	"encoding/hex"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const (
	certTarget = "example.com:443"
	certSNI    = "example.com"
	// baselineFingerprint is example.com's leaf certificate SHA-256
	// fingerprint, captured live 2026-08-18 (cert valid through
	// 2026-10-27). This needs periodic manual refresh as the
	// certificate rotates — same provenance caveat as
	// internal/checks/local/publicroots.pem (deferred to M5 in that
	// package's case; here it's an expected, spec-anticipated
	// occurrence: spec §6.2 says a mismatch is Anomalous at Confidence
	// medium precisely *because* normal rotation happens).
	baselineFingerprint = "6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200"
)

type CertIssuerCheck struct{ def registry.CheckDefinition }

func NewCertIssuerCheck(def registry.CheckDefinition) checks.Checker { return CertIssuerCheck{def} }
func (c CertIssuerCheck) Definition() registry.CheckDefinition       { return c.def }

// Run dials the control domain with InsecureSkipVerify and a custom
// VerifyPeerCertificate that unconditionally accepts (spec §6.2: "the
// certificate must not be rejected — the point is to see exactly what
// the network hands back").
func (c CertIssuerCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	var captured []*x509.Certificate
	cfg := &crypto_tls.Config{
		ServerName:         certSNI,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				if cert, err := x509.ParseCertificate(raw); err == nil {
					captured = append(captured, cert)
				}
			}
			return nil
		},
	}
	dialer := &crypto_tls.Dialer{Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", certTarget)
	if err != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "tls_handshake_failed"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	defer conn.Close()
	if len(captured) == 0 {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "no_certificate_presented"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	leaf := captured[0]
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	match := fingerprint == baselineFingerprint
	status := model.StatusNormal
	confidence := model.ConfidenceHigh
	if !match {
		status = model.StatusAnomalous
		confidence = model.ConfidenceMedium
		if foundInTrustStore(cc, leaf.Issuer.String()) {
			confidence = model.ConfidenceHigh
		}
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed: map[string]any{
			"issuer": leaf.Issuer.String(), "subject": leaf.Subject.String(),
			"fingerprint": "sha256:" + fingerprint, "chain_length": len(captured),
		},
		Expected:    map[string]any{"fingerprint": "sha256:" + baselineFingerprint, "source": "baseline_bundled"},
		Control:     model.Control{Performed: true, Result: "compared against bundled baseline fingerprint"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}

func foundInTrustStore(cc checks.CheckContext, issuer string) bool {
	cas, err := cc.Platform.TrustStoreCAs()
	if err != nil {
		return false
	}
	for _, ca := range cas {
		if ca.Subject == issuer {
			return true
		}
	}
	return false
}
