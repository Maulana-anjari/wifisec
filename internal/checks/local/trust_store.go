package local

import (
	"context"
	_ "embed"
	"encoding/pem"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

//go:embed publicroots.pem
var publicRootsPEM []byte

// knownPublicSubjects is derived once from the embedded bundle: the
// set of Subject strings this build recognizes as public CAs. Subject
// (not fingerprint) is used for matching because the runtime trust
// store and the embedded bundle may carry the exact same certificate
// re-serialized with different encoding, but the human-readable
// Subject stays stable — an acceptable approximation for classifying
// "public" vs "foreign", not a cryptographic identity check.
var knownPublicSubjects = loadPublicSubjects(publicRootsPEM)

func loadPublicSubjects(data []byte) map[string]bool {
	subjects := make(map[string]bool)
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := parseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		subjects[cert] = true
	}
	return subjects
}

type TrustStoreCheck struct{ def registry.CheckDefinition }

func NewTrustStoreCheck(def registry.CheckDefinition) checks.Checker { return TrustStoreCheck{def} }

func (c TrustStoreCheck) Definition() registry.CheckDefinition { return c.def }

func (c TrustStoreCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	cas, err := cc.Platform.TrustStoreCAs()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	var foreign []platform.CACert
	for _, ca := range cas {
		if !knownPublicSubjects[ca.Subject] {
			foreign = append(foreign, ca)
		}
	}
	if len(foreign) == 0 {
		return model.Check{
			ID:              c.def.ID,
			Layer:           c.def.Layer,
			Title:           c.def.Title,
			ProfileRequired: c.def.ProfileRequired,
			Status:          model.StatusNormal,
			Confidence:      model.ConfidenceHigh,
			Observed:        map[string]any{"non_public_ca_found": false},
			Control:         model.Control{Performed: false},
			DurationMS:      time.Since(start).Milliseconds(),
		}
	}
	// self_evident per spec §6.1: local presence of a foreign CA needs
	// no comparison control to report at high confidence.
	return model.Check{
		ID:              c.def.ID,
		Layer:           c.def.Layer,
		Title:           c.def.Title,
		ProfileRequired: c.def.ProfileRequired,
		Status:          model.StatusAnomalous,
		Confidence:      model.ConfidenceHigh,
		Observed: map[string]any{
			"non_public_ca_found": true,
			"subject":             foreign[0].Subject,
			"issuer":              foreign[0].Issuer,
			"count":               len(foreign),
		},
		Control:    model.Control{Performed: false},
		DurationMS: time.Since(start).Milliseconds(),
	}
}
