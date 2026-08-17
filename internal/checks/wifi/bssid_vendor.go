package wifi

import (
	"context"
	"strings"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

type BSSIDVendorCheck struct{ def registry.CheckDefinition }

func NewBSSIDVendorCheck(def registry.CheckDefinition) checks.Checker { return BSSIDVendorCheck{def} }

func (c BSSIDVendorCheck) Definition() registry.CheckDefinition { return c.def }

func (c BSSIDVendorCheck) Run(ctx context.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	info, err := cc.Platform.WiFiInfo()
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	base := model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Control: model.Control{Performed: false}, DurationMS: time.Since(start).Milliseconds(),
	}
	if !info.Available {
		base.Status = model.StatusInconclusive
		base.Confidence = model.ConfidenceLow
		base.Error = info.Reason
		return base
	}
	oui := ouiFromBSSID(info.BSSID)
	// No bundled OUI-to-vendor-name database in this milestone (YAGNI —
	// would need a real IEEE OUI dataset to be trustworthy); reporting
	// the OUI itself is still useful and honest.
	base.Observed = map[string]any{"oui": oui}
	base.Status = model.StatusNormal
	base.Confidence = model.ConfidenceHigh
	return base
}

func ouiFromBSSID(bssid string) string {
	parts := strings.Split(bssid, ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], ":")
}
