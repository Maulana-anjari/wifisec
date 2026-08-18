package net

import (
	stdcontext "context"
	"io"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/checks"
	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/registry"
)

const (
	captivePortalURL    = "http://example.com/"
	captivePortalMarker = "Example Domain"
)

type CaptivePortalCheck struct{ def registry.CheckDefinition }

func NewCaptivePortalCheck(def registry.CheckDefinition) checks.Checker { return CaptivePortalCheck{def} }
func (c CaptivePortalCheck) Definition() registry.CheckDefinition       { return c.def }

// Run fetches the control domain over plain HTTP with redirects
// disabled: a captive portal typically either 30x-redirects the
// request elsewhere or serves its own login page instead of the real
// site (spec §6.3, "net.captive_portal"). A clean network gets a 200
// with the expected page content.
func (c CaptivePortalCheck) Run(ctx stdcontext.Context, cc checks.CheckContext) model.Check {
	start := time.Now()
	if err := cc.Counter.Add(c.def.ID, c.def.EstimatedPackets); err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	client := stdhttp.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *stdhttp.Request, via []*stdhttp.Request) error {
			return stdhttp.ErrUseLastResponse
		},
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, captivePortalURL, nil)
	if err != nil {
		return checks.NewErrorCheck(c.def, err, start)
	}
	resp, err := client.Do(req)
	if err != nil {
		return model.Check{
			ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
			Status: model.StatusInconclusive, Confidence: model.ConfidenceLow,
			Control:     model.Control{Performed: false, Reason: "http_unreachable"},
			PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	redirected := resp.StatusCode >= 300 && resp.StatusCode < 400
	contentMatches := strings.Contains(string(body), captivePortalMarker)
	portalDetected := redirected || (resp.StatusCode == 200 && !contentMatches)

	observed := map[string]any{"status_code": resp.StatusCode, "portal_detected": portalDetected}
	if redirected {
		observed["redirect_location"] = resp.Header.Get("Location")
	}

	status := model.StatusNormal
	confidence := model.ConfidenceMedium
	if portalDetected {
		status = model.StatusAnomalous
		confidence = model.ConfidenceHigh
	}
	return model.Check{
		ID: c.def.ID, Layer: c.def.Layer, Title: c.def.Title, ProfileRequired: c.def.ProfileRequired,
		Status: status, Confidence: confidence,
		Observed:    observed,
		Control:     model.Control{Performed: true, Result: "compared against known example.com response"},
		PacketsSent: c.def.EstimatedPackets, DurationMS: time.Since(start).Milliseconds(),
	}
}
