// Package interpret turns Check results into Findings and a Verdict
// (spec §7). This milestone's rules.yaml covers only findings reachable
// from spec §6.1 (passive) checks; later milestones extend it as more
// checks land.
package interpret

import (
	_ "embed"

	"gopkg.in/yaml.v3"

	"github.com/Maulana-anjari/wifisec/internal/model"
)

//go:embed rules.yaml
var rulesYAML []byte

type rule struct {
	ID                 string   `yaml:"id"`
	Severity           string   `yaml:"severity"`
	When               ruleWhen `yaml:"when"`
	Title              string   `yaml:"title"`
	Explanation        string   `yaml:"explanation"`
	Impact             []string `yaml:"impact"`
	Recommendation     string   `yaml:"recommendation"`
	FalsePositiveHints []string `yaml:"false_positive_hints"`
}

// ruleWhen supports only the single-condition case this milestone's
// rules.yaml needs (spec §7.1 also defines all/any/not; not needed
// until a rule requires combining multiple checks).
type ruleWhen struct {
	Check  string `yaml:"check"`
	Status string `yaml:"status"`
}

var rules = loadRules(rulesYAML)

func loadRules(data []byte) []rule {
	var f struct {
		Rules []rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &f); err != nil {
		panic("interpret: invalid rules.yaml: " + err.Error()) // embedded, compile-time data — a parse failure is a build defect
	}
	return f.Rules
}

// Apply evaluates every rule against checks and computes the resulting
// Verdict per spec §7.3.
func Apply(checks []model.Check) ([]model.Finding, model.Verdict) {
	byID := make(map[string]model.Check, len(checks))
	for _, c := range checks {
		byID[c.ID] = c
	}

	var findings []model.Finding
	for _, r := range rules {
		c, ok := byID[r.When.Check]
		if !ok || string(c.Status) != r.When.Status {
			continue
		}
		findings = append(findings, model.Finding{
			ID:                 r.ID,
			Severity:           model.Severity(r.Severity),
			Confidence:         c.Confidence,
			Title:              r.Title,
			Explanation:        r.Explanation,
			Impact:             r.Impact,
			BasedOn:            []string{c.ID},
			Recommendation:     r.Recommendation,
			FalsePositiveHints: r.FalsePositiveHints,
		})
	}

	return findings, buildVerdict(checks, findings)
}

func buildVerdict(checks []model.Check, findings []model.Finding) model.Verdict {
	score := 100
	hasCritical := false
	warningPenalty, infoPenalty := 0, 0
	topFindings := make([]string, 0, len(findings))
	for _, f := range findings {
		topFindings = append(topFindings, f.ID)
		switch f.Severity {
		case model.SeverityCritical:
			hasCritical = true
		case model.SeverityWarning:
			warningPenalty += 15
		case model.SeverityInfo:
			infoPenalty += 5
		}
	}
	if hasCritical {
		score -= 40
	}
	if warningPenalty > 45 {
		warningPenalty = 45
	}
	if infoPenalty > 15 {
		infoPenalty = 15
	}
	score -= warningPenalty + infoPenalty

	allFailed := len(checks) > 0
	for _, c := range checks {
		if c.Status != model.StatusError && c.Status != model.StatusSkipped {
			allFailed = false
			break
		}
	}
	var safety model.Safety
	switch {
	case allFailed:
		safety = model.SafetyUnknown
	case hasCritical:
		safety = model.SafetyAvoid
	case score >= 80:
		safety = model.SafetyOK
	case score >= 50:
		safety = model.SafetyCaution
	default:
		safety = model.SafetyAvoid
	}

	return model.Verdict{
		Safety:      safety,
		Score:       score,
		Headline:    headlineFor(safety),
		TopFindings: topFindings,
		BlindSpots:  blindSpotsFor(checks),
		UseCases:    useCasesFor(safety),
	}
}

func blindSpotsFor(checks []model.Check) []string {
	var spots []string
	for _, c := range checks {
		if c.Status == model.StatusSkipped {
			spots = append(spots, c.Title+" tidak diperiksa - profil aktif tidak mengizinkan.")
		}
	}
	return spots
}

func headlineFor(safety model.Safety) string {
	switch safety {
	case model.SafetyOK:
		return "Jaringan ini tampak aman untuk penggunaan umum."
	case model.SafetyCaution:
		return "Jaringan ini memiliki beberapa hal yang perlu diwaspadai."
	case model.SafetyAvoid:
		return "Jaringan ini memiliki risiko signifikan; hindari trafik sensitif."
	default:
		return "Belum cukup data untuk menyimpulkan keamanan jaringan ini."
	}
}

func useCasesFor(safety model.Safety) map[string]string {
	value := "caution"
	switch safety {
	case model.SafetyOK:
		value = "ok"
	case model.SafetyAvoid:
		value = "avoid"
	}
	return map[string]string{
		"browsing_umum":      value,
		"login_akun_pribadi": value,
		"kerja_sensitif":     value,
		"internet_banking":   value,
	}
}
