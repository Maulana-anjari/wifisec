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

// ruleWhen supports single checks, all/any conditions, and observed field matching.
type ruleWhen struct {
	Check    string         `yaml:"check"`
	Status   string         `yaml:"status"`
	Observed map[string]any `yaml:"observed"`
	All      []ruleCond     `yaml:"all"`
	Any      []ruleCond     `yaml:"any"`
}

type ruleCond struct {
	Check    string         `yaml:"check"`
	Status   string         `yaml:"status"`
	Observed map[string]any `yaml:"observed"`
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
		basedOn := ruleMatches(r.When, byID)
		if len(basedOn) == 0 {
			continue
		}
		// Use the first matching check's confidence; in multi-check rules, we could average but simple is safer
		c := byID[basedOn[0]]
		findings = append(findings, model.Finding{
			ID:                 r.ID,
			Severity:           model.Severity(r.Severity),
			Confidence:         c.Confidence,
			Title:              r.Title,
			Explanation:        r.Explanation,
			Impact:             r.Impact,
			BasedOn:            basedOn,
			Recommendation:     r.Recommendation,
			FalsePositiveHints: r.FalsePositiveHints,
		})
	}

	return findings, buildVerdict(checks, findings)
}

// ruleMatches evaluates a ruleWhen condition and returns the list of check IDs that matched, or empty if no match.
func ruleMatches(when ruleWhen, byID map[string]model.Check) []string {
	// Simple case: single check + status (+ optional observed)
	if when.Check != "" {
		c, ok := byID[when.Check]
		if !ok {
			return nil
		}
		if when.Status != "" && string(c.Status) != when.Status {
			return nil
		}
		if len(when.Observed) > 0 && !matchesObserved(c, when.Observed) {
			return nil
		}
		return []string{c.ID}
	}

	// All conditions must match
	if len(when.All) > 0 {
		var matched []string
		for _, cond := range when.All {
			c, ok := byID[cond.Check]
			if !ok {
				return nil
			}
			if cond.Status != "" && string(c.Status) != cond.Status {
				return nil
			}
			if len(cond.Observed) > 0 && !matchesObserved(c, cond.Observed) {
				return nil
			}
			matched = append(matched, c.ID)
		}
		return matched
	}

	// Any condition matches
	if len(when.Any) > 0 {
		var matched []string
		for _, cond := range when.Any {
			c, ok := byID[cond.Check]
			if !ok {
				continue
			}
			if cond.Status != "" && string(c.Status) != cond.Status {
				continue
			}
			if len(cond.Observed) > 0 && !matchesObserved(c, cond.Observed) {
				continue
			}
			matched = append(matched, c.ID)
		}
		if len(matched) > 0 {
			return matched
		}
	}

	return nil
}

// matchesObserved checks if a Check's Observed fields contain the expected key-value pairs.
func matchesObserved(c model.Check, expected map[string]any) bool {
	for k, v := range expected {
		actual, ok := c.Observed[k]
		if !ok || actual != v {
			return false
		}
	}
	return true
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
		if c.Status != model.StatusSkipped {
			continue
		}
		switch c.Control.Reason {
		case "profile_does_not_allow":
			spots = append(spots, c.Title+" tidak diperiksa - profil aktif tidak mengizinkan.")
		case "not_implemented":
			spots = append(spots, c.Title+" belum diimplementasikan.")
		default:
			// Graceful fallback for skip reasons not yet given their own
			// message.
			spots = append(spots, c.Title+" tidak diperiksa.")
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

// useCasesFor holds one map per Safety tier (spec §7.3's per-use-case
// risk table). SafetyOK, SafetyAvoid, and SafetyUnknown are taken
// verbatim from testdata/fixtures/*.json (the spec's own reference
// behavior). No fixture has safety: caution, so SafetyCaution below is
// a controller ruling interpolated between the OK and Avoid tiers, not
// derived from fixture data: kerja_sensitif/internet_banking (highest
// sensitivity) degrade one step before login_akun_pribadi, which
// degrades one step before browsing_umum (lowest sensitivity, never
// reaches avoid in any fixture).
var useCasesTable = map[model.Safety]map[string]string{
	model.SafetyOK: {
		"browsing_umum":      "ok",
		"login_akun_pribadi": "ok",
		"kerja_sensitif":     "caution",
		"internet_banking":   "caution",
	},
	model.SafetyCaution: {
		"browsing_umum":      "caution",
		"login_akun_pribadi": "caution",
		"kerja_sensitif":     "avoid",
		"internet_banking":   "avoid",
	},
	model.SafetyAvoid: {
		"browsing_umum":      "caution",
		"login_akun_pribadi": "avoid",
		"kerja_sensitif":     "avoid",
		"internet_banking":   "avoid",
	},
	model.SafetyUnknown: {
		"browsing_umum":      "caution",
		"login_akun_pribadi": "caution",
		"kerja_sensitif":     "caution",
		"internet_banking":   "caution",
	},
}

func useCasesFor(safety model.Safety) map[string]string {
	return useCasesTable[safety]
}
