package model

import "fmt"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID                 string     `json:"id"`
	Severity           Severity   `json:"severity"`
	Confidence         Confidence `json:"confidence"`
	Title              string     `json:"title"`
	Explanation        string     `json:"explanation"`
	Impact             []string   `json:"impact,omitempty"`
	BasedOn            []string   `json:"based_on"`
	Recommendation     string     `json:"recommendation"`
	FalsePositiveHints []string   `json:"false_positive_hints,omitempty"`
}

// ValidateFinding enforces spec §4.3: a Finding must cite at least one
// check ID that actually exists among the run's results.
func ValidateFinding(f Finding, validCheckIDs map[string]bool) error {
	if len(f.BasedOn) == 0 {
		return fmt.Errorf("finding %s: based_on must not be empty", f.ID)
	}
	for _, id := range f.BasedOn {
		if !validCheckIDs[id] {
			return fmt.Errorf("finding %s: based_on references unknown check id %q", f.ID, id)
		}
	}
	return nil
}
