package model

import "fmt"

type Safety string

const (
	SafetyOK      Safety = "ok"
	SafetyCaution Safety = "caution"
	SafetyAvoid   Safety = "avoid"
	SafetyUnknown Safety = "unknown"
)

type Verdict struct {
	Safety      Safety            `json:"safety"`
	Score       int               `json:"score"`
	Headline    string            `json:"headline"`
	TopFindings []string          `json:"top_findings"`
	BlindSpots  []string          `json:"blind_spots"`
	UseCases    map[string]string `json:"use_cases"`
}

// ValidateVerdict enforces spec §4.4 / P4: any skipped check must be
// reflected in the verdict's BlindSpots.
func ValidateVerdict(checks []Check, v Verdict) error {
	for _, c := range checks {
		if c.Status == StatusSkipped {
			if len(v.BlindSpots) == 0 {
				return fmt.Errorf("verdict: checks include a skipped status but blind_spots is empty (see P4)")
			}
			return nil
		}
	}
	return nil
}
