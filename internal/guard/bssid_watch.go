package guard

import (
	"context"
	"time"

	"github.com/Maulana-anjari/wifisec/internal/platform"
)

// Watch polls adapter.WiFiInfo() every interval and calls onChange
// exactly once, with the newly observed BSSID, the first time it
// differs from initialBSSID (spec G4: "perubahan BSSID saat runtime
// menurunkan profil ke passive seketika dan membatalkan check yang
// sedang berjalan"). Watch itself does not downgrade any profile or
// cancel anything — that's the caller's onChange callback (typically
// calling the run's context.CancelFunc and updating the reported
// profile). Watch returns when ctx is done or after firing onChange
// once, whichever comes first.
//
// An empty or unavailable BSSID reading (platform.WiFiInfo.Available
// == false) is not treated as a change — a check run doesn't need to
// treat "WiFi briefly unreadable" the same as "associated to a
// different AP."
func Watch(ctx context.Context, adapter platform.Adapter, initialBSSID string, interval time.Duration, onChange func(newBSSID string)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := adapter.WiFiInfo()
			if err != nil || !info.Available {
				continue
			}
			if info.BSSID != "" && info.BSSID != initialBSSID {
				onChange(info.BSSID)
				return
			}
		}
	}
}
