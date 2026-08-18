package main

import (
	"fmt"
	"os"

	"github.com/Maulana-anjari/wifisec/internal/model"
	"github.com/Maulana-anjari/wifisec/internal/platform"
	"github.com/Maulana-anjari/wifisec/internal/whitelist"
)

// runKnownNetworksAdd implements `wifisec known-networks add` (spec
// §9.1): hash the currently-associated network's BSSID and add it to
// the whitelist, so future runs see KnownNetwork == true for it
// (gating spec G5's second full-profile confirmation).
func runKnownNetworksAdd() {
	info, err := platform.New().WiFiInfo()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read WiFi info:", err)
		os.Exit(3)
	}
	if !info.Available || info.BSSID == "" {
		fmt.Fprintln(os.Stderr, "error: no connected WiFi network to add")
		os.Exit(3)
	}

	net := model.NewNetworkInfo(info.SSID, info.BSSID)
	list, err := whitelist.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: load whitelist:", err)
		os.Exit(3)
	}
	list.Add(net.BSSIDHash, info.SSID)
	if err := list.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "error: save whitelist:", err)
		os.Exit(3)
	}
	fmt.Printf("Ditambahkan ke whitelist: %s\n", info.SSID)
}
