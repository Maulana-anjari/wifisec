// Package net implements wifisec active checks for network properties
// including latency (gateway, internet), IPv6 reachability, and related
// observations (spec §6.3). This file provides the TCP sampling primitive.
//
// No ICMP: CLAUDE.md forbids adding a third-party ICMP library, and raw
// ICMP sockets need root on most systems this tool targets. Every
// latency measurement here uses TCP connect-time instead — dial, time
// how long the handshake takes, close. Cheap, privilege-free, and
// "packet" (in the guard.PacketCounter sense) maps 1:1 to one dial
// attempt.
package net

import (
	stdcontext "context"
	"net"
	"time"
)

// sampleTCP dials addr n times sequentially (a small gap between
// attempts avoids a connection burst that could look like a port
// scan), and returns each successful dial's connect duration plus how
// many attempts succeeded/failed. A failed dial (refused, timeout,
// no route) counts toward lost, not toward samples — there is no RTT
// for a connection that never completed.
func sampleTCP(ctx stdcontext.Context, addr string, n int, perDialTimeout time.Duration) (samples []time.Duration, sent, lost int) {
	dialer := net.Dialer{Timeout: perDialTimeout}
	for i := 0; i < n; i++ {
		sent++
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			lost++
		} else {
			samples = append(samples, time.Since(start))
			conn.Close()
		}
		if i < n-1 {
			select {
			case <-ctx.Done():
				return samples, sent, lost
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return samples, sent, lost
}

func msFloats(d []time.Duration) []float64 {
	out := make([]float64, len(d))
	for i, v := range d {
		out[i] = float64(v.Microseconds()) / 1000.0
	}
	return out
}

func meanMS(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s
	}
	return sum / float64(len(samples))
}
