//go:build !windows

package lic

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// MachineID fallback no-Windows: hostname + primera MAC (para desarrollo y
// tests fuera de Windows; el producto se distribuye para Windows).
func MachineID() (string, error) {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "", os.ErrNotExist
	}
	macs, err := net.Interfaces()
	if err == nil {
		for _, iface := range macs {
			ha := iface.HardwareAddr
			if len(ha) >= 6 && !strings.EqualFold(iface.Name, "lo") {
				sum := sha256.Sum256([]byte(strings.ToLower(h) + "|" + hex.EncodeToString(ha)))
				return hex.EncodeToString(sum[:16]), nil
			}
		}
	}
	return "host:" + strings.ToLower(h), nil
}
