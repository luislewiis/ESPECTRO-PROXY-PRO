//go:build windows

package lic

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// MachineID identifica el equipo de forma estable en Windows.
// Primario: MachineGuid (identificador unico de instalacion de Windows,
// el mismo que usan las licencias comerciales tipicas). Fallback: hostname.
func MachineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		v, _, err := k.GetStringValue("MachineGuid")
		k.Close()
		if err == nil && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), nil
		}
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "", os.ErrNotExist
	}
	return "host:" + strings.ToLower(h), nil
}
