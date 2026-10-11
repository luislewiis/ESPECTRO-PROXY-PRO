//go:build windows

package main

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

// TestNotificacionScriptParsea: el script PowerShell embebido debe parsear
// sin errores de sintaxis. ParseInput no ejecuta el script ni abre ventanas
// (seguro en CI). Si no parseara, powershell saldria con exit 1 y el
// arranque seguiria (degrada a "continuar"), pero se perdia la distincion
// de botones: este test lo impide en cada CI.
func TestNotificacionScriptParsea(t *testing.T) {
	script := notificacionScript([]cambioPuerto{
		{"gateway proxy", 8080, 8090},
		{"API/panel", 8081, 8091},
	}, "gateway: 127.0.0.1:8090\r\npanel:   http://127.0.0.1:8091/panel")

	if strings.Contains(script, "%%") {
		t.Fatal("quedaron placeholders sin sustituir en el script")
	}
	// Codigos altos: 10 = Copiar, 20 = Cerrar; un crash (exit 1) no debe
	// confundirse con ningun boton.
	if !strings.Contains(script, "exit 10") || !strings.Contains(script, "exit 20") {
		t.Fatal("codigos de salida de los botones ausentes (10=copiar, 20=cerrar)")
	}
	if !strings.Contains(script, "8080,8081") {
		t.Fatal("los puertos ocupados no llegaron al script")
	}

	// Parse por stdin (sin rutas ni variables de entorno): solo sintaxis.
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"$errs = $null; $src = [Console]::In.ReadToEnd(); "+
			"$null = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$errs); "+
			"if ($errs -and $errs.Count -gt 0) { $errs | ForEach-Object { Write-Output ($_.Message + ' (linea ' + $_.Extent.StartLineNumber + ')') }; exit 1 }")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("el script PowerShell no parsea:\n%s", out)
	}
}

// TestCodificacionEncodedCommand: lo que genera utf16LE + base64 debe poder
// ejecutarse con -EncodedCommand y devolver exactamente el codigo de salida
// esperado (10 = Copiar, 20 = Cerrar). Si la codificacion fallara,
// powershell saldria con 1 y el arranque degradaria a "continuar".
func TestCodificacionEncodedCommand(t *testing.T) {
	casos := []struct {
		script string
		want   int
	}{
		{"exit 10", 10},
		{"exit 20", 20},
		{"exit 0", 0},
	}
	for _, c := range casos {
		cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive",
			"-EncodedCommand", base64.StdEncoding.EncodeToString(utf16LE(c.script)))
		_ = cmd.Run()
		if got := cmd.ProcessState.ExitCode(); got != c.want {
			t.Errorf("script %q: exit = %d, esperaba %d", c.script, got, c.want)
		}
	}
}
