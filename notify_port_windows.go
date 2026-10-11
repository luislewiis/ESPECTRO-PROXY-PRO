//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

// notificacionScript construye el codigo PowerShell de la notificacion
// flotante (WinForms) con los textos ya sustituidos. Separado de la ejecucion
// para poder validar la sintaxis del script en tests (TestNotificacionScriptParsea)
// sin abrir ninguna ventana.
func notificacionScript(cambios []cambioPuerto, urlCopia string) string {
	var texto strings.Builder
	texto.WriteString("ESPECTRO PROXY PRO - puerto ocupado\r\n\r\n")
	for _, c := range cambios {
		fmt.Fprintf(&texto, "El puerto %d (%s) esta en uso.\r\nSe usara el puerto %d en su lugar.\r\n\r\n",
			c.viejo, c.que, c.nuevo)
	}
	texto.WriteString(urlCopia)
	// Los puertos viejos se pasan para que el script identifique al proceso
	// culpable (Docker, otra instancia, etc.) con Get-NetTCPConnection.
	var viejos []string
	for _, c := range cambios {
		viejos = append(viejos, fmt.Sprintf("%d", c.viejo))
	}

	script := `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$f = New-Object System.Windows.Forms.Form
$f.Text = 'ESPECTRO PROXY PRO'
$f.FormBorderStyle = 'FixedDialog'
$f.MaximizeBox = $false
$f.StartPosition = 'CenterScreen'
$f.TopMost = $true
$f.ClientSize = New-Object System.Drawing.Size(470,265)
$l = New-Object System.Windows.Forms.Label
$l.AutoSize = $false
$l.Size = New-Object System.Drawing.Size(435,175)
$l.Location = New-Object System.Drawing.Point(15,15)
$texto = '%%TEXTO%%'
$nombres = @()
foreach ($p in ('%%PUERTOS%%') -split ',') {
  try {
    $c = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) {
      $n = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
      if ($n -and $nombres -notcontains $n) { $nombres += $n }
    }
  } catch {}
}
if ($nombres.Count -gt 0) { $texto += [string][char]13 + [string][char]10 + [string][char]13 + [string][char]10 + 'Proceso que lo ocupa: ' + ($nombres -join ', ') }
$l.Text = $texto
$mk = { param($txt,$x)
  $b = New-Object System.Windows.Forms.Button
  $b.Text = $txt
  $b.Size = New-Object System.Drawing.Size(135,36)
  $b.Location = New-Object System.Drawing.Point($x,215)
  $b
}
$b1 = & $mk 'Continuar' 15
$b1.DialogResult = [System.Windows.Forms.DialogResult]::OK
$b2 = & $mk 'Copiar URL' 160
$b2.DialogResult = [System.Windows.Forms.DialogResult]::Yes
$b3 = & $mk 'Cerrar' 305
$b3.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$f.Controls.AddRange(@($l,$b1,$b2,$b3))
$f.AcceptButton = $b1
$f.CancelButton = $b3
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 20000
$handler = { $timer.Stop(); $f.Close() }
$timer.Add_Tick($handler)
$f.Add_Shown({ $timer.Start(); $f.Activate() | Out-Null })
$r = $f.ShowDialog()
$timer.Dispose()
$f.Dispose()
if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
  try { Set-Clipboard -Value '%%URL%%' } catch {}
  exit 10
}
if ($r -eq [System.Windows.Forms.DialogResult]::Cancel) { exit 20 }
exit 0`

	// Escapado de comillas simples para el literal PS ('texto').
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	script = strings.ReplaceAll(script, "%%TEXTO%%", esc(texto.String()))
	script = strings.ReplaceAll(script, "%%PUERTOS%%", strings.Join(viejos, ","))
	script = strings.ReplaceAll(script, "%%URL%%", esc(urlCopia))
	return script
}

// notificarCambiosPuerto muestra una notificacion flotante (WinForms) cuando
// algun puerto estaba ocupado y hubo que cambiarlo al arrancar. Botones:
//
//	Continuar -> seguir con los puertos nuevos (tambien con ESC, timeout
//	             de 20s o cualquier fallo: nunca bloquea el arranque)
//	Copiar    -> copia "gateway + panel" al portapapeles y sigue
//	Cerrar    -> el usuario pide salir (la app se detiene limpiamente)
//
// Devuelve "continuar", "copiar" o "cerrar". El caller solo la invoca en
// sesion interactiva real (consola o --window, sin --no-notify); el chequeo
// de CI aqui es defensa en profundidad para automatizaciones. Su timeout y
// los exit codes altos garantizan que jamas puede bloquear el arranque.
func notificarCambiosPuerto(cambios []cambioPuerto, urlCopia string) string {
	if os.Getenv("CI") != "" || len(cambios) == 0 {
		return "continuar"
	}

	// -EncodedCommand exige UTF-16LE en base64 (evita problemas de escaping).
	enc := base64.StdEncoding.EncodeToString(utf16LE(notificacionScript(cambios, urlCopia)))
	cmd := exec.Command("powershell", "-NoProfile", "-STA", "-NonInteractive",
		"-WindowStyle", "Hidden", "-EncodedCommand", enc)
	if err := cmd.Start(); err != nil {
		return "continuar" // sin PowerShell: no bloquea, sigue con el puerto nuevo
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(25 * time.Second): // timeout por si el usuario no toca nada
		_ = cmd.Process.Kill()
		<-done
		return "continuar"
	}
	// Codigos altos (10/20) para que un crash de PowerShell (exit 1 u otro)
	// caiga en "continuar" y nunca en "cerrar".
	switch cmd.ProcessState.ExitCode() {
	case 10: // Copiar URL
		return "copiar"
	case 20: // Cerrar
		return "cerrar"
	default: // Continuar, ESC, timeout del timer interno (20s) o error
		return "continuar"
	}
}

// utf16LE codifica una cadena como UTF-16 little-endian (formato de
// -EncodedCommand de PowerShell).
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return b
}
