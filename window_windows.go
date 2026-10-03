//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

var (
	k32             = syscall.NewLazyDLL("kernel32.dll")
	u32             = syscall.NewLazyDLL("user32.dll")
	procGetConsoleH = k32.NewProc("GetConsoleWindow")
	procShowWindow  = u32.NewProc("ShowWindow")
	procGetConsoleP = k32.NewProc("GetConsoleProcessList")
	procFreeConsole = k32.NewProc("FreeConsole")
)

// ocultarConsola esconde la ventana de consola SOLO si este proceso es el
// unico que la usa (doble-click). Si la consola es compartida (lanzado desde
// una terminal del usuario o por tests), no se toca: ocultaria la terminal ajena.
func ocultarConsola() {
	h, _, _ := procGetConsoleH.Call()
	if h == 0 {
		return
	}
	buf := make([]uint32, 2)
	n, _, _ := procGetConsoleP.Call(uintptr(unsafe.Pointer(&buf[0])), 2)
	if n == 1 { // somos los unicos en esta consola -> es nuestra
		procShowWindow.Call(h, 0) // SW_HIDE
	}
}

// cerrarConsolaPropia ELIMINA la consola cuando es exclusiva de este
// proceso (doble-click o terminal propia): no deja pestaña/ventana de
// consola abierta y el programa queda unicamente dentro de la ventana del
// panel (consola "dentro" del programa). Con consola compartida no hace
// nada (devuelve false y el llamador cae a ocultarConsola). Tras
// FreeConsole, los handles de stdout redirigidos a fichero/pipe siguen
// validos: los tests con salida capturada no se ven afectados.
func cerrarConsolaPropia() bool {
	buf := make([]uint32, 2)
	n, _, _ := procGetConsoleP.Call(uintptr(unsafe.Pointer(&buf[0])), 2)
	if n != 1 {
		// consola compartida (lanzado desde una terminal del usuario) o sin
		// consola: no se toca y se deja constancia en el Log del panel.
		if logConsola != nil {
			logConsola("consola no cerrada (procesos en la terminal: %d)", int(n))
		}
		return false
	}
	r, _, _ := procFreeConsole.Call()
	if logConsola != nil {
		if r != 0 {
			logConsola("consola propia cerrada; el programa queda solo en la ventana del panel")
		} else {
			logConsola("FreeConsole no funciono: se deja la consola oculta")
		}
	}
	return r != 0
}

// mostrarConsola restaura la consola (fallback al navegador).
func mostrarConsola() {
	h, _, _ := procGetConsoleH.Call()
	if h != 0 {
		procShowWindow.Call(h, 5) // SW_SHOW
	}
}

// webview2Disponible comprueba si el runtime Evergreen de WebView2 esta
// instalado (evita que go-webview2 llame a log.Fatal y mate el proceso).
func webview2Disponible() bool {
	var dirs []string
	if pf86 := os.Getenv("ProgramFiles(x86)"); pf86 != "" {
		dirs = append(dirs, filepath.Join(pf86, "Microsoft", "EdgeWebView", "Application"))
	}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		dirs = append(dirs, filepath.Join(pf, "Microsoft", "EdgeWebView", "Application"))
	}
	if lad := os.Getenv("LOCALAPPDATA"); lad != "" {
		dirs = append(dirs, filepath.Join(lad, "Microsoft", "EdgeWebView", "Application"))
	}
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// abrirVentana abre el panel en una ventana WebView2 nativa y bloquea hasta
// que el usuario la cierra (al cerrarla el proceso termina). Devuelve false
// si WebView2 no esta disponible, para que el llamador caiga al navegador.
// Si “ocultar“ es true (arranque tipico con doble-click) la consola propia
// se CIERRA del todo al crear la ventana: el programa queda solo en el panel.
func abrirVentana(url string, ocultar bool) (ok bool) {
	if !webview2Disponible() {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			mostrarConsola()
			ok = false
		}
	}()
	dataPath := dataPathWebview()
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  dataPath,
		WindowOptions: webview2.WindowOptions{
			Title:  "ESPECTRO PROXY PRO",
			Width:  1280,
			Height: 860,
			Center: true,
		},
	})
	if w == nil {
		mostrarConsola()
		os.RemoveAll(dataPath)
		return false
	}
	if ocultar {
		if !cerrarConsolaPropia() {
			// consola compartida (lanzado desde la terminal del usuario) o
			// FreeConsole fallo: si somos los unicos, al menos ocultarla.
			ocultarConsola()
		}
	}
	// ocultar=false (--console o sin terminal interactiva): la consola no se
	// toca; con --console se queda visible como promete el flag.
	w.Navigate(url)
	w.Run()
	w.Destroy()
	os.RemoveAll(dataPath)
	return true
}

// dataPathWebview devuelve un perfil WebView2 privativo de esta instancia.
// Por defecto WebView2 usa %APPDATA%\<nombre-del-exe>: si una segunda
// instancia de ProxyGateway.exe arranca mientras otra tiene la ventana
// abierta, la creacion del entorno se bloquea y la ventana queda congelada
// sin bombear mensajes. Un perfil por PID evita ese choque; el panel no
// persiste nada en el perfil, asi que no se pierde estado.
func dataPathWebview() string {
	dp := filepath.Join(os.TempDir(), "gw_webview", strconv.Itoa(os.Getpid()))
	os.MkdirAll(dp, 0o700)
	return dp
}
