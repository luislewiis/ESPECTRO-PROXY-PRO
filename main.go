package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

// pausaSiConsola espera Enter antes de salir para que la ventana de
// doble-click no desaparezca de inmediato. Si stdin no es consola (tests,
// pipes), no pausa. Restaura la consola previamente oculta para que el
// usuario vea el error.
func pausaSiConsola() {
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return
	}
	mostrarConsola()
	fmt.Println("\nPresiona Enter para salir...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// stdinEsConsola indica si hay una consola interactiva (doble-click/terminal).
func stdinEsConsola() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// debeOcultarConsola: en doble-click con panel abierto la consola se oculta
// (los logs quedan en la pestaña Log del panel). Se mantiene visible con
// --console, --no-browser (modo headless), --check-now (imprime y sale) o
// cuando no hay consola interactiva (tests/servicios).
func debeOcultarConsola(showConsole, noBrowser, checkNow, consolaInteractiva bool) bool {
	return !showConsole && !noBrowser && !checkNow && consolaInteractiva
}

// logConsola lleva el veredicto sobre la consola terminal a la pestaña Log
// del panel ("consola propia cerrada" / "consola compartida..."). Se asigna
// al crear la App en main(); en no-Windows queda sin usar.
var logConsola func(format string, args ...interface{})

var listasDefault = []string{"proxies.txt", "proxy.txt", "lista.txt", "lista_proxies.txt"}

const plantillaLista = `# ESPECTRO PROXY PRO - una linea por proxy (formatos soportados):
#   1.2.3.4:8080
#   usuario:clave@1.2.3.4:8080
#   socks5://1.2.3.4:1080
#   0:1.2.3.4:8080::          (formato OB: tipo:host:puerto:user:pass)
#
# Pega aqui tus proxies y pulsa "Recargar listas" en el panel.
`

// crearPlantilla escribe proxies.txt (con ejemplos comentados) junto al exe
// o en el cwd. Devuelve la ruta creada. Si ya existe algun .txt, no hace nada.
func crearPlantilla() string {
	dir := ""
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	if cwd, err := os.Getwd(); err == nil && dir == "" {
		dir = cwd
	}
	path := "proxies.txt"
	if dir != "" {
		path = filepath.Join(dir, "proxies.txt")
	}
	if err := os.WriteFile(path, []byte(plantillaLista), 0644); err != nil {
		return ""
	}
	return path
}

// abrirURL abre una URL en el navegador por defecto (doble-click UX).
func abrirURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// findDefaultList busca una lista por defecto en el cwd y junto al exe
// para que el doble-click funcione sin argumentos.
func findDefaultList() string {
	for _, name := range listasDefault {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range listasDefault {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func usageYSal() {
	fmt.Fprintln(os.Stderr, "ERROR: no se encontro ningun archivo .txt de proxies")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "ESPECTRO PROXY PRO")
	fmt.Fprintln(os.Stderr, "Uso:   ProxyGateway.exe proxies.txt [--http-port 8080] [--api-port 8081]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Tip: crea un archivo 'proxies.txt' junto al exe (una linea por proxy):")
	fmt.Fprintln(os.Stderr, "     1.2.3.4:8080")
	fmt.Fprintln(os.Stderr, "     usuario:clave@1.2.3.4:8080")
	fmt.Fprintln(os.Stderr, "     socks5://1.2.3.4:1080")
	fmt.Fprintln(os.Stderr, "     0:1.2.3.4:8080::          (formato OB)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Luego: panel en http://127.0.0.1:8081/panel")
	pausaSiConsola()
	os.Exit(2)
}

// reorderArgs mueve los flags delante de los archivos posicionales para que
// el paquete flag de Go los procese (acepta: ProxyGateway.exe lista.txt --http-port 9090)
func reorderArgs() {
	valueFlags := map[string]bool{
		"bind": true, "http-port": true, "api-port": true, "strategy": true,
		"check-interval": true, "check-batch": true, "test-url": true,
		"api-token": true, "idle-timeout": true, "state-file": true,
		"check-timeout": true, "check-retries": true,
	}
	args := os.Args[1:]
	var flags, files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			files = append(files, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(a, "=") && valueFlags[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			files = append(files, a)
		}
	}
	os.Args = append([]string{os.Args[0]}, append(flags, files...)...)
}

func main() {
	// Panic recovery (herencia Security Shield V3): un panic en main imprime
	// el error y mantiene la consola visible (en doble-click la ventana se
	// cerraria sin que el usuario viera nada). Los defers NO corren con
	// os.Exit de los errores de arranque (ahi ya hay mensaje + pausa).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[gw] PANICO: %v\n%s\n", r, debug.Stack())
			pausaSiConsola()
		}
	}()

	reorderArgs()
	bind := flag.String("bind", "127.0.0.1", "direccion de escucha")
	httpPort := flag.Int("http-port", 8080, "puerto del gateway proxy")
	apiPort := flag.Int("api-port", 8081, "puerto de la API y el panel")
	strategy := flag.String("strategy", "round-robin", "round-robin | random | sticky")
	checkInterval := flag.Int("check-interval", 60, "segundos entre health-checks (0 = off)")
	checkBatch := flag.Int("check-batch", 1000, "proxies chequeados por ciclo de health-check (0 = todos)")
	testURL := flag.String("test-url", "http://api.ipify.org/", "URL usada para validar proxies")
	checkNow := flag.Bool("check-now", false, "validar una vez y salir")
	quiet := flag.Bool("quiet", false, "no loguea cada peticion")
	noBrowser := flag.Bool("no-browser", false, "no abrir la ventana ni el navegador del panel")
	window := flag.Bool("window", false, "abrir la ventana del panel aunque no haya consola")
	showConsole := flag.Bool("console", false, "mantener visible la ventana de consola (por defecto se oculta en doble-click)")
	apiToken := flag.String("api-token", "", "token opcional: exige X-API-Token en mutantes y en lecturas sensibles (/proxies, /proxy.txt, /checker/hits|export)")
	allowAnyPath := flag.Bool("allow-any-path", false, "permitir /validate y /import con rutas fuera de los directorios permitidos")
	idleTimeout := flag.Int("idle-timeout", 600, "segundos de inactividad maxima en conexiones (0 = off) - watchdog RED-01")
	checkTimeoutMs := flag.Int("check-timeout", 5000, "timeout en ms por intento de health-check")
	checkRetries := flag.Int("check-retries", 1, "reintentos extra por proxy antes de darlo por muerto (0 = sin reintentos)")
	checkAll := flag.Bool("check-all", false, "el auto-check revisa tambien los muertos verificados (default: solo vivos + sin verificar)")
	noState := flag.Bool("no-state", false, "no persistir el estado de analisis (no crea <lista>.state.json)")
	stateFileFlag := flag.String("state-file", "", "ruta del archivo de estado persistente (default: <lista>.state.json)")
	showVersion := flag.Bool("version", false, "imprime la version y la licencia y sale")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ESPECTRO PROXY PRO %s\n", version)
		if buildDate != "" {
			fmt.Printf("build: %s\n", buildDate)
		}
		fmt.Printf("licencia: %s\n", licDesc())
		return
	}

	if *bind != "127.0.0.1" && *bind != "localhost" && *bind != "::1" {
		fmt.Printf("[gw] AVISO: --bind %s expone el gateway y la API SIN autenticacion a la red local. Usa un firewall o --api-token.\n", *bind)
	}

	// doble-click UX: oculta la consola ya al arrancar (evita el parpadeo
	// de la ventana CMD); en errores se restaura en pausaSiConsola.
	if debeOcultarConsola(*showConsole, *noBrowser, *checkNow, stdinEsConsola()) {
		ocultarConsola()
	}

	files := ExpandGlobs(flag.Args())
	if len(files) == 0 {
		if def := findDefaultList(); def != "" {
			files = []string{def}
			fmt.Printf("[gw] sin argumentos: usando lista por defecto -> %s\n", def)
		} else if tpl := crearPlantilla(); tpl != "" {
			files = []string{tpl}
			fmt.Printf("[gw] primera ejecucion: creado %s con plantilla de ejemplo\n", tpl)
			fmt.Println("[gw] pega tus proxies ahi y pulsa 'Recargar listas' en el panel")
		} else {
			usageYSal()
		}
	}
	if *strategy != "round-robin" && *strategy != "random" && *strategy != "sticky" {
		fmt.Fprintln(os.Stderr, "ERROR: --strategy debe ser round-robin, random o sticky")
		pausaSiConsola()
		os.Exit(2)
	}

	app := NewApp(files, *strategy, *quiet, *checkInterval, *testURL)
	app.logf("licencia: %s", licDesc())
	app.apiToken = *apiToken
	app.allowAnyPath = *allowAnyPath
	app.checkBatch = *checkBatch
	app.checkTimeout = time.Duration(*checkTimeoutMs) * time.Millisecond
	app.checkRetries = *checkRetries
	app.checkAll = *checkAll
	app.stateDisabled = *noState
	app.stateFile = *stateFileFlag
	if *idleTimeout > 0 {
		app.idle = time.Duration(*idleTimeout) * time.Second
	}
	logConsola = app.logf
	// Estado persistente: se carga ANTES de la lista para fusionarlo
	// (memoria > disco > default) y se guarda al salir (reinicio/reload
	// no re-analiza desde cero).
	app.loadState()
	defer app.saveState()
	app.LoadProxies()
	_, total := app.counts()
	if total == 0 && *checkNow {
		fmt.Fprintln(os.Stderr, "ERROR: no se cargo ningun proxy. Ejemplo de linea: 1.2.3.4:8080")
		pausaSiConsola()
		os.Exit(2)
	}
	if total == 0 {
		fmt.Println("[gw] AVISO: 0 proxies cargados - edita la lista y pulsa 'Recargar listas' en el panel")
	}

	if *checkNow {
		app.RunChecks()
		app.mu.Lock()
		for _, p := range app.proxies {
			if p.Alive {
				fmt.Printf("OK   %s\n", p.Tag())
			} else {
				fmt.Printf("DEAD %s\n", p.Tag())
			}
		}
		app.mu.Unlock()
		return
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *bind, *httpPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: no se pudo abrir el puerto %d: %v\n", *httpPort, err)
		fmt.Fprintln(os.Stderr, "       (¿ya hay otra instancia corriendo? usa --http-port 9090)")
		pausaSiConsola()
		os.Exit(1)
	}
	go app.ServeGateway(ln)

	lnAPI, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *bind, *apiPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: no se pudo abrir el puerto %d: %v\n", *apiPort, err)
		pausaSiConsola()
		os.Exit(1)
	}
	// MaxHeaderBytes: tope de cabeceras de la API (64 KB) — sin esto un
	// cliente podia enviar cabeceras enormes hasta agotar memoria.
	apiSrv := &http.Server{
		Handler:           app.APIMux(*httpPort, *bind),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go apiSrv.Serve(lnAPI)

	go app.CheckerLoop()
	go app.SessionSweeper()

	apiBase := fmt.Sprintf("http://%s:%d", *bind, *apiPort)
	// El banner informativo (marca, endpoints, estrategia, estado) vive
	// DENTRO del programa: seccion "Info de arranque" del panel y pagina /.
	// La consola solo emite eventos.
	if !*noBrowser && !*checkNow && (stdinEsConsola() || *window) {
		ocultar := debeOcultarConsola(*showConsole, *noBrowser, *checkNow, stdinEsConsola())
		if logConsola != nil {
			if ocultar {
				logConsola("ventana del panel: la consola terminal se cerrara al crearse")
			} else {
				logConsola("ventana del panel: se mantiene la consola (--console o sin terminal propia)")
			}
		}
		if abrirVentana(apiBase+"/panel", ocultar) {
			fmt.Println("\n[gw] ventana cerrada - detenido")
			return
		}
		mostrarConsola()
		abrirURL(apiBase + "/panel")
		fmt.Printf("[gw] panel abierto en el navegador (%s/panel) - usa --no-browser para desactivar\n", apiBase)
	} else {
		fmt.Printf("[gw] panel: %s/panel\n", apiBase)
	}

	// Salida limpia: Ctrl+C (y SIGTERM en servicios Linux) drena la API
	// (Shutdown con tope de 3s), cierra el listener del gateway y los
	// defers (saveState) se ejecutan al salir de main.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\n[gw] deteniendo...")
	// Salvavidas del checker masivo: si hay un job en marcha, cancelarlo y
	// esperar a que vuelque vivos + Report.json (herencia EspectroProxy:
	// Ctrl+C guardaba lo analizado antes de morir).
	if !app.massShutdown(10 * time.Second) {
		fmt.Println("[gw] aviso: el checker masivo no llego a guardarse antes del cierre")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = apiSrv.Shutdown(ctx)
	cancel()
	ln.Close() // ServeGateway sale con net.ErrClosed
	fmt.Println("[gw] detenido")
}
