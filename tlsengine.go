package main

// Modo uTLS: delegar la peticion en un motor TLS externo.
//
// Que es: el TLS_v13_MASTER.exe (Nuitka) lanza un motor en Go
// (HVN_TLS_Engine.exe) que hace la peticion CON LA HUELLA TLS que elijas
// (tls_client: chrome_131, firefox_120, safari_ios_18_5, okhttp4_android_*,
// mms_ios_*, mesh_ios_*, nike/zalando android, confirmed_ios/android...).
//
// Su API (127.0.0.1:9150, cabecera X-HVN-Key) es:
//	POST /hvn/forward  {url, method, headers, body_b64, profile, proxy,
//	                    timeout_ms, follow_redirects}
//	-> {status, headers, body_b64, proto, profile, latency_ms, won, error}
//	GET  /hvn/ping     -> {engine, ok, profiles:[...]}
//
// Lo que aporta al gateway: el motor NO lee HTTP(S)_PROXY, pero SI acepta
// el campo "proxy" -> se le puede encadenar con NUESTRO gateway para que la
// peticion salga por el POOL de proxies (y no con la IP real de la maquina).
//
// Limitacion importante: el motor hace peticiones COMPLETAS, no tuneles.
// Para el trafico https en forma CONNECT (que es lo que hacen OpenBullet y
// SilverBullet) haria falta terminar el TLS aqui (MITM); este modo cubre la
// via HTTP en forma absoluta.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// tlsEngineRequest: lo que espera /hvn/forward.
type tlsEngineRequest struct {
	URL             string            `json:"url"`
	Method          string            `json:"method,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	BodyB64         string            `json:"body_b64,omitempty"`
	Profile         string            `json:"profile,omitempty"`
	Proxy           string            `json:"proxy,omitempty"`
	TimeoutMS       int               `json:"timeout_ms,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`
}

// tlsEngineReply: lo que devuelve /hvn/forward.
type tlsEngineReply struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	BodyB64   string            `json:"body_b64"`
	Proto     string            `json:"proto"`
	Profile   string            `json:"profile"`
	LatencyMS int               `json:"latency_ms"`
	Won       bool              `json:"won"`
	Error     string            `json:"error"`
	ID        string            `json:"id"`
}

// checkEngineExposure: el launcher del TLS_v13 (la GUI) expone su API en
// 0.0.0.0:<puerto> (9000 por defecto), o sea, accesible desde la red local:
// cualquiera del LAN puede usar tu motor uTLS y tu licencia. El motor Go
// (9150) si escucha solo en loopback, pero el launcher no.
//
// Comprobacion: se intenta conectar a la IP LAN de esta maquina en el puerto
// del launcher. Si responde, esta EXPUESTO -> se avisa (sin tocar su
// configuracion: el aviso es informativo y el fix lo pone el usuario).
func (a *App) checkEngineExposure(launcherPort int) {
	if launcherPort <= 0 {
		launcherPort = 9000
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, ad := range addrs {
		ipn, ok := ad.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		ip := ipn.IP.String()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(launcherPort)), 700*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()
		a.mu.Lock()
		a.tlsEngineWarn = fmt.Sprintf(
			"AVISO DE SEGURIDAD: la API del TLS_v13_MASTER responde en %s:%d (0.0.0.0). "+
				"Cualquier equipo de tu red puede usar tu motor uTLS y tu licencia. "+
				"El motor Go (9150) si es local, pero el launcher no. "+
				"Para cerrarlo: bloquea ese puerto en el firewall de Windows "+
				"(netsh advfirewall firewall add rule name=block-TLSv13 dir=in action=block remoteip=localsubnet)",
			ip, launcherPort)
		a.mu.Unlock()
		a.logf("%s", a.tlsEngineWarn)
		return
	}
}

// engineClient: cliente HTTP del motor (timeout propio, sin proxy del sistema:
// el motor es local y no debe hereditar HTTP_PROXY del entorno).
func (a *App) engineClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil, // el motor es local: nunca por el proxy del sistema
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// engineForward: llama a /hvn/forward y devuelve la respuesta del destino.
func (a *App) engineForward(req tlsEngineRequest) (*tlsEngineReply, error) {
	base := strings.TrimRight(a.tlsEngineURL, "/")
	if base == "" {
		return nil, fmt.Errorf("motor TLS no configurado")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, base+"/hvn/forward", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if a.tlsEngineKey != "" {
		httpReq.Header.Set("X-HVN-Key", a.tlsEngineKey)
	}
	resp, err := a.engineClient(a.tlsEngineTimeout).Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var rep tlsEngineReply
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("respuesta del motor no valida: %s", truncate(string(raw), 160))
	}
	if rep.Error != "" {
		return nil, fmt.Errorf("motor: %s", rep.Error)
	}
	return &rep, nil
}

// enginePing: consulta /hvn/ping (estado del motor y perfiles disponibles).
func (a *App) enginePing() (map[string]interface{}, error) {
	base := strings.TrimRight(a.tlsEngineURL, "/")
	if base == "" {
		return nil, fmt.Errorf("motor TLS no configurado")
	}
	req, err := http.NewRequest(http.MethodGet, base+"/hvn/ping", nil)
	if err != nil {
		return nil, err
	}
	if a.tlsEngineKey != "" {
		req.Header.Set("X-HVN-Key", a.tlsEngineKey)
	}
	resp, err := a.engineClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ping del motor no valido")
	}
	return out, nil
}

// engineProxyFor: la URL del gateway para que el motor salga por el POOL.
// Se le pasa el usuario de la sesion del cliente (sticker) para que la IP
// de salida sea la misma que en el resto del trafico.
func (a *App) engineProxyFor(session, country string, rotate bool) string {
	a.mu.Lock()
	base := a.gateway
	a.mu.Unlock()
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	user := "user"
	switch {
	case rotate:
		user = "user-rotate"
	case session != "":
		user = "user-session-" + session
	}
	if country != "" {
		user += "-country-" + strings.ToUpper(country)
	}
	u.User = url.UserPassword(user, "x")
	return u.String()
}

// engineURLFor: la URL que se pide al motor. Si el cliente pidio http:// y
// esta activo el "upgrade", se sube a https:// (asi la huella uTLS sirve de
// algo: es el TLS del destino el que se suplanta).
func (a *App) engineURLFor(u *url.URL) string {
	if u == nil {
		return ""
	}
	out := *u
	if out.Scheme == "http" && a.tlsUpgrade {
		out.Scheme = "https"
		if out.Port() == "80" || out.Port() == "" {
			out.Host = u.Hostname()
			if out.Host == "" {
				out.Host = "localhost"
			}
		}
	}
	return out.String()
}

// engineHeadersFor: cabeceras del cliente que se reenvian al motor.
// Se quitan las hop-by-hop y las que el motor recalcula (Host, Content-Length,
// Proxy-Authorization...).
func engineHeadersFor(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		lk := strings.ToLower(k)
		switch lk {
		case "connection", "proxy-connection", "proxy-authorization", "host",
			"content-length", "transfer-encoding", "upgrade", "te", "x-proxy-rotate":
			continue
		}
		if isStrippedHeader(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// handleViaEngine: atiende una peticion en forma absoluta delegandola en el
// motor TLS externo (uTLS) y devolviendo su respuesta al cliente.
// Devuelve false si el motor no pudo servirla (el llamador sigue con el
// relay normal por el pool).
func (a *App) handleViaEngine(client net.Conn, method string, u *url.URL, h map[string]string, body []byte, session, country string, rotate bool) bool {
	target := a.engineURLFor(u)
	if target == "" {
		return false
	}
	req := tlsEngineRequest{
		URL:             target,
		Method:          method,
		Headers:         engineHeadersFor(h),
		Profile:         a.tlsEngineProfile,
		Proxy:           a.engineProxyFor(session, country, rotate),
		TimeoutMS:       int(a.tlsEngineTimeout / time.Millisecond),
		FollowRedirects: true,
	}
	if len(body) > 0 {
		req.BodyB64 = base64.StdEncoding.EncodeToString(body)
	}
	rep, err := a.engineForward(req)
	if err != nil {
		a.stats.Errors.Add(1)
		a.logf("motor TLS fallo: %v", err)
		return false
	}
	payload, _ := base64.StdEncoding.DecodeString(rep.BodyB64)
	if body != nil {
		a.stats.BytesUp.Add(int64(len(body)))
	}
	a.stats.BytesDown.Add(int64(len(payload)))

	// Respuesta al cliente: status + cabeceras (sin hop-by-hop) + cuerpo.
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", rep.Status, http.StatusText(rep.Status))
	seenCT := false
	for k, v := range rep.Headers {
		lk := strings.ToLower(k)
		if lk == "content-length" {
			fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(payload))
			seenCT = true
			continue
		}
		if lk == "connection" || lk == "transfer-encoding" || lk == "content-encoding" {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	if !seenCT {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(payload))
	}
	sb.WriteString("Connection: close\r\n\r\n")
	client.Write([]byte(sb.String()))
	if len(payload) > 0 {
		client.Write(payload)
	}
	if !a.quiet {
		a.logf("%s %s via motor uTLS (%s, %d ms)", method, redactURL(truncate(target, 90)),
			rep.Profile, rep.LatencyMS)
	}
	return true
}
