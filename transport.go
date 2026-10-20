package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// transporteEntry envuelve el http.Transport reutilizable de UN upstream
// concreto (scheme|host:port|user).
type transporteEntry struct {
	t        *http.Transport
	lastUsed atomic.Int64
}

// transporteTTL: transporte sin uso durante este tiempo se recicla (se
// cierran sus conexiones idle y se borra de la cache). Los proxies
// publicos caducan: una conexion guardada hace 3 minutos suele estar
// muerta y conviene re-dial (el dial del proxy es el coste real).
const transporteTTL = 90 * time.Second

// transportePara devuelve el Transport cacheado para p. Antes, roundTrip
// construia un Transport NUEVO por peticion con DisableKeepAlives=true:
// cada request abria conexion TCP nueva contra el proxy (handshake
// completo) aunque fuera el mismo proxy de siempre (p. ej. una sesion
// sticky de OB). Con la cache la conexion se reutiliza: el coste por
// request baja de un RTT+handshake a cero en el caso fijo.
func (a *App) transportePara(p *Proxy) *http.Transport {
	key := p.Key()
	if v, ok := a.tp.Load(key); ok {
		// Asercion comprobada: un panic aqui tumbaria el gateway entero.
		if e, ok2 := v.(*transporteEntry); ok2 {
			e.lastUsed.Store(time.Now().UnixNano())
			return e.t
		}
	}
	e := &transporteEntry{t: &http.Transport{ // keep-alive ON: reutilizar conexiones al mismo upstream (sticky, y
		// rotacion con tasa alta sobre pool pequeno).
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       transporteTTL,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		DisableCompression:    true, // trafico de checker: sin gzip = menos CPU
		ForceAttemptHTTP2:     false,
	}}
	if p.EffScheme() == "http" {
		pu := &url.URL{Scheme: "http", Host: p.Addr()}
		if p.User != "" {
			pu.User = url.UserPassword(p.User, p.Password)
		}
		e.t.Proxy = http.ProxyURL(pu)
		// El dial de este Transport es contra el PROXY: sus fallos se
		// envuelven en upstreamError para que marquen muerto al proxy,
		// a diferencia de los errores post-CONNECT (web caida != proxy
		// muerto, ARQ-01).
		e.t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			timeout := dialUpTimeout
			if dl, ok := ctx.Deadline(); ok {
				if rest := time.Until(dl); rest < timeout {
					timeout = rest
				}
			}
			c, err := dialRaw(addr, timeout)
			if err != nil {
				return nil, &upstreamError{err}
			}
			return c, nil
		}
	} else {
		e.t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			timeout := dialUpTimeout
			if dl, ok := ctx.Deadline(); ok {
				if rest := time.Until(dl); rest < timeout {
					timeout = rest
				}
			}
			// bufConn: entrega primero los bytes bufferizados por el
			// handshake (respuestas tempranas del destino), que si no se
			// descartarian con el bufio de dialThrough.
			c, br, err := dialThrough(p, addr, timeout)
			if err != nil {
				return nil, err
			}
			return &bufConn{Conn: c, r: br}, nil
		}
	}
	// Fijar lastUsed ya en la creacion: si no, un entry recien creado y
	// aun no reusado pareceria "usado en epoch 0" y el sweeper lo barreria
	// en la siguiente pasada aunque este fresco.
	e.lastUsed.Store(time.Now().UnixNano())
	if v, loaded := a.tp.LoadOrStore(key, e); loaded {
		// Carrera con otra goroutine: se queda el ya guardado y el nuestro
		// se recicla (sus conexiones idle se cierran aqui).
		e.t.CloseIdleConnections()
		if w, ok2 := v.(*transporteEntry); ok2 {
			w.lastUsed.Store(time.Now().UnixNano())
			return w.t
		}
		return e.t
	}
	return e.t
}

// TransportSweeper recicla transports sin uso: cierra sus conexiones idle
// y los borra de la cache. Corre cada minuto junto al resto de tareas de
// fondo (una cache que solo crece mantendria conexiones a proxies ya
// retirados de las listas).
func (a *App) TransportSweeper() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		a.sweepTransportes(time.Now())
	}
}

// sweepTransportes cierra y borra de la cache los transports sin uso desde
// hace mas de transporteTTL. Solo se tocan conexiones IDLE: una peticion
// en vuelo sobre una conexion activa termina igual.
func (a *App) sweepTransportes(now time.Time) {
	limite := now.Add(-transporteTTL).UnixNano()
	a.tp.Range(func(k, v any) bool {
		e, ok := v.(*transporteEntry)
		if !ok {
			return true
		}
		if e.lastUsed.Load() < limite {
			e.t.CloseIdleConnections()
			a.tp.Delete(k)
		}
		return true
	})
}
