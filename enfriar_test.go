package main

import (
	"testing"
	"time"
)

func appConProxies(n int) *App {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = make([]*Proxy, n)
	for i := range a.proxies {
		a.proxies[i] = &Proxy{Scheme: "http", Host: "10.0.0.1", Port: 8000 + i, Alive: true}
	}
	return a
}

// Con pool grande, un proxy que acaba de fallar se aparta de la rotacion:
// es el fix de las corridas que "se pausan" (cada bot pagaba 4-16s
// reintentando el mismo proxy muerto).
func TestEnfriamientoApartaFallados(t *testing.T) {
	a := appConProxies(20)
	malo := a.proxies[7]
	a.markFail(malo) // 1 fallo: sigue vivo pero enfriado

	visto := false
	for i := 0; i < 200; i++ {
		if p := a.pick("", nil); p == malo {
			visto = true
			break
		}
	}
	if visto {
		t.Error("un proxy recien fallado no deberia salir en la rotacion")
	}
	// los demas siguen saliendo
	if a.pick("", nil) == nil {
		t.Error("la rotacion no deberia quedarse sin proxies")
	}
}

// Pool pequeno: NO se enfria (si solo hay 3 proxies hay que probarlos todos;
// ademas los tests con listas cortas dependen de ver los fallos).
func TestEnfriamientoNoAplicaAPoolsPequenos(t *testing.T) {
	a := appConProxies(4)
	malo := a.proxies[2]
	a.markFail(malo)

	visto := false
	for i := 0; i < 50; i++ {
		if p := a.pick("", nil); p == malo {
			visto = true
			break
		}
	}
	if !visto {
		t.Error("con pool pequeno el proxy enfriado debe seguir saliendo")
	}
}

// Caducado el enfriamiento, el proxy vuelve a la rotacion (los publicos se
// recuperan) y markOK lo readmite de inmediato.
func TestEnfriamientoCaducaYMarkOKReincorpora(t *testing.T) {
	a := appConProxies(20)
	malo := a.proxies[3]
	a.markFail(malo)
	// caducar a mano
	a.mu.Lock()
	a.enfriar[malo.Key()] = time.Now().Unix() - 1
	a.mu.Unlock()

	visto := false
	for i := 0; i < 100; i++ {
		if p := a.pick("", nil); p == malo {
			visto = true
			break
		}
	}
	if !visto {
		t.Error("caducado el enfriamiento el proxy debe volver a salir")
	}

	a.markFail(malo)
	a.markOK(malo) // trafico correcto: readmitido al instante
	visto = false
	for i := 0; i < 100; i++ {
		if p := a.pick("", nil); p == malo {
			visto = true
			break
		}
	}
	if !visto {
		t.Error("tras markOK el proxy debe volver a la rotacion de inmediato")
	}
}
