package main

import (
	"fmt"
	"testing"
)

// Benchmark del pick con 24k proxies (C2): antes de los indices O(1) el
// coste era ~1.240.968 ns/op + 998.473 B/op + 19 allocs por la construccion
// del slice de candidatos en cada llamada.
func benchApp(n int) *App {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = make([]*Proxy, n)
	for i := range a.proxies {
		a.proxies[i] = &Proxy{
			Scheme: "http",
			Host:   fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255),
			Port:   8080 + i%60000,
			Alive:  i%3 != 0,
		}
	}
	return a
}

func BenchmarkPickRR24k(b *testing.B) {
	a := benchApp(24000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if a.pick("", nil) == nil {
			b.Fatal("nil")
		}
	}
}

func BenchmarkPickSticky24k(b *testing.B) {
	a := benchApp(24000)
	a.strategy = "sticky"
	a.pick("sesion-bench", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if a.pick("sesion-bench", nil) == nil {
			b.Fatal("nil")
		}
	}
}

func BenchmarkCounts24k(b *testing.B) {
	a := benchApp(24000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.counts()
	}
}
