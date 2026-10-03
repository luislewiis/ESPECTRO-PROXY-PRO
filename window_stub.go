//go:build !windows

package main

func ocultarConsola()           {}
func mostrarConsola()           {}
func cerrarConsolaPropia() bool { return false }

func abrirVentana(string, bool) bool { return false }
