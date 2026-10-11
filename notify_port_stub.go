//go:build !windows

package main

// notificarCambiosPuerto: en no-Windows no hay notificacion flotante; el
// cambio de puerto ya queda informado por consola (log de arranque) y la
// app sigue con el puerto nuevo. Nunca bloquea.
func notificarCambiosPuerto(_ []cambioPuerto, _ string) string { return "continuar" }
