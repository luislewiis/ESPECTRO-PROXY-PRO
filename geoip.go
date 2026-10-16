package main

// GeoIP offline: lector minimo del formato MaxMind DB (.mmdb) sin
// dependencias externas. Lee las mismas bases que usa el Proxy Checker de
// referencia (GeoLite2-Country.mmdb / DbipLite-Country.mmdb): pais del proxy
// por busqueda LOCAL, sin juez, sin limites de tasa (ip-api.com gratis corta
// a ~45 consultas/min: con miles de hilos casi todo pais salia vacio) y sin
// mandar la lista de proxies a un tercero.
//
// Formato: https://maxmind.github.io/MaxMind-DB/ (v2.0)
//   - arbol binario de busqueda: node_count nodos, record_size bits por
//     registro, dos registros por nodo (big-endian).
//   - separador de 16 bytes NULOS entre el arbol y la seccion de datos.
//   - metadata al final, tras el ultimo "\xab\xcd\xefMaxMind.com".
//
//	offset_en_fichero = (valor_registro - node_count) + tamaño_arbol
//	punteros: relativos al inicio de la seccion de datos (o de la metadata
//	cuando se decodifica la propia metadata).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

// Limites de decodificacion (spec, "Reader Resource Limits"): una base
// corrupta o maliciosa no debe poder colgar ni inflar el proceso.
const (
	mmdbMaxDepth = 512
	mmdbMaxVals  = 65536
	mmdbMaxBytes = 8 << 20
	mmdbCacheMax = 250000
	mmdbSepSize  = 16
	mmdbMetaMax  = 128 << 10
)

// geoDB: base MaxMind DB abierta en memoria.
type geoDB struct {
	buf     []byte
	dataOff int // inicio de la seccion de datos (fin del arbol + separador)
	nodeCnt int
	recSize int
	ipv6    bool

	dbType string
	built  int64
	desc   string
	ipv4   int // nodo de arranque del subarbol IPv4 (bases v6); -1 = sin calcular

	nCache atomic.Int64
	cache  sync.Map // ip (string) -> pais (string); "" tambien se cachea
}

// openGeoDB carga y valida una base .mmdb.
func openGeoDB(path string) (*geoDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 64 {
		return nil, errors.New("archivo mmdb invalido (demasiado corto)")
	}
	idx := bytes.LastIndex(b, mmdbMarker)
	if idx < 0 {
		return nil, errors.New("no es una base MaxMind DB (falta el marcador de metadata)")
	}
	if len(b)-idx > mmdbMetaMax {
		return nil, errors.New("metadata mmdb fuera de rango")
	}
	g := &geoDB{buf: b, ipv4: -1}

	// La metadata es un mapa al final del fichero. Sus punteros son
	// relativos al inicio de la metadata: se prueban los dos convenios
	// posibles (inicio del marcador / primer byte del mapa) y se acepta el
	// que produzca un mapa con node_count.
	meta := idx + len(mmdbMarker)
	md := g.decodeMeta(meta, idx)
	if md == nil {
		md = g.decodeMeta(meta, meta)
	}
	if md == nil {
		return nil, errors.New("metadata mmdb ilegible")
	}
	nodeCnt := mmdbInt(md["node_count"])
	recSize := mmdbInt(md["record_size"])
	if nodeCnt <= 0 || (recSize != 24 && recSize != 28 && recSize != 32) {
		return nil, fmt.Errorf("metadata mmdb incoherente (node_count=%d record_size=%d)", nodeCnt, recSize)
	}
	nodeBytes := recSize / 4 // (record_size*2)/8
	tree := nodeCnt * nodeBytes
	g.nodeCnt, g.recSize = nodeCnt, recSize
	g.dataOff = tree + mmdbSepSize
	if g.dataOff > len(b) {
		return nil, errors.New("arbol mmdb fuera de rango")
	}
	g.ipv6 = mmdbInt(md["ip_version"]) == 6
	if s, ok := md["database_type"].(string); ok {
		g.dbType = s
	}
	g.built = int64(mmdbInt(md["build_epoch"]))
	if dm, ok := md["description"].(map[string]any); ok {
		for _, k := range []string{"es", "en"} {
			if s, ok := dm[k].(string); ok && s != "" {
				g.desc = s
				break
			}
		}
	}
	return g, nil
}

func (g *geoDB) decodeMeta(off, base int) map[string]any {
	d := &mmdbDec{g: g, base: base}
	v, _, err := d.value(off)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	if mmdbInt(m["node_count"]) <= 0 {
		return nil
	}
	return m
}

// findGeoDB busca una base de paises en las rutas habituales. Devuelve la
// primera que exista ("" si no hay ninguna). Los nombres son los de las
// bases libres mas usadas (MaxMind GeoLite2 y DB-IP Lite).
func findGeoDB() string {
	names := []string{
		"GeoLite2-Country.mmdb",
		"DbipLite-Country.mmdb",
		"dbip-country-lite.mmdb",
		"country.mmdb",
	}
	dirs := []string{".", "Country Databases", "databases", "data"}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		dirs = append(dirs, base, filepath.Join(base, "Country Databases"))
	}
	for _, d := range dirs {
		for _, n := range names {
			p := filepath.Join(d, n)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	return ""
}

// info: resumen para el panel/log ("GeoLite2-Country 2026-10-01").
func (g *geoDB) info() string {
	if g == nil {
		return ""
	}
	s := g.dbType
	if s == "" {
		s = "mmdb"
	}
	if g.built > 0 {
		s += " " + time.Unix(g.built, 0).UTC().Format("2006-01-02")
	}
	return s
}

// countryRec: pais de una IP (nombre para mostrar + ISO para filtros).
type countryRec struct {
	Name string
	ISO  string
}

// countryRecIP devuelve el pais de una IP/host, con cache (positiva o
// negativa). El nombre mostrado es el INGLES (igual que el Proxy Checker de
// referencia y que la salida por defecto de GeoLite2): las otras lenguas son
// trampa (MaxMind viejo abreviaba el espanol como "RU" para Reino Unido y
// DB-IP usa nombres oficiales de la ONU de 40 caracteres). El ISO queda para
// filtrar en cualquier idioma.
func (g *geoDB) countryRecIP(host string) countryRec {
	if g == nil || host == "" {
		return countryRec{}
	}
	if v, ok := g.cache.Load(host); ok {
		return v.(countryRec)
	}
	var out countryRec
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		out = g.country(ip)
	}
	if g.nCache.Load() < mmdbCacheMax {
		if _, loaded := g.cache.LoadOrStore(host, out); !loaded {
			g.nCache.Add(1)
		}
	}
	return out
}

// countryIP: solo el nombre (compat/conveniencia).
func (g *geoDB) countryIP(host string) string { return g.countryRecIP(host).Name }

func (g *geoDB) country(ip net.IP) countryRec {
	rec, err := g.lookup(ip)
	if err != nil || rec == nil {
		return countryRec{}
	}
	cm, _ := rec["country"].(map[string]any)
	if cm == nil {
		// algunas bases traen el pais en registered_country
		cm, _ = rec["registered_country"].(map[string]any)
	}
	if cm == nil {
		return countryRec{}
	}
	out := countryRec{}
	if s, ok := cm["iso_code"].(string); ok {
		out.ISO = s
	}
	if names, ok := cm["names"].(map[string]any); ok {
		if s, ok := names["en"].(string); ok && s != "" {
			out.Name = s
		}
	}
	if out.Name == "" {
		out.Name = out.ISO
	}
	return out
}

// lookup recorre el arbol para la IP y devuelve el mapa de datos.
func (g *geoDB) lookup(ip net.IP) (map[string]any, error) {
	var bits []byte
	node := 0
	if g.ipv6 {
		if v4 := ip.To4(); v4 != nil {
			node = g.ipv4Start()
			bits = v4 // 96 ramas de ceros + los 32 bits de la IPv4
		} else if v16 := ip.To16(); v16 != nil {
			bits = v16
		} else {
			return nil, errors.New("ip invalida")
		}
	} else {
		v4 := ip.To4()
		if v4 == nil {
			return nil, errors.New("IPv6 en una base IPv4")
		}
		bits = v4
	}
	for _, b := range bits {
		for i := 7; i >= 0; i-- {
			if node < 0 || node >= g.nodeCnt {
				return g.resolve(node)
			}
			node = g.readNode(node, int(b>>uint(i))&1)
		}
	}
	return g.resolve(node)
}

// resolve interpreta un valor de registro: == node_count (sin datos),
// > node_count (dato en la seccion de datos), < (sigue siendo un nodo).
func (g *geoDB) resolve(v int) (map[string]any, error) {
	if v <= g.nodeCnt {
		return nil, nil // sin datos (o netblock mas especifico que la IP)
	}
	// offset = (valor - node_count) + tamaño_arbol
	off := (v - g.nodeCnt) + (g.dataOff - mmdbSepSize)
	d := &mmdbDec{g: g, base: g.dataOff}
	val, _, err := d.value(off)
	if err != nil {
		return nil, err
	}
	rec, _ := val.(map[string]any)
	return rec, nil
}

// ipv4Start: nodo donde arranca el subarbol IPv4 de una base IPv6
// (96 ramas de ceros desde la raiz, spec "IPv4 addresses in an IPv6 tree").
func (g *geoDB) ipv4Start() int {
	if g.ipv4 >= 0 {
		return g.ipv4
	}
	n := 0
	for i := 0; i < 96; i++ {
		if n < 0 || n >= g.nodeCnt {
			break
		}
		n = g.readNode(n, 0)
	}
	g.ipv4 = n
	return n
}

// readNode lee el registro index (0=izquierda, 1=derecha) del nodo num.
func (g *geoDB) readNode(num, index int) int {
	base := num * g.recSize / 4
	b := g.buf
	if base < 0 || base+g.recSize/4 > len(b) {
		return g.nodeCnt // fuera de rango: se trata como "sin datos"
	}
	switch g.recSize {
	case 24:
		if index == 0 {
			return int(b[base])<<16 | int(b[base+1])<<8 | int(b[base+2])
		}
		return int(b[base+3])<<16 | int(b[base+4])<<8 | int(b[base+5])
	case 28:
		if index == 0 {
			return int(b[base])<<16 | int(b[base+1])<<8 | int(b[base+2]) | int(b[base+3]>>4)<<24
		}
		return int(b[base+4])<<16 | int(b[base+5])<<8 | int(b[base+6]) | int(b[base+3]&0x0f)<<24
	default: // 32
		if index == 0 {
			return int(binary.BigEndian.Uint32(b[base : base+4]))
		}
		return int(binary.BigEndian.Uint32(b[base+4 : base+8]))
	}
}

/* ------------------------- decodificador de datos ------------------------- */

type mmdbDec struct {
	g     *geoDB
	base  int // base de los punteros
	vals  int
	bytes int
	depth int
}

func (d *mmdbDec) charge(n int) error {
	d.vals++
	if d.vals > mmdbMaxVals {
		return errors.New("mmdb: demasiados valores")
	}
	d.bytes += n
	if d.bytes > mmdbMaxBytes {
		return errors.New("mmdb: payload demasiado grande")
	}
	return nil
}

// value decodifica el campo que empieza en off y devuelve (valor,
// offset siguiente, error).
func (d *mmdbDec) value(off int) (any, int, error) {
	if err := d.charge(1); err != nil {
		return nil, off, err
	}
	if off < 0 || off >= len(d.g.buf) {
		return nil, off, errors.New("mmdb: offset fuera de rango")
	}
	ctrl := d.g.buf[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 0 { // tipo extendido: el tipo real va en el byte siguiente menos 7
		if off >= len(d.g.buf) {
			return nil, off, errors.New("mmdb: control truncado")
		}
		typ = int(d.g.buf[off]) + 7
		off++
	}
	size := 0
	if typ != 1 { // los punteros usan los 5 bits de otra forma
		size = int(ctrl & 0x1f)
		switch {
		case size == 29:
			if off+1 > len(d.g.buf) {
				return nil, off, errors.New("mmdb: tamaño truncado")
			}
			size = 29 + int(d.g.buf[off])
			off++
		case size == 30:
			if off+2 > len(d.g.buf) {
				return nil, off, errors.New("mmdb: tamaño truncado")
			}
			size = 285 + int(binary.BigEndian.Uint16(d.g.buf[off:]))
			off += 2
		case size == 31:
			if off+3 > len(d.g.buf) {
				return nil, off, errors.New("mmdb: tamaño truncado")
			}
			size = 65821 + int(d.g.buf[off])<<16 | int(d.g.buf[off+1])<<8 | int(d.g.buf[off+2])
			off += 3
		}
	}
	if err := d.charge(size); err != nil {
		return nil, off, err
	}

	switch typ {
	case 1: // pointer
		p, nxt, err := readPointer(d.g.buf, ctrl, off)
		if err != nil {
			return nil, off, err
		}
		d.depth++
		if d.depth > mmdbMaxDepth {
			return nil, off, errors.New("mmdb: profundidad excesiva")
		}
		v, _, err := d.value(d.base + p)
		d.depth--
		return v, nxt, err

	case 2: // utf-8 string
		if off+size > len(d.g.buf) {
			return nil, off, errors.New("mmdb: string truncado")
		}
		return string(d.g.buf[off : off+size]), off + size, nil

	case 3: // double
		if size != 8 || off+8 > len(d.g.buf) {
			return nil, off, errors.New("mmdb: double invalido")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d.g.buf[off:])), off + 8, nil

	case 4: // bytes
		if off+size > len(d.g.buf) {
			return nil, off, errors.New("mmdb: bytes truncados")
		}
		return append([]byte(nil), d.g.buf[off:off+size]...), off + size, nil

	case 5, 6, 9, 10: // uint16/32/64/128
		if size > 16 || off+size > len(d.g.buf) {
			return nil, off, errors.New("mmdb: entero invalido")
		}
		var u uint64
		for _, b := range d.g.buf[off : off+size] {
			u = u<<8 | uint64(b)
		}
		return u, off + size, nil

	case 7: // map: el tamaño es el NUMERO de pares, no bytes
		m := make(map[string]any, size)
		for i := 0; i < size; i++ {
			k, nxt, err := d.value(off)
			if err != nil {
				return nil, off, err
			}
			ks, _ := k.(string)
			v, nxt2, err := d.value(nxt)
			if err != nil {
				return nil, off, err
			}
			m[ks] = v
			off = nxt2
		}
		return m, off, nil

	case 8: // int32
		if size > 4 || off+size > len(d.g.buf) {
			return nil, off, errors.New("mmdb: int32 invalido")
		}
		var v uint64
		for _, b := range d.g.buf[off : off+size] {
			v = v<<8 | uint64(b)
		}
		if size == 4 && v >= 1<<31 {
			return int64(int32(uint32(v))), off + size, nil
		}
		return int64(v), off + size, nil

	case 11: // array: el tamaño es el numero de valores
		arr := make([]any, 0, size)
		for i := 0; i < size; i++ {
			v, nxt, err := d.value(off)
			if err != nil {
				return nil, off, err
			}
			arr = append(arr, v)
			off = nxt
		}
		return arr, off, nil

	case 12: // data cache container (deprecado, sin payload descrito)
		return nil, off, nil

	case 13: // end marker (deprecado): sin payload
		return nil, off, nil

	case 14: // boolean: el valor va en el tamaño
		return size == 1, off, nil

	case 15: // float
		if size != 4 || off+4 > len(d.g.buf) {
			return nil, off, errors.New("mmdb: float invalido")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(d.g.buf[off:]))), off + 4, nil
	}
	return nil, off, fmt.Errorf("mmdb: tipo desconocido %d", typ)
}

// readPointer decodifica un puntero: los 5 bits del control se parten en
// tamaño (2 bits) y valor (3 bits) segun la spec (001SSVVV).
func readPointer(buf []byte, ctrl byte, off int) (int, int, error) {
	size := (ctrl >> 3) & 0x3
	v := int(ctrl & 0x7)
	need := 1 << size // 1, 2, 4, 8 bytes... (size 3 = 4 bytes)
	if size == 3 {
		need = 4
	}
	if off+need > len(buf) {
		return 0, off, errors.New("mmdb: puntero truncado")
	}
	switch size {
	case 0:
		v = v<<8 | int(buf[off])
	case 1:
		v = (v<<16 | int(buf[off])<<8 | int(buf[off+1])) + 2048
	case 2:
		v = (v<<24 | int(buf[off])<<16 | int(buf[off+1])<<8 | int(buf[off+2])) + 526336
	default:
		v = int(binary.BigEndian.Uint32(buf[off : off+4]))
	}
	return v, off + need, nil
}

func mmdbInt(v any) int {
	switch n := v.(type) {
	case uint64:
		return int(n)
	case int64:
		return int(n)
	}
	return 0
}
