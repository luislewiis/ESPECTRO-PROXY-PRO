package main

import (
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type Proxy struct {
	Scheme   string
	Host     string
	Port     int
	User     string
	Password string
	Alive    bool
	Fails    int

	// Lista de origen (para borrar/editar y reescribir el .txt en disco).
	File string

	// Estado de analisis (persistido en <lista>.state.json):
	// Checked=false => nunca verificado (se auto-escanea siempre).
	// LastCheck: unix seg del ultimo health-check (0 = nunca).
	Checked   bool
	PingMs    int
	LastCheck int64
}

var typeMap = map[string]string{
	"0": "http", "1": "socks4", "2": "socks5", "3": "http",
	"http": "http", "https": "http", "socks": "socks5",
	"socks4": "socks4", "socks4a": "socks4a", "socks5": "socks5",
}

func (p *Proxy) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

func (p *Proxy) Key() string {
	return p.Scheme + "|" + p.Host + "|" + strconv.Itoa(p.Port) + "|" + p.User
}

func (p *Proxy) Tag() string {
	auth := ""
	if p.User != "" {
		auth = p.User + "@@"
	}
	return p.Scheme + "://" + auth + p.Host + ":" + strconv.Itoa(p.Port)
}

func (p *Proxy) Plain() string {
	return p.Host + ":" + strconv.Itoa(p.Port)
}

// LineaCanon serializa el proxy con esquema y credenciales completos:
// es la forma canonica que se escribe al editar una lista (no se pierde
// el esquema de ficheros tipo socks5.txt ni el user/pass).
func (p *Proxy) LineaCanon() string {
	s := p.Scheme + "://"
	if p.User != "" {
		s += url.UserPassword(p.User, p.Password).String() + "@"
	}
	return s + p.Addr()
}

func (p *Proxy) OB() string {
	t := "0"
	if v, ok := map[string]string{"http": "0", "socks4": "1", "socks5": "2"}[p.Scheme]; ok {
		t = v
	}
	return t + ":" + p.Host + ":" + strconv.Itoa(p.Port) + ":" + p.User + ":" + p.Password
}

func splitHostPort(s string) (string, int, bool) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// ParseProxyDef parsea una linea; defScheme se aplica a los formatos sin
// esquema explicito (p. ej. "ip:puerto" dentro de socks5.txt se toma como socks5).
func ParseProxyDef(line string, defScheme string) *Proxy {
	s := strings.TrimPrefix(strings.TrimSpace(line), "\ufeff")
	if s == "" || strings.HasPrefix(s, "#") {
		return nil
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil
		}
		scheme, ok := typeMap[strings.ToLower(u.Scheme)]
		if !ok {
			return nil
		}
		host := u.Hostname()
		if host == "" {
			return nil
		}
		port := 0
		if ps := u.Port(); ps != "" {
			if port, err = strconv.Atoi(ps); err != nil || port < 1 || port > 65535 {
				return nil
			}
		} else if strings.HasPrefix(scheme, "socks") {
			port = 1080
		} else {
			port = 8080
		}
		user, pwd := "", ""
		if u.User != nil {
			user = u.User.Username()
			pwd, _ = u.User.Password()
		}
		return &Proxy{Scheme: scheme, Host: host, Port: port, User: user, Password: pwd, Alive: true}
	}

	if strings.Contains(s, "@") {
		i := strings.LastIndex(s, "@")
		left, right := s[:i], s[i+1:]
		user, pwd, _ := strings.Cut(left, ":")
		host, port, ok := splitHostPort(right)
		if !ok {
			return nil
		}
		return &Proxy{Scheme: bareScheme(defScheme), Host: host, Port: port, User: user, Password: pwd, Alive: true}
	}

	if strings.HasPrefix(s, "[") {
		host, port, ok := splitHostPort(s)
		if !ok {
			return nil
		}
		return &Proxy{Scheme: bareScheme(defScheme), Host: host, Port: port, Alive: true}
	}

	parts := strings.Split(s, ":")
	if len(parts) >= 3 {
		if scheme, ok := typeMap[parts[0]]; ok {
			host := parts[1]
			port, err := strconv.Atoi(parts[2])
			if err != nil || host == "" || port < 1 || port > 65535 {
				return nil
			}
			user := ""
			if len(parts) > 3 {
				user = parts[3]
			}
			pwd := ""
			if len(parts) > 4 {
				pwd = parts[4]
			}
			return &Proxy{Scheme: scheme, Host: host, Port: port, User: user, Password: pwd, Alive: true}
		}
	}

	switch len(parts) {
	case 2:
		host, port, ok := splitHostPort(s)
		if !ok {
			return nil
		}
		return &Proxy{Scheme: bareScheme(defScheme), Host: host, Port: port, Alive: true}
	case 3:
		host, port, ok := splitHostPort(parts[0] + ":" + parts[1])
		if !ok {
			return nil
		}
		return &Proxy{Scheme: bareScheme(defScheme), Host: host, Port: port, User: parts[2], Alive: true}
	case 4:
		host, port, ok := splitHostPort(parts[0] + ":" + parts[1])
		if !ok {
			return nil
		}
		return &Proxy{Scheme: bareScheme(defScheme), Host: host, Port: port, User: parts[2], Password: parts[3], Alive: true}
	}
	return nil
}

// bareScheme devuelve el esquema por defecto para formatos sin protocolo.
func bareScheme(def string) string {
	switch def {
	case "http", "socks4", "socks4a", "socks5":
		return def
	}
	return "http"
}

// schemeFromFileName infiere el esquema por defecto del nombre del archivo
// (socks5.txt -> socks5, socks4.txt -> socks4, http.txt -> http).
func schemeFromFileName(name string) string {
	n := strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	switch {
	case strings.Contains(n, "socks5"):
		return "socks5"
	case strings.Contains(n, "socks4a"):
		return "socks4a"
	case strings.Contains(n, "socks4"):
		return "socks4"
	case strings.Contains(n, "https"), strings.Contains(n, "http"):
		return "http"
	}
	return ""
}
