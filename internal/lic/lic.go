// Package lic: formato de licencia ESPECTRO PROXY PRO (doble licencia:
// GPLv3 para la comunidad / comercial para Pro).
//
// Capas de proteccion (orden de verificacion en Open):
//  1. AES-256-GCM con clave derivada de la maquina (SHA-256 de la
//     fingerprint): el archivo es ilegible y no funciona en otro equipo.
//     AAD amarra el cifrado al producto ("ESPECTRO-PROXY-PRO").
//  2. Ed25519: firma del payload JSON. La clave privada jamas viaja en el
//     binario; solo la publica (embebida en el programa).
//  3. Control de vida: version, edicion y expiracion dentro del payload.
//
// La clave privada vive fuera del repo y solo pasa por el binario lictool.
package lic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version del formato de licencia.
const Version = 1

const (
	edicionPro      = "pro"
	edicionBusiness = "business"
)

var (
	ErrFormato  = errors.New("licencia: formato invalido (base64)")
	ErrCorto    = errors.New("licencia: blob demasiado corto")
	ErrCifrado  = errors.New("licencia: no se pudo descifrar (maquina distinta o archivo corrupto)")
	ErrJSON     = errors.New("licencia: payload invalido")
	ErrVersion  = errors.New("licencia: version de formato no soportada")
	ErrFirma    = errors.New("licencia: firma Ed25519 invalida")
	ErrMaquina  = errors.New("licencia: no emitida para esta maquina")
	ErrEdicion  = errors.New("licencia: edicion desconocida")
	ErrCaducada = errors.New("licencia: caducada")
)

var aad = []byte("ESPECTRO-PROXY-PRO")

// Payload es el contenido firmado (y luego cifrado) de la licencia.
// Sig se calcula sobre el JSON del payload con Sig="" (el marshal de Go es
// determinista: mismo struct = mismos bytes; no cambiar los tags).
type Payload struct {
	V        int      `json:"v"`
	Edition  string   `json:"edition"`  // "pro" | "business"
	Licensee string   `json:"licensee"` // titular visible de la licencia
	Machine  string   `json:"machine"`  // Fingerprint() de la maquina objetivo
	Issued   string   `json:"issued"`   // RFC3339
	Expires  string   `json:"expires"`  // RFC3339; "" = perpetua
	Features []string `json:"features"` // reservado para futuros niveles
	Sig      string   `json:"sig"`      // base64 de la firma Ed25519
}

// Fingerprint identifica una maquina de forma irreversible (hex sha256).
// Se usa dentro del payload Y como base de la clave de cifrado: una licencia
// copiada a otro equipo ni siquiera se puede descifrar.
func Fingerprint(machineID string) string {
	sum := sha256.Sum256([]byte("ESPECTRO-MACHINE-v1\x00" + machineID))
	return hex.EncodeToString(sum[:])
}

func deriveKey(fp string) []byte {
	sum := sha256.Sum256([]byte("ESPECTRO-LIC-K1-v1\x00" + fp))
	return sum[:]
}

// Seal firma (Ed25519) y cifra (AES-256-GCM) el payload para la maquina
// dada. Devuelve el blob binario: nonce(12) || ciphertext(+tag).
func Seal(priv ed25519.PrivateKey, p *Payload, machineID string) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("licencia: clave privada invalida")
	}
	p.V = Version
	p.Machine = Fingerprint(machineID)
	if p.Issued == "" {
		p.Issued = time.Now().UTC().Format(time.RFC3339)
	}
	if p.Edition != edicionPro && p.Edition != edicionBusiness {
		return nil, ErrEdicion
	}
	p.Sig = ""
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	p.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body))
	full, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey(Fingerprint(machineID)))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, full, aad), nil
}

// Unseal descifra y verifica la licencia blob contra la maquina local.
// NO valida caducidad: ver p.Valid(time.Now()).
func Unseal(pub ed25519.PublicKey, blob []byte, machineID string) (*Payload, error) {
	fp := Fingerprint(machineID)
	block, err := aes.NewCipher(deriveKey(fp))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrCorto
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrCifrado
	}
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, ErrJSON
	}
	if p.V != Version {
		return nil, ErrVersion
	}
	if p.Edition != edicionPro && p.Edition != edicionBusiness {
		return nil, ErrEdicion
	}
	sig, err := base64.StdEncoding.DecodeString(p.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrFirma
	}
	p.Sig = ""
	body, err := json.Marshal(&p)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, body, sig) {
		return nil, ErrFirma
	}
	if p.Machine != fp {
		return nil, ErrMaquina
	}
	return &p, nil
}

// Valid comprueba expiracion ("" = perpetua) y edicion.
func (p *Payload) Valid(now time.Time) error {
	if p.Edition != edicionPro && p.Edition != edicionBusiness {
		return ErrEdicion
	}
	if p.Expires == "" {
		return nil
	}
	exp, err := time.Parse(time.RFC3339, p.Expires)
	if err != nil {
		return ErrJSON
	}
	if now.After(exp) {
		return ErrCaducada
	}
	return nil
}

// DecodeFile normaliza el contenido del archivo de licencia
// (base64 std/URL, con o sin saltos de linea).
func DecodeFile(raw []byte) ([]byte, error) {
	s := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			s = append(s, c)
		}
	}
	blob, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return nil, ErrFormato
	}
	return blob, nil
}

// EncodeFile formatea el blob para escribir el archivo .lic.
func EncodeFile(blob []byte) string {
	return base64.StdEncoding.EncodeToString(blob) + "\n"
}
