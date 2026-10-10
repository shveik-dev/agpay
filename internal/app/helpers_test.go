package app

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"

	"github.com/shveik-dev/agpay/internal/sol"
)

func hexDecode(s string) ([]byte, error)      { return hex.DecodeString(strings.TrimPrefix(s, "0x")) }
func b58(s string) ([]byte, error)            { return sol.B58Decode(s) }
func ed25519Verify(pub, msg, sig []byte) bool { return ed25519.Verify(pub, msg, sig) }
