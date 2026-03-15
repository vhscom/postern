package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

// RandomHex returns n cryptographically random bytes as a hex string.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}
