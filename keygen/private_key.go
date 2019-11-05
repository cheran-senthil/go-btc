package keygen

import (
	"crypto/rand"
	"math/big"
)

// N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF
const N = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

// GenPrivateKey generates a hex encoded private key
func GenPrivateKey() string {
	n, _ := new(big.Int).SetString(N, 16)
	privateKey, _ := rand.Int(rand.Reader, n)
	return privateKey.Text(16)
}

// IsPrivateKeyValid checks if a given string is a valid private key
func IsPrivateKeyValid(privateKey string) bool {
	n, _ := new(big.Int).SetString(N, 16)
	privateKeyInt, ok := new(big.Int).SetString(privateKey, 16)
	if !ok {
		return false
	}

	return privateKeyInt.Cmp(big.NewInt(0)) == 1 && privateKeyInt.Cmp(n) == -1
}
