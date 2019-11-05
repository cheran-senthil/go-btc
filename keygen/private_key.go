package keygen

import (
	"crypto/rand"
	"math/big"
)

// N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF
const N = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

// GenPrivateKey generates a private key
func GenPrivateKey() *big.Int {
	n, _ := new(big.Int).SetString(N, 16)
	privateKey, _ := rand.Int(rand.Reader, n)
	return privateKey
}

// IsPrivateKeyValid checks if a given private key is valid
func IsPrivateKeyValid(privateKey *big.Int) bool {
	n, _ := new(big.Int).SetString(N, 16)
	return privateKey.Cmp(big.NewInt(0)) == 1 && privateKey.Cmp(n) == -1
}
