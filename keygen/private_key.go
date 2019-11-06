package keygen

import (
	"crypto/rand"
	"math/big"
)

// order
var n *big.Int

func init() {
	n, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
}

// GenPrivateKey generates a hex encoded private key
func GenPrivateKey() string {
	privateKey, _ := rand.Int(rand.Reader, n)
	return privateKey.Text(16)
}

// IsPrivateKeyValid checks if a given string is a valid private key
func IsPrivateKeyValid(privateKey string) bool {
	privateKeyInt, ok := new(big.Int).SetString(privateKey, 16)
	if !ok {
		return false
	}

	return privateKeyInt.Cmp(big.NewInt(0)) == 1 && privateKeyInt.Cmp(n) == -1
}
