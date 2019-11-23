// Package keygen provides functions to generate Bitcoin private keys and relevant details.
package keygen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// The order n of G.
var n *big.Int

func init() {
	n, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
}

// GenPrivateKey generates a hex encoded private key.
func GenPrivateKey() (privateKey string) {
	privateKeyInt, _ := rand.Int(rand.Reader, n)
	return fmt.Sprintf("%064s", privateKeyInt.Text(16))
}

// IsPrivateKeyValid checks if a given string is a valid private key.
func IsPrivateKeyValid(privateKey string) (valid bool) {
	privateKeyInt, ok := new(big.Int).SetString(privateKey, 16)
	if !ok {
		return false
	}

	return privateKeyInt.Cmp(big.NewInt(0)) == 1 && privateKeyInt.Cmp(n) == -1
}
