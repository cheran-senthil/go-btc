package keygen

import "testing"

func TestPrivateKey(t *testing.T) {
	if !IsPrivateKeyValid(GenPrivateKey()) {
		panic(nil)
	}
}
