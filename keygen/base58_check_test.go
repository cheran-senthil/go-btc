package keygen

import (
	"testing"
)

func TestBase58Check(t *testing.T) {
	if !ChecksumCheck("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") {
		panic(nil)
	}
}
