package main

import (
	"fmt"

	"github.com/cheran-senthil/go-btc/keygen"
)

func main() {
	privateKey := keygen.GenPrivateKey()
	fmt.Println("Private Key:", privateKey)
	fmt.Println()

	wif, _ := keygen.Private2WIF(privateKey, false, true)
	fmt.Println("WIF:", wif)

	publicKey, _ := keygen.Private2Public(privateKey, false)
	fmt.Println("Public Key:", publicKey)

	address, _ := keygen.Public2Address(publicKey, true)
	fmt.Println("Address:", address)
	fmt.Println()

	wif, _ = keygen.Private2WIF(privateKey, true, true)
	fmt.Println("WIF (Compressed):", wif)

	publicKey, _ = keygen.Private2Public(privateKey, true)
	fmt.Println("Public Key (Compressed):", publicKey)

	address, _ = keygen.Public2Address(publicKey, true)
	fmt.Println("Address (Compressed):", address)
}
