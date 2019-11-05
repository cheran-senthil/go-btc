package main

import (
	"fmt"

	"github.com/cheran-senthil/go-btc/keygen"
)

func main() {
	fmt.Println("Private Key:", keygen.GenPrivateKey())
}
