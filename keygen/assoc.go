package keygen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

// Private2Public returns the public key associated with a private key (hex string)
func Private2Public(privateKey string, compressed bool) string {
	return ""
}

// Public2Address returns the address associated with a public key
func Public2Address(publicKey string, mainnet bool) (string, error) {
	decoded, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(decoded)
	ripemd160 := ripemd160.New()
	ripemd160.Write(sum[:])
	payload := hex.EncodeToString(ripemd160.Sum(nil))
	if mainnet {
		return Encode("00", payload)
	}

	return Encode("6f", payload)
}

// Private2Address returns the address associated with a private key
func Private2Address(privateKey string, compressed bool, mainnet bool) (string, error) {
	if !IsPrivateKeyValid(privateKey) {
		return "", fmt.Errorf("%s is not a valid key", privateKey)
	}

	address, err := Public2Address(Private2Public(privateKey, compressed), mainnet)
	if err != nil {
		return "", err
	}

	return address, nil
}

// Private2WIF returns the Wallet Import Format (WIF) associated with a private key (hex string)
func Private2WIF(privateKey string, compressed bool, mainnet bool) (string, error) {
	if !IsPrivateKeyValid(privateKey) {
		return "", fmt.Errorf("%s is not a valid key", privateKey)
	}

	if compressed {
		privateKey = privateKey + "01"
	}

	if mainnet {
		wif, err := Encode("80", privateKey)
		if err != nil {
			return "", err
		}

		return wif, nil
	}

	wif, err := Encode("ef", privateKey)
	if err != nil {
		return "", err
	}

	return wif, nil
}

// WIF2Private returns the private key associated with a Wallet Import Format (WIF)
func WIF2Private(wif string, compressed bool) string {
	_, privateKey := Decode(wif)
	if compressed {
		return privateKey[:len(privateKey)-2]
	}

	return privateKey
}
