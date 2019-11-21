package keygen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"

	"golang.org/x/crypto/ripemd160"
)

type point struct {
	x *big.Int
	y *big.Int
}

var p *big.Int

func init() {
	p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
}

func ellipticAdd(q point, n point) point {
	var lam *big.Int
	if reflect.DeepEqual(q, n) {
		lam = new(big.Int).Mul(
			new(big.Int).Mul(
				big.NewInt(3),
				new(big.Int).Mul(n.x, n.x),
			),
			new(big.Int).Exp(
				new(big.Int).Mul(big.NewInt(2), n.y),
				new(big.Int).Sub(p, big.NewInt(2)),
				p,
			))
	} else {
		lam = new(big.Int).Mul(
			new(big.Int).Sub(q.y, n.y),
			new(big.Int).Exp(
				new(big.Int).Sub(q.x, n.x),
				new(big.Int).Sub(p, big.NewInt(2)),
				p,
			))
	}

	q.x = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(lam, lam),
			new(big.Int).Add(q.x, n.x),
		),
		p,
	)

	q.y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(lam, new(big.Int).Sub(n.x, q.x)),
			n.y,
		),
		p,
	)

	return q
}

// Private2Public returns the public key associated with a private key (hex string)
func Private2Public(privateKey string, compressed bool) (string, error) {
	if !IsPrivateKeyValid(privateKey) {
		return "", fmt.Errorf("%s is not a valid key", privateKey)
	}

	// base point
	var g, q point
	g.x, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	g.y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	// compute g * privateKey with repeated addition
	x, _ := new(big.Int).SetString(privateKey, 16)
	pow2, big2 := big.NewInt(1), big.NewInt(2)
	for i := 0; i < 256; i++ {
		if big.NewInt(0).Cmp(new(big.Int).And(x, pow2)) == -1 {
			if reflect.DeepEqual(q, point{}) {
				q = g
			} else {
				q = ellipticAdd(q, g)
			}
		}

		g = ellipticAdd(g, g)
		pow2.Mul(pow2, big2)
	}

	if compressed {
		if big.NewInt(0).Cmp(new(big.Int).And(q.y, big.NewInt(1))) == -1 {
			return "03" + q.x.Text(16), nil
		}

		return "02" + q.x.Text(16), nil
	}

	return "04" + fmt.Sprintf("%064s", q.x.Text(16)) + fmt.Sprintf("%064s", q.y.Text(16)), nil
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
func Private2Address(privateKey string, compressed, mainnet bool) (string, error) {
	if !IsPrivateKeyValid(privateKey) {
		return "", fmt.Errorf("%s is not a valid key", privateKey)
	}

	publicKey, err := Private2Public(privateKey, compressed)
	if err != nil {
		return "", err
	}

	address, err := Public2Address(publicKey, mainnet)
	if err != nil {
		return "", err
	}

	return address, nil
}

// Private2WIF returns the Wallet Import Format (WIF) associated with a private key (hex string)
func Private2WIF(privateKey string, compressed, mainnet bool) (string, error) {
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
