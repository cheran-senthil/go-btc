package keygen

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

const codeStr = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var invCodeStr = make(map[byte]*big.Int)

func init() {
	for i := range codeStr {
		invCodeStr[codeStr[i]] = big.NewInt(int64(i))
	}
}

// Encode a version byte and payload to creates a Base58Check string
func Encode(version, payload string) (base58Str string, err error) {
	// concatenate the version and payload
	extKey := version + payload
	decoded, err := hex.DecodeString(extKey)
	if err != nil {
		return "", err
	}

	// take the checksum of the extended key
	sum := sha256.Sum256(decoded)
	sum = sha256.Sum256(sum[:])
	checksum := sum[:4]

	// concatenate the external key and checksum
	extKey += hex.EncodeToString(checksum)

	// convert the external key to base-58
	var outStr string
	x, _ := new(big.Int).SetString(extKey, 16)
	for x.Cmp(big.NewInt(0)) == 1 {
		var rem big.Int
		x.DivMod(x, big.NewInt(58), &rem)
		outStr = string(codeStr[rem.Int64()]) + outStr
	}

	// represent leading zero bytes by "1"
	leadingOnes := strings.Repeat("1", (len(extKey)-len(strings.TrimLeft(extKey, "0")))/2)

	// concatenate the 1's with the external key in base-58
	return leadingOnes + outStr, nil
}

// Decode a Base58Check string to a version byte and payload
func Decode(base58Str string) (version, payload string) {
	// strip leading 1's
	outStr := strings.TrimLeft(base58Str, "1")

	// construct byte string
	x, pow58 := big.NewInt(0), big.NewInt(1)
	for i := range outStr {
		x.Add(x, new(big.Int).Mul(pow58, invCodeStr[outStr[len(outStr)-1-i]]))
		pow58.Mul(pow58, big.NewInt(58))
	}

	byteStr := x.Text(16)
	leadingZeroes := strings.Repeat("00", len(base58Str)-len(outStr)) + strings.Repeat("0", len(byteStr)&1)
	byteStr = leadingZeroes + byteStr

	// drop checksum
	return byteStr[:2], byteStr[2 : len(byteStr)-8]
}

// ChecksumCheck checks if a Base58Check string is valid
func ChecksumCheck(base58Str string) (valid bool) {
	base58StrCheck, err := Encode(Decode(base58Str))
	if err != nil {
		return false
	}

	return base58StrCheck == base58Str
}
