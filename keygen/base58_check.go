package keygen

const codeStr = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var invCodeStr = make(map[byte]int)

func init() {
	for i := range codeStr {
		invCodeStr[codeStr[i]] = i
	}
}

// Encode a version byte and payload to creates a Base58Check string
func Encode(version string, payload string) string {
	return ""
}

// Decode a Base58Check string to a version byte and payload
func Decode(base58Str string) (string, string) {
	return "", ""
}

// ChecksumCheck checks if a Base58Check string is valid
func ChecksumCheck(base58Str string) bool {
	return Encode(Decode(base58Str)) == base58Str
}
