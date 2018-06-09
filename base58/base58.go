package base58

import (
	"fmt"
	"math/big"
)

var alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func Encode(src []byte) ([]byte, error) {
	n := new(big.Int).SetBytes(src)
	zero := big.NewInt(0)
	radix := big.NewInt(58)
	mod := new(big.Int)
	bytes := []byte{}
	for {
		switch n.Cmp(zero) {
		case 1:
			n.DivMod(n, radix, mod)
			bytes = append(bytes, alphabet[mod.Int64()])
		case 0:
			reverse(bytes)
			return bytes, nil
		default:
			return nil, fmt.Errorf("expecting a positive number in base58 encoding but got %q", n)
		}
	}
}

func reverse(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
