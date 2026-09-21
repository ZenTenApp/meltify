package derive

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

const cashAddrCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var cashAddrGenerators = [5]uint64{
	0x98f2bc8e61,
	0x79b76d99e2,
	0xf33e5fb3c4,
	0xae2eabe2a8,
	0x1e4f43e470,
}

// BitcoinCash derives a BIP44 P2PKH CashAddr at m/44'/145'/0'/0/0 (Electron Cash).
// The returned string is the payload only (starts with "q"), without the
// "bitcoincash:" prefix, so meltify-info can print bitcoincash:<payload>.
func BitcoinCash(mnemonic, bip39Passphrase string) (string, error) {
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 44, 145) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Bitcoin Cash key: %w", err)
	}
	return encodeCashAddr("bitcoincash", 0, pubKeyHash)
}

func encodeCashAddr(prefix string, version byte, hash []byte) (string, error) {
	payload := make([]byte, 0, 1+len(hash))
	payload = append(payload, version)
	payload = append(payload, hash...)
	data5, err := bech32.ConvertBits(payload, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for cashaddr: %w", err)
	}

	values := cashAddrPrefixExpand(prefix)
	values = append(values, data5...)
	values = append(values, 0, 0, 0, 0, 0, 0, 0, 0)
	mod := cashAddrPolymod(values) ^ 1
	checksum := make([]byte, 8) //nolint:mnd
	for i := range checksum {
		checksum[i] = byte((mod >> uint(5*(7-i))) & 31) //nolint:mnd
	}

	encoded := make([]byte, len(data5)+len(checksum))
	for i, v := range data5 {
		encoded[i] = cashAddrCharset[v]
	}
	for i, v := range checksum {
		encoded[len(data5)+i] = cashAddrCharset[v]
	}
	return string(encoded), nil
}

func cashAddrPrefixExpand(prefix string) []byte {
	out := make([]byte, 0, len(prefix)+1)
	for i := 0; i < len(prefix); i++ {
		out = append(out, prefix[i]&31)
	}
	out = append(out, 0)
	return out
}

func cashAddrPolymod(values []byte) uint64 {
	c := uint64(1)
	for _, d := range values {
		c0 := c >> 35
		c = ((c & 0x07ffffffff) << 5) ^ uint64(d)
		for i := range cashAddrGenerators {
			if (c0>>uint(i))&1 == 1 {
				c ^= cashAddrGenerators[i]
			}
		}
	}
	return c
}
