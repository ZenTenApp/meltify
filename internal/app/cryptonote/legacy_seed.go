package cryptonote

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"

	"filippo.io/edwards25519"
)

const (
	moneroLegacySeedBytes = 32
	moneroLegacyWordCount = 25
	moneroLegacyGroupSize = 4
	moneroLegacyGroups    = 8
	moneroLegacyRadix     = 1626
	moneroChecksumPrefix  = 3
)

func legacySeedFromKey(key *ed25519.PrivateKey) (string, error) {
	reduced := scReduce32(key.Seed())
	words, err := moneroLegacyBytesToWords(reduced)
	if err != nil {
		return "", err
	}
	return strings.Join(words, " "), nil
}

func moneroLegacyBytesToWords(keyBytes []byte) ([]string, error) {
	if len(keyBytes) != moneroLegacySeedBytes {
		return nil, fmt.Errorf("monero legacy seed: expected %d bytes, got %d", moneroLegacySeedBytes, len(keyBytes))
	}

	words := make([]string, 0, moneroLegacyWordCount)
	for i := range moneroLegacyGroups {
		v := binary.LittleEndian.Uint32(keyBytes[moneroLegacyGroupSize*i : moneroLegacyGroupSize*i+moneroLegacyGroupSize])
		w1 := v % moneroLegacyRadix
		w2 := (v/moneroLegacyRadix + w1) % moneroLegacyRadix
		w3 := (v/moneroLegacyRadix/moneroLegacyRadix + w2) % moneroLegacyRadix
		words = append(words, moneroLegacyWordlist[w1], moneroLegacyWordlist[w2], moneroLegacyWordlist[w3])
	}
	words = append(words, words[moneroLegacyChecksumIndex(words)])
	return words, nil
}

func moneroLegacyChecksumIndex(words []string) int {
	buf := make([]byte, 0, (moneroLegacyWordCount-1)*moneroChecksumPrefix)
	for _, word := range words[:moneroLegacyWordCount-1] {
		if len(word) >= moneroChecksumPrefix {
			buf = append(buf, word[:moneroChecksumPrefix]...)
		} else {
			buf = append(buf, word...)
		}
	}
	return int(crc32.ChecksumIEEE(buf) % (moneroLegacyWordCount - 1))
}

func scReduce32(input []byte) []byte {
	if len(input) != moneroLegacySeedBytes {
		return input
	}

	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(input)
	if err == nil {
		return scalar.Bytes()
	}

	padded := make([]byte, 64) //nolint:mnd
	copy(padded, input)
	scalar, err = edwards25519.NewScalar().SetUniformBytes(padded)
	if err != nil {
		result := make([]byte, moneroLegacySeedBytes)
		copy(result, input)
		result[moneroLegacySeedBytes-1] &= 0x0F
		return result
	}
	return scalar.Bytes()
}
