// Copyright (c) 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright (c) 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"unicode/utf16"
)

const (
	// ucs2RuneSize is the number of bytes per UCS-2 code unit.
	ucs2RuneSize = 2

	// nonBMPRune is what utf16.EncodeRune returns for a rune with no surrogate
	// pair; such runes cannot be represented in UCS-2.
	nonBMPRune = 0xfffd

	// byteRadix splits a rune into its big-endian UCS-2 code unit bytes.
	byteRadix = 256

	// kdfPurposeIntegrity is the PKCS#12 KDF purpose byte for MAC keys.
	kdfPurposeIntegrity = 3
)

// bmpString returns s encoded in UCS-2 without a terminator.
func bmpString(s string) ([]byte, error) {
	out := make([]byte, 0, ucs2RuneSize*len(s)+ucs2RuneSize)
	for _, r := range s {
		if t, _ := utf16.EncodeRune(r); t != nonBMPRune {
			return nil, errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
		}
		out = append(out, byte(r/byteRadix), byte(r%byteRadix))
	}
	return out, nil
}

// bmpStringZeroTerminated returns s encoded in UCS-2 with a zero terminator.
// PKCS#12 passwords used by the legacy KDF are NULL-terminated BMP strings
// (RFC 7292, appendix B.1).
func bmpStringZeroTerminated(s string) ([]byte, error) {
	out, err := bmpString(s)
	if err != nil {
		return nil, err
	}
	return append(out, 0, 0), nil
}

func sha256Sum(in []byte) []byte {
	sum := sha256.Sum256(in)
	return sum[:]
}

// fillWithRepeats returns v*ceiling(len(pattern)/v) bytes consisting of repeats
// of pattern, truncated to a multiple of v.
func fillWithRepeats(pattern []byte, v int) []byte {
	if len(pattern) == 0 {
		return nil
	}
	outputLen := v * ((len(pattern) + v - 1) / v)
	return bytes.Repeat(pattern, (outputLen+len(pattern)-1)/len(pattern))[:outputLen]
}

// pkcs12KDF implements the PKCS#12 key derivation function of RFC 7292,
// appendix B.2 for a hash with u-bit output and v-bit blocks. u and v are the
// hash output size and block size in bytes, salt is the KDF salt, password the
// NULL-terminated BMP-encoded password, iterations the iteration count, id the
// purpose byte (1 = key, 2 = IV, 3 = MAC key), and size the number of bytes to
// produce.
func pkcs12KDF(u, v int, salt, password []byte, iterations int, id byte, size int) []byte {
	// D is the diversifier: v bytes of the purpose ID.
	diversifier := bytes.Repeat([]byte{id}, v)

	// I is the salt and password, each padded to a multiple of v.
	i := append(fillWithRepeats(salt, v), fillWithRepeats(password, v)...)

	// c is the number of hash rounds needed to cover size bytes.
	c := (size + u - 1) / u
	a := make([]byte, c*u)
	var blockBuf []byte
	for k := 0; k < c; k++ {
		input := make([]byte, 0, len(diversifier)+len(i))
		input = append(input, diversifier...)
		input = append(input, i...)
		ai := sha256Sum(input)
		for j := 1; j < iterations; j++ {
			ai = sha256Sum(ai)
		}
		copy(a[k*u:], ai)

		if k == c-1 {
			break
		}

		// B is Ai repeated/truncated to v bytes.
		var b []byte
		for len(b) < v {
			b = append(b, ai...)
		}
		b = b[:v]

		// I_j = (I_j + B + 1) mod 2^v for every v-byte block of I.
		bInt := new(big.Int).SetBytes(b)
		one := big.NewInt(1)
		ij := new(big.Int)
		for j := 0; j < len(i)/v; j++ {
			ij.SetBytes(i[j*v : (j+1)*v])
			ij.Add(ij, bInt)
			ij.Add(ij, one)
			ijBytes := ij.Bytes()
			if len(ijBytes) > v {
				ijBytes = ijBytes[len(ijBytes)-v:]
			}
			if len(ijBytes) < v {
				if blockBuf == nil {
					blockBuf = make([]byte, v)
				}
				short := v - len(ijBytes)
				for n := 0; n < short; n++ {
					blockBuf[n] = 0
				}
				copy(blockBuf[short:], ijBytes)
				ijBytes = blockBuf
			}
			copy(i[j*v:(j+1)*v], ijBytes)
		}
	}

	return a[:size]
}

// macKey derives the HMAC-SHA-256 integrity key from the PKCS#12 KDF.
func macKey(salt, password []byte, iterations int) []byte {
	const (
		sha256Size  = 32
		sha256Block = 64
	)
	return pkcs12KDF(sha256Size, sha256Block, salt, password, iterations, kdfPurposeIntegrity, sha256Size)
}
