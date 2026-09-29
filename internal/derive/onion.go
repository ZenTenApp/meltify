package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"strings"

	"golang.org/x/crypto/sha3"
)

// torOnionVersion is the Tor v3 hidden service version byte used in the onion
// address checksum and encoding.
const torOnionVersion = byte(0x03)

// torSecretKeyHeader is the 32-byte magic prefix Tor expects at the start of
// every hs_ed25519_secret_key file (29 ASCII chars + 3 NUL padding bytes).
const torSecretKeyHeader = "== ed25519v1-secret: type0 ==\x00\x00\x00" //nolint:gosec // Tor file-format magic prefix, not a credential.

// torPublicKeyHeader is the 32-byte magic prefix Tor expects at the start of
// every hs_ed25519_public_key file (29 ASCII chars + 3 NUL padding bytes).
const torPublicKeyHeader = "== ed25519v1-public: type0 ==\x00\x00\x00"

const (
	ed25519ClampClearLow  = 248
	ed25519ClampClearHigh = 127
	ed25519ClampSetBit    = 64
	onionChecksumPrefix   = ".onion checksum"
	onionChecksumLen      = 2
)

// OnionKeys holds the material needed to deploy a Tor v3 hidden service
// derived from an Ed25519 SSH key.
type OnionKeys struct {
	// Address is the 56-character v3 .onion hostname.
	Address string

	// PrivateKeyFile is hs_ed25519_secret_key (96 bytes: 32-byte Tor header +
	// 64-byte expanded Ed25519 private key).
	PrivateKeyFile []byte

	// PublicKeyFile is hs_ed25519_public_key (64 bytes: 32-byte Tor header +
	// 32-byte Ed25519 public key).
	PublicKeyFile []byte

	// HostnameFile is hostname (onion address + newline).
	HostnameFile []byte
}

// Onion derives a Tor v3 hidden service identity from an Ed25519 private key.
//
// This matches seedify.DeriveOnionServiceKeys: SHA-256("seedify:tor:v3:" ||
// seed) as the Ed25519 seed, RFC 8032 expanded secret, and rend-spec-v3
// address encoding.
func Onion(key *ed25519.PrivateKey) (*OnionKeys, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}

	label := []byte("seedify:tor:v3:")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())
	subSeed := sha256.Sum256(input)

	torPrivKey := ed25519.NewKeyFromSeed(subSeed[:])
	pubKey, ok := torPrivKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("derived Tor key is not Ed25519")
	}

	expandedArr := sha512.Sum512(subSeed[:])
	expandedArr[0] &= ed25519ClampClearLow
	expandedArr[31] &= ed25519ClampClearHigh
	expandedArr[31] |= ed25519ClampSetBit

	checksumInput := make([]byte, 0, len(onionChecksumPrefix)+ed25519.PublicKeySize+1)
	checksumInput = append(checksumInput, []byte(onionChecksumPrefix)...)
	checksumInput = append(checksumInput, pubKey...)
	checksumInput = append(checksumInput, torOnionVersion)
	checksumHash := sha3.Sum256(checksumInput)

	addrBytes := make([]byte, 0, ed25519.PublicKeySize+onionChecksumLen+1)
	addrBytes = append(addrBytes, pubKey...)
	addrBytes = append(addrBytes, checksumHash[:onionChecksumLen]...)
	addrBytes = append(addrBytes, torOnionVersion)

	onionAddr := strings.ToLower(base32.StdEncoding.EncodeToString(addrBytes)) + ".onion"

	privFile := make([]byte, 0, len(torSecretKeyHeader)+len(expandedArr))
	privFile = append(privFile, []byte(torSecretKeyHeader)...)
	privFile = append(privFile, expandedArr[:]...)

	pubFile := make([]byte, 0, len(torPublicKeyHeader)+ed25519.PublicKeySize)
	pubFile = append(pubFile, []byte(torPublicKeyHeader)...)
	pubFile = append(pubFile, pubKey...)

	return &OnionKeys{
		Address:        onionAddr,
		PrivateKeyFile: privFile,
		PublicKeyFile:  pubFile,
		HostnameFile:   []byte(onionAddr + "\n"),
	}, nil
}
