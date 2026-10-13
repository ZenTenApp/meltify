package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	// i2pDestKeyRegionSize is the fixed size of the key region that precedes
	// the Certificate in every I2P Destination / RouterIdentity structure.
	// Per the I2P Common Structures spec it is always exactly 384 bytes.
	i2pDestKeyRegionSize = 384

	// i2pKeyCertType is the Certificate type code for a Key Certificate (0x05).
	i2pKeyCertType = byte(0x05)

	// i2pKeyCertPayloadSize is the length of the Key Certificate payload:
	// the signing type (2 bytes) followed by the crypto type (2 bytes).
	i2pKeyCertPayloadSize = 4

	// i2pSigTypeEd25519 is the Signing Public Key type code for
	// EdDSA_SHA512_Ed25519 (type 7), encoded big-endian.
	i2pSigTypeEd25519 = uint16(7)

	// i2pCryptoTypeX25519 is the Crypto Public Key type code for X25519
	// (type 4), encoded big-endian.
	i2pCryptoTypeX25519 = uint16(4)

	// i2pUint16HighByteShift extracts the high byte of a big-endian uint16.
	i2pUint16HighByteShift = 8

	// i2pPrivKeyComponentSize is the size in bytes of each private-key
	// component appended to the keys.dat Destination file.
	i2pPrivKeyComponentSize = 32

	// RFC 7748 §5 X25519 scalar clamping constants.
	i2pClampClearLow  = 248
	i2pClampClearHigh = 127
	i2pClampSetBit    = 64
)

// I2PKeys holds all material needed to deploy or advertise an I2P Destination
// derived from an Ed25519 private key.
type I2PKeys struct {
	// B32Address is the 52-character base32 .b32.i2p hostname.
	B32Address string

	// DestinationBytes is the serialised public Destination structure
	// (384-byte key region + 7-byte Key Certificate).
	DestinationBytes []byte

	// PrivateKeyFile is the content of the i2pd destination.dat / keys.dat
	// private-key file: Destination bytes, the X25519 private scalar, and the
	// Ed25519 private seed.
	PrivateKeyFile []byte

	// X25519PrivKey is the 32-byte clamped X25519 private scalar.
	X25519PrivKey []byte

	// Ed25519Seed is the 32-byte seed for the Ed25519 signing key.
	Ed25519Seed []byte
}

// I2P derives an I2P Destination (Ed25519 signing + X25519 encryption) from an
// Ed25519 private key.
//
// Two independent sub-keys are produced via domain separation:
//
//	signing key   : SHA-256("seedify:i2p:sign:" || seed) → Ed25519 key pair
//	encryption key: SHA-256("seedify:i2p:enc:"  || seed) → X25519 key pair
//
// This matches seedify.DeriveI2PDestinationKeys. The Destination layout follows
// the I2P Common Structures spec (0.9.44+):
//
//	[X25519 pubkey (32 B)] [zero padding (320 B)] [Ed25519 pubkey (32 B)]
//	[Key Certificate: type=5, len=4, sigType=7, cryptoType=4]
//
// Security note: the derived destination key is cryptographically linked to the
// source SSH key. Compromising either key compromises both.
func I2P(key *ed25519.PrivateKey) (*I2PKeys, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}

	// Signing sub-key (Ed25519).
	signLabel := []byte("seedify:i2p:sign:")
	signInput := make([]byte, len(signLabel)+len(key.Seed()))
	copy(signInput, signLabel)
	copy(signInput[len(signLabel):], key.Seed())
	signSubSeed := sha256.Sum256(signInput)

	signPrivKey := ed25519.NewKeyFromSeed(signSubSeed[:])
	signPubKey, ok := signPrivKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("derived I2P signing key is not Ed25519")
	}

	// Encryption sub-key (X25519), clamped per RFC 7748 §5.
	encLabel := []byte("seedify:i2p:enc:")
	encInput := make([]byte, len(encLabel)+len(key.Seed()))
	copy(encInput, encLabel)
	copy(encInput[len(encLabel):], key.Seed())
	encPrivScalar := sha256.Sum256(encInput)
	encPrivScalar[0] &= i2pClampClearLow
	encPrivScalar[31] &= i2pClampClearHigh
	encPrivScalar[31] |= i2pClampSetBit

	encPubKey, err := curve25519.X25519(encPrivScalar[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("i2p: X25519 public key derivation failed: %w", err)
	}

	// Destination serialisation.
	const (
		cryptoKeySize = 32
		signKeySize   = 32
		paddingSize   = i2pDestKeyRegionSize - cryptoKeySize - signKeySize
		keyCertSize   = 1 + 2 + i2pKeyCertPayloadSize
		destSize      = i2pDestKeyRegionSize + keyCertSize
	)

	destBytes := make([]byte, destSize)
	copy(destBytes, encPubKey)
	// Padding bytes [32..351] stay zero from make().
	copy(destBytes[cryptoKeySize+paddingSize:], signPubKey)

	offset := i2pDestKeyRegionSize
	destBytes[offset] = i2pKeyCertType
	destBytes[offset+1] = 0x00
	destBytes[offset+2] = byte(i2pKeyCertPayloadSize)
	destBytes[offset+3] = byte(i2pSigTypeEd25519 >> i2pUint16HighByteShift)
	destBytes[offset+4] = byte(i2pSigTypeEd25519)
	destBytes[offset+5] = byte(i2pCryptoTypeX25519 >> i2pUint16HighByteShift)
	destBytes[offset+6] = byte(i2pCryptoTypeX25519)

	// b32 = base32(SHA-256(destBytes)) — no padding, lowercase, + ".b32.i2p".
	destHash := sha256.Sum256(destBytes)
	b32Addr := strings.ToLower(
		strings.TrimRight(base32.StdEncoding.EncodeToString(destHash[:]), "="),
	) + ".b32.i2p"

	privFile := make([]byte, 0, destSize+i2pPrivKeyComponentSize+i2pPrivKeyComponentSize)
	privFile = append(privFile, destBytes...)
	privFile = append(privFile, encPrivScalar[:]...)
	privFile = append(privFile, signSubSeed[:]...)

	return &I2PKeys{
		B32Address:       b32Addr,
		DestinationBytes: destBytes,
		PrivateKeyFile:   privFile,
		X25519PrivKey:    encPrivScalar[:],
		Ed25519Seed:      signSubSeed[:],
	}, nil
}
