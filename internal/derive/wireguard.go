package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// RFC 7748 §5 X25519 scalar clamping constants.
const (
	wireGuardClampClearLow  = 248
	wireGuardClampClearHigh = 127
	wireGuardClampSetBit    = 64
)

// WireGuardKeys holds a WireGuard static key pair in the base64 format used by
// `wg genkey` / `wg pubkey`.
type WireGuardKeys struct {
	// PrivateKey is the 32-byte clamped Curve25519 scalar, base64-encoded.
	PrivateKey string

	// PublicKey is the corresponding Curve25519 public key, base64-encoded.
	PublicKey string
}

// WireGuard derives a deterministic WireGuard static key pair from an Ed25519
// private key.
//
// The seed is domain-separated and reduced to a Curve25519 scalar:
//
//	private key: SHA-256("seedify:wireguard:" || seed) → clamp (RFC 7748 §5)
//	public key : X25519(private key, curve25519.Basepoint)
//
// This matches seedify.DeriveWireGuardKeys. Both halves are standard padded
// base64, so they can be pasted directly into a WireGuard [Interface] or [Peer]
// section.
//
// Security note: the derived static key is cryptographically linked to the
// source SSH key. Compromising either key compromises both.
func WireGuard(key *ed25519.PrivateKey) (*WireGuardKeys, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}

	label := []byte("seedify:wireguard:")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())
	privScalar := sha256.Sum256(input)

	// Clamp per RFC 7748 §5.
	privScalar[0] &= wireGuardClampClearLow
	privScalar[31] &= wireGuardClampClearHigh
	privScalar[31] |= wireGuardClampSetBit

	pubKey, err := curve25519.X25519(privScalar[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("wireguard: public key derivation failed: %w", err)
	}

	return &WireGuardKeys{
		PrivateKey: base64.StdEncoding.EncodeToString(privScalar[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
	}, nil
}
