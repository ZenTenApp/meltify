package derive

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestI2PRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := I2P(nil); err == nil {
		t.Fatal("I2P(nil) succeeded, want error")
	}
}

func TestI2PMatchesGolden(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := I2P(&key)
	if err != nil {
		t.Fatalf("I2P: %v", err)
	}

	assertEq(t, "b32", keys.B32Address, GoldenI2PB32Address)
	assertEq(t, "destination", hex.EncodeToString(keys.DestinationBytes), GoldenI2PDestination)
	assertEq(t, "private file", hex.EncodeToString(keys.PrivateKeyFile), GoldenI2PPrivateKeyFile)
	assertEq(t, "x25519", hex.EncodeToString(keys.X25519PrivKey), GoldenI2PX25519PrivKey)
	assertEq(t, "ed25519 seed", hex.EncodeToString(keys.Ed25519Seed), GoldenI2PEd25519Seed)

	if !strings.HasSuffix(keys.B32Address, ".b32.i2p") {
		t.Fatalf("address missing .b32.i2p suffix: %s", keys.B32Address)
	}
	if got, want := len(strings.TrimSuffix(keys.B32Address, ".b32.i2p")), 52; got != want {
		t.Fatalf("b32 hostname length = %d, want %d", got, want)
	}
	if len(keys.DestinationBytes) != 391 {
		t.Fatalf("destination len = %d, want 391", len(keys.DestinationBytes))
	}
	if len(keys.PrivateKeyFile) != 455 {
		t.Fatalf("private file len = %d, want 455", len(keys.PrivateKeyFile))
	}
	if len(keys.X25519PrivKey) != 32 || len(keys.Ed25519Seed) != 32 {
		t.Fatalf("secret component lengths = %d/%d, want 32/32", len(keys.X25519PrivKey), len(keys.Ed25519Seed))
	}

	dest := keys.DestinationBytes
	if !bytes.Equal(keys.PrivateKeyFile[:len(dest)], dest) {
		t.Fatal("private file does not start with destination bytes")
	}
	if !bytes.Equal(keys.PrivateKeyFile[len(dest):len(dest)+32], keys.X25519PrivKey) {
		t.Fatal("private file X25519 component mismatch")
	}
	if !bytes.Equal(keys.PrivateKeyFile[len(dest)+32:], keys.Ed25519Seed) {
		t.Fatal("private file Ed25519 component mismatch")
	}

	// The Key Certificate must close the destination: type 5, len 4,
	// sigType 7 (EdDSA), cryptoType 4 (X25519).
	if got, want := dest[len(dest)-7:], []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}; !bytes.Equal(got, want) {
		t.Fatalf("key certificate = %x, want %x", got, want)
	}
}

func TestI2PDiffersByKey(t *testing.T) {
	t.Parallel()
	firstKey := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	first, err := I2P(&firstKey)
	if err != nil {
		t.Fatalf("I2P(first): %v", err)
	}

	otherSeed := make([]byte, 32)
	copy(otherSeed, FixedSeed00to1f)
	otherSeed[0] ^= 0xff
	secondKey := ed25519.NewKeyFromSeed(otherSeed)
	second, err := I2P(&secondKey)
	if err != nil {
		t.Fatalf("I2P(second): %v", err)
	}

	if first.B32Address == second.B32Address {
		t.Fatal("different keys produced the same b32 address")
	}
}
