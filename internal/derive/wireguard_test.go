package derive

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestWireGuardRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := WireGuard(nil); err == nil {
		t.Fatal("WireGuard(nil) succeeded, want error")
	}
}

func TestWireGuardMatchesGolden(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := WireGuard(&key)
	if err != nil {
		t.Fatalf("WireGuard: %v", err)
	}

	assertEq(t, "private key", keys.PrivateKey, GoldenWireGuardPrivateKey)
	assertEq(t, "public key", keys.PublicKey, GoldenWireGuardPublicKey)

	privBytes, err := base64.StdEncoding.DecodeString(keys.PrivateKey)
	if err != nil {
		t.Fatalf("private key is not valid base64: %v", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(keys.PublicKey)
	if err != nil {
		t.Fatalf("public key is not valid base64: %v", err)
	}
	if len(privBytes) != 32 || len(pubBytes) != 32 {
		t.Fatalf("decoded key lengths = %d/%d, want 32/32", len(privBytes), len(pubBytes))
	}

	// Clamp per RFC 7748 §5.
	if privBytes[0]&0x07 != 0 {
		t.Fatalf("private key low bits not cleared: %02x", privBytes[0])
	}
	if privBytes[31]&0x80 != 0 {
		t.Fatalf("private key high bit not cleared: %02x", privBytes[31])
	}
	if privBytes[31]&0x40 == 0 {
		t.Fatalf("private key bit 6 not set: %02x", privBytes[31])
	}

	// Recompute the public key independently from the decoded scalar.
	wantPub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	assertEq(t, "recomputed public key", keys.PublicKey, base64.StdEncoding.EncodeToString(wantPub))
}

func TestWireGuardDiffersByKey(t *testing.T) {
	t.Parallel()
	firstKey := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	first, err := WireGuard(&firstKey)
	if err != nil {
		t.Fatalf("WireGuard(first): %v", err)
	}

	otherSeed := make([]byte, 32)
	copy(otherSeed, FixedSeed00to1f)
	otherSeed[0] ^= 0xff
	secondKey := ed25519.NewKeyFromSeed(otherSeed)
	second, err := WireGuard(&secondKey)
	if err != nil {
		t.Fatalf("WireGuard(second): %v", err)
	}

	if first.PrivateKey == second.PrivateKey || first.PublicKey == second.PublicKey {
		t.Fatal("different keys produced the same WireGuard keypair")
	}
}
