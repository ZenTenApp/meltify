package derive

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestValidRSABits(t *testing.T) {
	t.Parallel()
	if err := ValidRSABits(DefaultRSABits); err != nil {
		t.Fatalf("DefaultRSABits: %v", err)
	}
	for _, bits := range []int{2048, 3072, 4096} {
		if err := ValidRSABits(bits); err != nil {
			t.Fatalf("ValidRSABits(%d): %v", bits, err)
		}
	}
	if err := ValidRSABits(1024); err == nil {
		t.Fatal("ValidRSABits(1024) succeeded, want error")
	}
}

func TestRSARejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := RSA(nil, 2048); err == nil {
		t.Fatal("RSA(nil) succeeded, want error")
	}
}

func TestRSARejectsInvalidBits(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := RSA(&key, 1024); err == nil {
		t.Fatal("RSA(1024) succeeded, want error")
	}
}

func TestRSAMatchesGolden2048(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	rsaKey, err := RSA(&key, 2048)
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	if err := rsaKey.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Fatalf("N bitlen = %d", rsaKey.N.BitLen())
	}
	assertEq(t, "N", strings.ToLower(rsaKey.N.Text(16)), GoldenRSA2048N)
}
