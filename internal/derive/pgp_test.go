package derive

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestValidPGPBits(t *testing.T) {
	t.Parallel()
	if err := ValidPGPBits(DefaultPGPBits); err != nil {
		t.Fatalf("DefaultPGPBits: %v", err)
	}
	for _, bits := range []int{2048, 3072, 4096} {
		if err := ValidPGPBits(bits); err != nil {
			t.Fatalf("ValidPGPBits(%d): %v", bits, err)
		}
	}
	if err := ValidPGPBits(1024); err == nil {
		t.Fatal("ValidPGPBits(1024) succeeded, want error")
	}
}

func TestPGPRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := PGP(nil, 2048); err == nil {
		t.Fatal("PGP(nil) succeeded, want error")
	}
}

func TestPGPMatchesGolden2048(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := PGP(&key, 2048)
	if err != nil {
		t.Fatalf("PGP: %v", err)
	}
	if !keys.CreationTime.Equal(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("CreationTime = %s", keys.CreationTime)
	}
	if keys.PrimaryKey.N.BitLen() != 2048 {
		t.Fatalf("primary N bitlen = %d", keys.PrimaryKey.N.BitLen())
	}
	if keys.EncryptSubkey.N.BitLen() != 2048 {
		t.Fatalf("encrypt N bitlen = %d", keys.EncryptSubkey.N.BitLen())
	}
	if keys.PrimaryKey.N.Cmp(keys.EncryptSubkey.N) == 0 {
		t.Fatal("primary and encrypt moduli are equal")
	}
	assertEq(t, "primary.N", strings.ToLower(keys.PrimaryKey.N.Text(16)), GoldenPGPPrimaryN2048)
	assertEq(t, "encrypt.N", strings.ToLower(keys.EncryptSubkey.N.Text(16)), GoldenPGPEncryptN2048)
}
