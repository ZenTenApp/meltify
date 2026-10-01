package derive

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestDKIMRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := DKIM(nil, DefaultDKIMSelector, 2048); err == nil {
		t.Fatal("DKIM(nil) succeeded, want error")
	}
}

func TestDKIMRejectsEmptySelector(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := DKIM(&key, "", 2048); err == nil {
		t.Fatal("empty selector succeeded, want error")
	}
}

func TestDKIMRejectsInvalidBits(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := DKIM(&key, DefaultDKIMSelector, 1024); err == nil {
		t.Fatal("DKIM(1024) succeeded, want error")
	}
}

func TestDKIMMatchesGolden2048(t *testing.T) {
	t.Parallel()
	keys := goldenDKIM(t, DefaultDKIMSelector)
	rsaKey := parseDKIMPrivateKey(t, keys.PrivateKeyPEM)
	if rsaKey.N.BitLen() != 2048 {
		t.Fatalf("N bitlen = %d", rsaKey.N.BitLen())
	}
	assertEq(t, "N", strings.ToLower(rsaKey.N.Text(16)), GoldenDKIM2048N)
	assertEq(t, "TXT", keys.DNSTXTRecord, GoldenDKIM2048TXT)
	if !strings.HasPrefix(keys.DNSTXTRecord, "v=DKIM1; k=rsa; p="+keys.PublicKeyBase64) {
		t.Fatal("TXT record does not wrap PublicKeyBase64")
	}
}

func TestDKIMSelectorIsolatesFromRSA(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	rsaKey, err := RSA(&key, 2048)
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	dkimKey := parseDKIMPrivateKey(t, goldenDKIM(t, DefaultDKIMSelector).PrivateKeyPEM)
	if rsaKey.N.Cmp(dkimKey.N) == 0 {
		t.Fatal("DKIM modulus equals RSA modulus")
	}
}

func TestDKIMDifferentSelectors(t *testing.T) {
	t.Parallel()
	mail := parseDKIMPrivateKey(t, goldenDKIM(t, DefaultDKIMSelector).PrivateKeyPEM)
	other, err := DKIM(fixedKeyPtr(), "mail2026", 2048)
	if err != nil {
		t.Fatalf("DKIM mail2026: %v", err)
	}
	otherKey := parseDKIMPrivateKey(t, other.PrivateKeyPEM)
	if mail.N.Cmp(otherKey.N) == 0 {
		t.Fatal("selectors produced the same modulus")
	}
}

func goldenDKIM(t *testing.T, selector string) *DKIMKeys {
	t.Helper()
	keys, err := DKIM(fixedKeyPtr(), selector, 2048)
	if err != nil {
		t.Fatalf("DKIM: %v", err)
	}
	return keys
}

func fixedKeyPtr() *ed25519.PrivateKey {
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	return &key
}

func parseDKIMPrivateKey(t *testing.T, pemBytes []byte) *rsa.PrivateKey {
	t.Helper()
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	if len(rest) != 0 {
		t.Fatalf("trailing PEM bytes: %d", len(rest))
	}
	if block.Type != "PRIVATE KEY" {
		t.Fatalf("PEM type = %q", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("parsed type %T", parsed)
	}
	if err := rsaKey.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return rsaKey
}
