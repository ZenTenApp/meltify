package derive

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDNSSECUsesFixedEpoch(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	pair, err := DNSSEC(&key, "example.com", DNSSECAlgorithmED25519, DNSSECKSKFlags, DefaultRSABits)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}

	var created time.Time
	for _, line := range strings.Split(string(pair.PrivateKeyFile), "\n") {
		after, ok := strings.CutPrefix(line, "Created: ")
		if !ok {
			continue
		}
		created, err = time.Parse("20060102150405", after)
		if err != nil {
			t.Fatalf("parse Created: %v", err)
		}
	}
	if created.IsZero() {
		t.Fatal("no Created line in private file")
	}
	if !created.Equal(derivationEpoch) {
		t.Fatalf("Created = %s, want %s", created, derivationEpoch)
	}
}

func TestDNSSECRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := DNSSEC(nil, "example.com", DNSSECAlgorithmRSASHA256, DNSSECKSKFlags, 2048); err == nil {
		t.Fatal("DNSSEC(nil) succeeded, want error")
	}
}

func TestDNSSECRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := DNSSEC(&key, "example.com", 5, DNSSECKSKFlags, 2048); err == nil {
		t.Fatal("DNSSEC(5) succeeded, want error")
	}
}

func TestDNSSECRejectsInvalidFlags(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := DNSSEC(&key, "example.com", DNSSECAlgorithmRSASHA256, 258, 2048); err == nil {
		t.Fatal("DNSSEC(flags=258) succeeded, want error")
	}
}

func TestDNSSECRejectsInvalidBits(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := DNSSEC(&key, "example.com", DNSSECAlgorithmRSASHA256, DNSSECKSKFlags, 1024); err == nil {
		t.Fatal("DNSSEC(bits=1024) succeeded, want error")
	}
}

func TestDNSSECRejectsEmptyAndRootDomain(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	for _, domain := range []string{"", "   ", "."} {
		if _, err := DNSSEC(&key, domain, DNSSECAlgorithmRSASHA256, DNSSECKSKFlags, 2048); err == nil {
			t.Fatalf("DNSSEC(%q) succeeded, want error", domain)
		}
	}
}

func TestDNSSECMatchesGolden2048(t *testing.T) {
	t.Parallel()
	pair := goldenDNSSEC(t, "example.com", DNSSECKSKFlags)
	if got := len(pair.Domain); got == 0 || !strings.HasSuffix(pair.Domain, ".") {
		t.Fatalf("domain not absolute: %q", pair.Domain)
	}
	assertEq(t, "file base", pair.FileBase, GoldenDNSSEC2048FileBase)
	assertEq(t, "DNSKEY", pair.DNSKEYRecord, GoldenDNSSEC2048DNSKEY)
	assertEq(t, "DS", pair.DSRecord, GoldenDNSSEC2048DS)
	assertEq(t, "private file", string(pair.PrivateKeyFile), GoldenDNSSEC2048Private)
	if pair.KeyTag != GoldenDNSSEC2048KeyTag {
		t.Fatalf("key tag = %d, want %d", pair.KeyTag, GoldenDNSSEC2048KeyTag)
	}
	if string(pair.KeyFile) != GoldenDNSSEC2048DNSKEY+"\n" {
		t.Fatalf("key file = %q", pair.KeyFile)
	}
	if pair.Algorithm != DNSSECAlgorithmRSASHA256 || pair.Flags != DNSSECKSKFlags {
		t.Fatalf("algorithm/flags = %d/%d", pair.Algorithm, pair.Flags)
	}
	if pair.PublicKeyBase64 == "" {
		t.Fatal("empty public key base64")
	}
}

func TestDNSSECCanonicalizesDomain(t *testing.T) {
	t.Parallel()
	first := goldenDNSSEC(t, "Example.COM", DNSSECKSKFlags)
	second := goldenDNSSEC(t, "example.com.", DNSSECKSKFlags)
	if first.DNSKEYRecord != second.DNSKEYRecord || first.DSRecord != second.DSRecord {
		t.Fatal("canonicalization produced different records")
	}
	if string(first.PrivateKeyFile) != string(second.PrivateKeyFile) {
		t.Fatal("canonicalization produced different private keys")
	}
}

func TestDNSSECZSKAndKSKAreDistinct(t *testing.T) {
	t.Parallel()
	ksk := goldenDNSSEC(t, "example.com", DNSSECKSKFlags)
	zsk, err := DNSSEC(fixedKeyPtr(), "example.com", DNSSECAlgorithmRSASHA256, DNSSECZSKFlags, 2048)
	if err != nil {
		t.Fatalf("DNSSEC ZSK: %v", err)
	}
	if zsk.DNSKEYRecord == ksk.DNSKEYRecord {
		t.Fatal("KSK and ZSK produced the same DNSKEY")
	}
	if zsk.Flags != DNSSECZSKFlags {
		t.Fatalf("ZSK flags = %d", zsk.Flags)
	}
	if !strings.Contains(zsk.DNSKEYRecord, " IN DNSKEY 256 3 8 ") {
		t.Fatalf("unexpected ZSK record: %q", zsk.DNSKEYRecord)
	}
}

func TestDNSSECDifferentDomainsAreDistinct(t *testing.T) {
	t.Parallel()
	first := goldenDNSSEC(t, "example.com", DNSSECKSKFlags)
	second := goldenDNSSEC(t, "example.net", DNSSECKSKFlags)
	if first.DNSKEYRecord == second.DNSKEYRecord {
		t.Fatal("different zones produced the same DNSKEY")
	}
}

func TestDNSSECMatchesGoldenEd25519(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	pair, err := DNSSECAt(&key, "example.com", DNSSECAlgorithmED25519, DNSSECKSKFlags, DefaultRSABits, goldenCreated())
	if err != nil {
		t.Fatalf("DNSSECAt(ED25519): %v", err)
	}

	assertEq(t, "file base", pair.FileBase, GoldenDNSSECEd25519FileBase)
	assertEq(t, "DNSKEY", pair.DNSKEYRecord, GoldenDNSSECEd25519DNSKEY)
	assertEq(t, "DS", pair.DSRecord, GoldenDNSSECEd25519DS)
	assertEq(t, "private file", string(pair.PrivateKeyFile), GoldenDNSSECEd25519Private)
	assertEq(t, "seed", hex.EncodeToString(pair.Ed25519Seed), GoldenDNSSECEd25519Seed)
	if pair.KeyTag != GoldenDNSSECEd25519KeyTag {
		t.Fatalf("key tag = %d, want %d", pair.KeyTag, GoldenDNSSECEd25519KeyTag)
	}
	if pair.Algorithm != DNSSECAlgorithmED25519 || pair.Flags != DNSSECKSKFlags {
		t.Fatalf("algorithm/flags = %d/%d", pair.Algorithm, pair.Flags)
	}

	// The public key must be the Ed25519 public key of the derived seed.
	priv := ed25519.NewKeyFromSeed(pair.Ed25519Seed)
	wantPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("derived public key is not Ed25519")
	}
	assertEq(t, "public key", pair.PublicKeyBase64, base64.StdEncoding.EncodeToString(wantPub))
}

func TestDNSSECEd25519IgnoresBits(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	first, err := DNSSECAt(&key, "example.com", DNSSECAlgorithmED25519, DNSSECKSKFlags, 2048, goldenCreated())
	if err != nil {
		t.Fatalf("DNSSECAt(2048): %v", err)
	}
	second, err := DNSSECAt(&key, "example.com", DNSSECAlgorithmED25519, DNSSECKSKFlags, 4096, goldenCreated())
	if err != nil {
		t.Fatalf("DNSSECAt(4096): %v", err)
	}
	if first.DNSKEYRecord != second.DNSKEYRecord {
		t.Fatal("ED25519 derivation depends on --bits")
	}
	if hex.EncodeToString(first.Ed25519Seed) != hex.EncodeToString(second.Ed25519Seed) {
		t.Fatal("ED25519 seed depends on --bits")
	}
}

func TestDNSSECDifferentAlgorithmsAreDistinct(t *testing.T) {
	t.Parallel()
	ed, err := DNSSECAt(fixedKeyPtr(), "example.com", DNSSECAlgorithmED25519, DNSSECKSKFlags, 4096, goldenCreated())
	if err != nil {
		t.Fatalf("DNSSEC ED25519: %v", err)
	}
	rsa := goldenDNSSEC(t, "example.com", DNSSECKSKFlags)
	if ed.DNSKEYRecord == rsa.DNSKEYRecord {
		t.Fatal("ED25519 and RSASHA256 produced the same DNSKEY")
	}
	if !strings.Contains(ed.DNSKEYRecord, " IN DNSKEY 257 3 15 ") {
		t.Fatalf("unexpected ED25519 record: %q", ed.DNSKEYRecord)
	}
	if !strings.Contains(rsa.DNSKEYRecord, " IN DNSKEY 257 3 8 ") {
		t.Fatalf("unexpected RSASHA256 record: %q", rsa.DNSKEYRecord)
	}
}

func goldenDNSSEC(t *testing.T, domain string, flags int) *DNSSECKeypair {
	t.Helper()
	pair, err := DNSSECAt(fixedKeyPtr(), domain, DNSSECAlgorithmRSASHA256, flags, 2048, goldenCreated())
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	return pair
}
