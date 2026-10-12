package derive

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestDNSSECRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := DNSSEC(nil, "example.com", DNSSECAlgorithmRSASHA256, DNSSECKSKFlags, 2048); err == nil {
		t.Fatal("DNSSEC(nil) succeeded, want error")
	}
}

func TestDNSSECRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := DNSSEC(&key, "example.com", 15, DNSSECKSKFlags, 2048); err == nil {
		t.Fatal("DNSSEC(15) succeeded, want error")
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

func goldenDNSSEC(t *testing.T, domain string, flags int) *DNSSECKeypair {
	t.Helper()
	pair, err := DNSSEC(fixedKeyPtr(), domain, DNSSECAlgorithmRSASHA256, flags, 2048)
	if err != nil {
		t.Fatalf("DNSSEC: %v", err)
	}
	return pair
}
