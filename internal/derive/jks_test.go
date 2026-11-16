package derive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

func TestJKSUsesFixedEpoch(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	pair, err := JKS(&key, "zenten", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("JKS: %v", err)
	}
	if !pair.CreationTime.Equal(derivationEpoch) || !pair.NotBefore.Equal(derivationEpoch) {
		t.Fatalf("CreationTime/NotBefore = %s/%s, want %s", pair.CreationTime, pair.NotBefore, derivationEpoch)
	}
}

func goldenJKSKeypair(t *testing.T) *JKSKeypair {
	t.Helper()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	pair, err := JKSAt(&key, GoldenJKSAlias, 2048, DefaultJKSValidityDays, pkix.Name{CommonName: "Zenten"}, goldenCreated())
	if err != nil {
		t.Fatalf("JKS: %v", err)
	}
	return pair
}

func TestJKSRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := JKS(nil, "zenten", 2048, DefaultJKSValidityDays, pkix.Name{}); err == nil {
		t.Fatal("JKS(nil) succeeded, want error")
	}
}

func TestJKSRejectsEmptyAlias(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := JKS(&key, "", 2048, DefaultJKSValidityDays, pkix.Name{}); err == nil {
		t.Fatal("empty alias succeeded, want error")
	}
}

func TestJKSRejectsInvalidValidity(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := JKS(&key, "zenten", 2048, 0, pkix.Name{}); err == nil {
		t.Fatal("zero validity succeeded, want error")
	}
}

func TestJKSRejectsInvalidBits(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	if _, err := JKS(&key, "zenten", 1024, DefaultJKSValidityDays, pkix.Name{}); err == nil {
		t.Fatal("1024-bit RSA succeeded, want error")
	}
}

func TestJKSMatchGolden(t *testing.T) {
	t.Parallel()
	pair := goldenJKSKeypair(t)

	assertEq(t, "alias", pair.Alias, GoldenJKSAlias)
	assertEq(t, "serial", pair.SerialNumber.String(), GoldenJKS2048Serial)
	assertEq(t, "modulus", pair.PrivateKey.N.Text(16), GoldenJKS2048N)
	assertEq(t, "pkcs8", hex.EncodeToString(pair.PrivateKeyPKCS8), GoldenJKS2048PrivateKeyPKCS8)
	assertEq(t, "cert", hex.EncodeToString(pair.CertificateDER), GoldenJKS2048CertDER)

	jksBytes, err := EncodeJKS(pair, []byte(GoldenJKS2048Password))
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}
	assertEq(t, "jks", hex.EncodeToString(jksBytes), GoldenJKS2048JKS)

	if got, want := pair.NotBefore.UTC().Format("20060102"), "20200101"; got != want {
		t.Fatalf("NotBefore = %s, want %s", got, want)
	}
	if !pair.NotAfter.Equal(pair.NotBefore.AddDate(0, 0, DefaultJKSValidityDays)) {
		t.Fatalf("NotAfter = %v, want %v", pair.NotAfter, pair.NotBefore.AddDate(0, 0, DefaultJKSValidityDays))
	}
}

func TestJKSDiffersByAlias(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	first, err := JKS(&key, "zenten", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("JKS(first): %v", err)
	}
	second, err := JKS(&key, "other", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("JKS(second): %v", err)
	}
	if first.PrivateKey.N.Cmp(second.PrivateKey.N) == 0 {
		t.Fatal("different aliases produced identical RSA keys")
	}
	if bytes.Equal(first.CertificateDER, second.CertificateDER) {
		t.Fatal("different aliases produced identical certificates")
	}
}

func TestJKSDefaultsCommonName(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	pair, err := JKS(&key, "zenten", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("JKS: %v", err)
	}
	assertEq(t, "common name", pair.DistinguishedName.CommonName, "zenten")
}

func TestParseJKSDistinguishedName(t *testing.T) {
	t.Parallel()
	name, err := ParseJKSDistinguishedName("CN=Zenten, OU=Mobile, O=ZenTen, L=City, ST=State, C=US")
	if err != nil {
		t.Fatalf("parse distinguished name: %v", err)
	}

	assertEq(t, "common name", name.CommonName, "Zenten")
	if len(name.OrganizationalUnit) != 1 || name.OrganizationalUnit[0] != "Mobile" {
		t.Fatalf("organizational unit = %#v, want [Mobile]", name.OrganizationalUnit)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "ZenTen" {
		t.Fatalf("organization = %#v, want [ZenTen]", name.Organization)
	}
	if len(name.Locality) != 1 || name.Locality[0] != "City" {
		t.Fatalf("locality = %#v, want [City]", name.Locality)
	}
	if len(name.Province) != 1 || name.Province[0] != "State" {
		t.Fatalf("province = %#v, want [State]", name.Province)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Fatalf("country = %#v, want [US]", name.Country)
	}
}

func TestParseJKSDistinguishedNameRejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, dn := range []string{"", "  ", "CN", "CN=", "XX=value", "CN=Zenten,,O=ZenTen"} {
		if _, err := ParseJKSDistinguishedName(dn); err == nil {
			t.Fatalf("ParseJKSDistinguishedName(%q) succeeded, want error", dn)
		}
	}
}

func TestEncodeJKSRejectsBadInput(t *testing.T) {
	t.Parallel()
	pair := goldenJKSKeypair(t)
	if _, err := EncodeJKS(nil, []byte("changeit")); err == nil {
		t.Fatal("EncodeJKS(nil) succeeded, want error")
	}
	if _, err := EncodeJKS(pair, nil); err == nil {
		t.Fatal("EncodeJKS with empty password succeeded, want error")
	}
}

func TestEncodeJKSSeparatePasswords(t *testing.T) {
	t.Parallel()
	pair := goldenJKSKeypair(t)
	storePassword, keyPassword := []byte("store-secret"), []byte("key-secret")
	for _, passwords := range [][2][]byte{{nil, keyPassword}, {storePassword, nil}} {
		if _, err := EncodeJKSWithPasswords(pair, passwords[0], passwords[1]); err == nil {
			t.Fatal("empty password succeeded")
		}
	}
	encoded, err := EncodeJKSWithPasswords(pair, storePassword, keyPassword)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	second, err := EncodeJKSWithPasswords(pair, storePassword, keyPassword)
	if err != nil || !bytes.Equal(encoded, second) {
		t.Fatal("separate-password encoding is not deterministic")
	}
	ks := keystore.New(keystore.WithCaseExactAliases())
	if err := ks.Load(bytes.NewReader(encoded), keyPassword); err == nil {
		t.Fatal("key password opened keystore")
	}
	if err := ks.Load(bytes.NewReader(encoded), storePassword); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := ks.GetPrivateKeyEntry(pair.Alias, storePassword); err == nil {
		t.Fatal("store password decrypted key entry")
	}
	entry, err := ks.GetPrivateKeyEntry(pair.Alias, keyPassword)
	if err != nil {
		t.Fatalf("get entry: %v", err)
	}
	if !bytes.Equal(entry.PrivateKey, pair.PrivateKeyPKCS8) {
		t.Fatal("private key mismatch")
	}
}

func TestEncodeJKSRoundTrip(t *testing.T) {
	t.Parallel()
	pair := goldenJKSKeypair(t)
	password := []byte(GoldenJKS2048Password)

	first, err := EncodeJKS(pair, password)
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}
	second, err := EncodeJKS(pair, password)
	if err != nil {
		t.Fatalf("EncodeJKS (second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("encoded JKS bytes differ for identical inputs")
	}

	ks := keystore.New(keystore.WithCaseExactAliases())
	if err := ks.Load(bytes.NewReader(first), password); err != nil {
		t.Fatalf("load JKS: %v", err)
	}
	if !ks.IsPrivateKeyEntry(GoldenJKSAlias) {
		t.Fatalf("keystore does not contain alias %s", GoldenJKSAlias)
	}

	entry, err := ks.GetPrivateKeyEntry(GoldenJKSAlias, password)
	if err != nil {
		t.Fatalf("get private key entry: %v", err)
	}
	if !bytes.Equal(entry.PrivateKey, pair.PrivateKeyPKCS8) {
		t.Fatal("decoded private key does not match")
	}
	if len(entry.CertificateChain) != 1 {
		t.Fatalf("certificate chain length = %d, want 1", len(entry.CertificateChain))
	}

	cert, err := x509.ParseCertificate(entry.CertificateChain[0].Content)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	assertEq(t, "certificate CN", cert.Subject.CommonName, "Zenten")
	if cert.NotAfter.Sub(pair.NotAfter) != 0 {
		t.Fatalf("certificate NotAfter = %v, want %v", cert.NotAfter, pair.NotAfter)
	}
}

func TestEncodePKCS12RoundTrip(t *testing.T) {
	t.Parallel()
	pair := goldenJKSKeypair(t)
	password := GoldenJKS2048Password

	first, err := EncodePKCS12(pair, []byte(password))
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}
	second, err := EncodePKCS12(pair, []byte(password))
	if err != nil {
		t.Fatalf("EncodePKCS12 (second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("encoded PKCS#12 bytes differ for identical inputs")
	}

	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(first, password)
	if err != nil {
		t.Fatalf("decode PKCS#12: %v", err)
	}
	if len(caCerts) != 0 {
		t.Fatalf("CA certificate count = %d, want 0", len(caCerts))
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("decoded key type = %T, want *rsa.PrivateKey", privateKey)
	}
	if rsaKey.D.Cmp(pair.PrivateKey.D) != 0 || rsaKey.N.Cmp(pair.PrivateKey.N) != 0 {
		t.Fatal("decoded private key does not match derived key")
	}
	if !bytes.Equal(certificate.Raw, pair.CertificateDER) {
		t.Fatal("decoded certificate does not match derived certificate")
	}

	// The alias is only visible through the friendlyName attribute, which the
	// entry must carry so keytool and Android signing configurations can find it.
	blocks, err := pkcs12.ToPEM(first, password)
	if err != nil {
		t.Fatalf("ToPEM: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("PEM block count = %d, want 2", len(blocks))
	}
	for _, block := range blocks {
		if got := block.Headers["friendlyName"]; got != GoldenJKSAlias {
			t.Fatalf("friendlyName = %q, want %q", got, GoldenJKSAlias)
		}
	}
}

func TestEncodePKCS12RejectsBadInput(t *testing.T) {
	t.Parallel()
	pair := goldenJKSKeypair(t)

	if _, err := EncodePKCS12(nil, []byte("secret")); err == nil {
		t.Fatal("EncodePKCS12(nil) succeeded, want error")
	}
	if _, err := EncodePKCS12(pair, nil); err == nil {
		t.Fatal("EncodePKCS12 with empty password succeeded, want error")
	}
}
