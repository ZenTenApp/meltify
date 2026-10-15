package pgp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestExecuteRequiresNameAndEmail(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	if err := Execute([]string{"--email", "alice@example.com"}, strings.NewReader(""), info); err == nil {
		t.Fatal("missing --name succeeded")
	}
	if err := Execute([]string{"--name", "Alice"}, strings.NewReader(""), info); err == nil {
		t.Fatal("missing --email succeeded")
	}
}

func TestExecuteRejectsInvalidBits(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{
		"--name", "Alice",
		"--email", "alice@example.com",
		"--bits", "1024",
		"/no/such/key",
	}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("invalid --bits succeeded")
	}
	if !strings.Contains(err.Error(), "invalid RSA bit size") {
		t.Fatalf("error = %v", err)
	}
}

func TestEncodeArmoredPrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.PGP(&key, 2048)
	if err != nil {
		t.Fatalf("PGP: %v", err)
	}

	gotFP := primaryFingerprint(keys)
	assertEq(t, "fingerprint", gotFP, derive.GoldenPGPFingerprint2048)

	const pass = "test-passphrase"
	asc, err := encodeArmoredPrivateKey(keys, "Alice", "alice@example.com", []byte(pass))
	if err != nil {
		t.Fatalf("encodeArmoredPrivateKey: %v", err)
	}
	if !bytes.Contains(asc, []byte("BEGIN PGP PRIVATE KEY BLOCK")) {
		t.Fatalf("missing armor header:\n%s", asc)
	}

	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(asc))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d entities", len(entities))
	}
	entity := entities[0]
	if err := entity.PrivateKey.Decrypt([]byte(pass)); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(entity.Subkeys) != 1 {
		t.Fatalf("got %d subkeys", len(entity.Subkeys))
	}
	if err := entity.Subkeys[0].PrivateKey.Decrypt([]byte(pass)); err != nil {
		t.Fatalf("Decrypt subkey: %v", err)
	}
	ident := "Alice <alice@example.com>"
	if _, ok := entity.Identities[ident]; !ok {
		t.Fatalf("identities = %v, want %q", identityNames(entity), ident)
	}
	assertEq(t, "imported fingerprint", fmtFingerprint(entity), derive.GoldenPGPFingerprint2048)
}

func TestEncodeArmoredPrivateKeyRejectsEmptyPassphrase(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.PGP(&key, 2048)
	if err != nil {
		t.Fatalf("PGP: %v", err)
	}
	if _, err := encodeArmoredPrivateKey(keys, "Alice", "alice@example.com", nil); err == nil {
		t.Fatal("empty passphrase succeeded")
	}
}

func TestReusePassphraseRequiresProtectedKey(t *testing.T) {
	t.Parallel()
	_, err := defaultReadOutputPassphrase(true, nil)
	if err == nil {
		t.Fatal("reuse with empty source pass succeeded")
	}
	if !strings.Contains(err.Error(), "--reuse-passphrase") {
		t.Fatalf("error = %v", err)
	}
}

func identityNames(entity *openpgp.Entity) []string {
	names := make([]string, 0, len(entity.Identities))
	for name := range entity.Identities {
		names = append(names, name)
	}
	return names
}

func primaryFingerprint(keys *derive.PGPKeys) string {
	pkt := packet.NewRSAPrivateKey(keys.CreationTime, keys.PrimaryKey)
	return hex.EncodeToString(pkt.Fingerprint)
}

func fmtFingerprint(entity *openpgp.Entity) string {
	return hex.EncodeToString(entity.PrimaryKey.Fingerprint)
}

func assertEq(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %s, want %s", name, got, want)
	}
}
