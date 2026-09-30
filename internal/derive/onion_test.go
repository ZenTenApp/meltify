package derive

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOnionRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := Onion(nil); err == nil {
		t.Fatal("Onion(nil) succeeded, want error")
	}
}

func TestOnionMatchesGolden(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := Onion(&key)
	if err != nil {
		t.Fatalf("Onion: %v", err)
	}
	assertEq(t, "address", keys.Address, GoldenOnionAddress)
	assertEq(t, "secret", hex.EncodeToString(keys.PrivateKeyFile), GoldenOnionSecretFile)
	assertEq(t, "public", hex.EncodeToString(keys.PublicKeyFile), GoldenOnionPublicFile)
	if !strings.HasSuffix(keys.Address, ".onion") {
		t.Fatalf("address missing .onion suffix: %s", keys.Address)
	}
	if got, want := len(strings.TrimSuffix(keys.Address, ".onion")), 56; got != want {
		t.Fatalf("onion hostname length = %d, want %d", got, want)
	}
	if !bytes.Equal(keys.HostnameFile, []byte(keys.Address+"\n")) {
		t.Fatalf("hostname file = %q", keys.HostnameFile)
	}
	if len(keys.PrivateKeyFile) != 96 {
		t.Fatalf("secret file len = %d", len(keys.PrivateKeyFile))
	}
	if len(keys.PublicKeyFile) != 64 {
		t.Fatalf("public file len = %d", len(keys.PublicKeyFile))
	}
}
