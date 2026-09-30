package sshkey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func marshalOpenSSH(t *testing.T, key ed25519.PrivateKey, passphrase []byte) []byte {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(key, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", passphrase)
	}
	if err != nil {
		t.Fatalf("marshal OpenSSH key: %v", err)
	}
	out := pem.EncodeToMemory(block)
	if out == nil {
		t.Fatal("PEM encode returned nil")
	}
	return out
}

func TestLoadEd25519KeyRejectsUnprotected(t *testing.T) {
	t.Parallel()
	key := testEd25519Key(t)
	pemBytes := marshalOpenSSH(t, key, nil)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_, err := LoadEd25519Key(path, nil)
	if !errors.Is(err, errKeyNotPasswordProtected) {
		t.Fatalf("LoadEd25519Key unprotected = %v, want %v", err, errKeyNotPasswordProtected)
	}
}

func TestLoadEd25519KeyRejectsUnprotectedStdin(t *testing.T) {
	t.Parallel()
	key := testEd25519Key(t)
	pemBytes := marshalOpenSSH(t, key, nil)

	_, err := LoadEd25519Key("-", bytes.NewReader(pemBytes))
	if !errors.Is(err, errKeyNotPasswordProtected) {
		t.Fatalf("LoadEd25519Key stdin unprotected = %v, want %v", err, errKeyNotPasswordProtected)
	}
}

func TestLoadEd25519KeyRejectsGarbageWithoutPrompt(t *testing.T) {
	t.Parallel()
	_, err := LoadEd25519Key("-", strings.NewReader("not a key"))
	if err == nil {
		t.Fatal("garbage key succeeded")
	}
	if errors.Is(err, errKeyNotPasswordProtected) {
		t.Fatalf("garbage key = unprotected, want parse error: %v", err)
	}
	if !strings.Contains(err.Error(), "could not parse key") {
		t.Fatalf("garbage key error = %v", err)
	}
}

func TestParseEncryptedEd25519Key(t *testing.T) {
	t.Parallel()
	key := testEd25519Key(t)
	const pass = "test-passphrase"
	pemBytes := marshalOpenSSH(t, key, []byte(pass))

	got, err := ParseEncryptedEd25519Key(pemBytes, []byte(pass))
	if err != nil {
		t.Fatalf("ParseEncryptedEd25519Key: %v", err)
	}
	if !bytes.Equal(got.Seed(), key.Seed()) {
		t.Fatal("parsed key seed mismatch")
	}
}

func TestParseEncryptedEd25519KeyRejectsUnprotected(t *testing.T) {
	t.Parallel()
	key := testEd25519Key(t)
	pemBytes := marshalOpenSSH(t, key, nil)

	_, err := ParseEncryptedEd25519Key(pemBytes, []byte("unused"))
	if !errors.Is(err, errKeyNotPasswordProtected) {
		t.Fatalf("ParseEncryptedEd25519Key unprotected = %v, want %v", err, errKeyNotPasswordProtected)
	}
}

func TestParseEncryptedEd25519KeyRejectsEmptyPassphrase(t *testing.T) {
	t.Parallel()
	key := testEd25519Key(t)
	pemBytes := marshalOpenSSH(t, key, []byte("test-passphrase"))

	_, err := ParseEncryptedEd25519Key(pemBytes, nil)
	if err == nil || !strings.Contains(err.Error(), "passphrase is required") {
		t.Fatalf("empty passphrase = %v", err)
	}
}

func TestParseEncryptedEd25519KeyWrongPassphrase(t *testing.T) {
	t.Parallel()
	key := testEd25519Key(t)
	pemBytes := marshalOpenSSH(t, key, []byte("test-passphrase"))

	_, err := ParseEncryptedEd25519Key(pemBytes, []byte("wrong"))
	if err == nil {
		t.Fatal("wrong passphrase succeeded")
	}
	if !strings.Contains(err.Error(), "could not parse key with passphrase") {
		t.Fatalf("wrong passphrase error = %v", err)
	}
}

func TestParseEncryptedEd25519KeyRejectsGarbage(t *testing.T) {
	t.Parallel()
	_, err := ParseEncryptedEd25519Key([]byte("not a key"), []byte("x"))
	if err == nil {
		t.Fatal("garbage key succeeded")
	}
	if errors.Is(err, errKeyNotPasswordProtected) {
		t.Fatalf("garbage key = unprotected, want parse error: %v", err)
	}
	if !strings.Contains(err.Error(), "could not parse key") {
		t.Fatalf("garbage key error = %v", err)
	}
}
