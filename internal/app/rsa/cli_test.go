package rsa

import (
	"bytes"
	"crypto/ed25519"
	stdcrypto "crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
)

func TestExecuteRejectsInvalidBits(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"--bits", "1024", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("invalid --bits succeeded")
	}
	if !strings.Contains(err.Error(), "invalid RSA bit size") {
		t.Fatalf("error = %v", err)
	}
}

func TestEncodeOpenSSHRoundTrip(t *testing.T) {
	t.Parallel()
	rsaKey := goldenRSA2048(t)
	const pass = "test-passphrase"
	pemBytes, err := encodeOpenSSH(rsaKey, []byte(pass))
	if err != nil {
		t.Fatalf("encodeOpenSSH: %v", err)
	}
	if !bytes.Contains(pemBytes, []byte("BEGIN OPENSSH PRIVATE KEY")) {
		t.Fatalf("missing OpenSSH header:\n%s", pemBytes)
	}

	parsed, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(pass))
	if err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase: %v", err)
	}
	got, ok := parsed.(*stdcrypto.PrivateKey)
	if !ok {
		t.Fatalf("parsed type %T", parsed)
	}
	if got.N.Cmp(rsaKey.N) != 0 {
		t.Fatal("parsed OpenSSH modulus mismatch")
	}
}

func TestEncodePKCS8RoundTrip(t *testing.T) {
	t.Parallel()
	rsaKey := goldenRSA2048(t)
	const pass = "test-passphrase"
	pemBytes, err := encodePKCS8(rsaKey, []byte(pass))
	if err != nil {
		t.Fatalf("encodePKCS8: %v", err)
	}
	if !bytes.Contains(pemBytes, []byte("BEGIN ENCRYPTED PRIVATE KEY")) {
		t.Fatalf("missing PKCS#8 header:\n%s", pemBytes)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	parsed, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(pass))
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	got, ok := parsed.(*stdcrypto.PrivateKey)
	if !ok {
		t.Fatalf("parsed type %T", parsed)
	}
	if got.N.Cmp(rsaKey.N) != 0 {
		t.Fatal("parsed PKCS#8 modulus mismatch")
	}
}

func TestEncodeRejectsEmptyPassphrase(t *testing.T) {
	t.Parallel()
	rsaKey := goldenRSA2048(t)
	if _, err := encodeOpenSSH(rsaKey, nil); err == nil {
		t.Fatal("encodeOpenSSH empty passphrase succeeded")
	}
	if _, err := encodePKCS8(rsaKey, nil); err == nil {
		t.Fatal("encodePKCS8 empty passphrase succeeded")
	}
}

func TestEncodeRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := encodeOpenSSH(nil, []byte("pass")); err == nil {
		t.Fatal("encodeOpenSSH nil key succeeded")
	}
	if _, err := encodePKCS8(nil, []byte("pass")); err == nil {
		t.Fatal("encodePKCS8 nil key succeeded")
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

func TestWriteOutputFileMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id_rsa_derived")
	payload := []byte("dummy-pem\n")
	if err := writeOutput(path, payload); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // Test reads a temp derived-key path.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("file = %q", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != derivedKeyFileMode {
		t.Fatalf("mode = %o, want %o", st.Mode().Perm(), derivedKeyFileMode)
	}
}

var (
	goldenRSAOnce sync.Once
	goldenRSAKey  *stdcrypto.PrivateKey
	goldenRSAErr  error
)

func goldenRSA2048(t *testing.T) *stdcrypto.PrivateKey {
	t.Helper()
	goldenRSAOnce.Do(func() {
		key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
		goldenRSAKey, goldenRSAErr = derive.RSA(&key, 2048)
	})
	if goldenRSAErr != nil {
		t.Fatalf("RSA: %v", goldenRSAErr)
	}
	return goldenRSAKey
}
