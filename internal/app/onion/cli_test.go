package onion

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestWriteHiddenServiceDir(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.Onion(&key)
	if err != nil {
		t.Fatalf("Onion: %v", err)
	}

	dir := t.TempDir()
	hs := filepath.Join(dir, "hs")
	if err := writeHiddenServiceDir(hs, keys); err != nil {
		t.Fatalf("writeHiddenServiceDir: %v", err)
	}

	secret, err := os.ReadFile(filepath.Join(hs, secretKeyFile)) //nolint:gosec // Test reads a temp HiddenServiceDir.
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	public, err := os.ReadFile(filepath.Join(hs, publicKeyFile)) //nolint:gosec
	if err != nil {
		t.Fatalf("read public: %v", err)
	}
	host, err := os.ReadFile(filepath.Join(hs, hostnameFile)) //nolint:gosec
	if err != nil {
		t.Fatalf("read hostname: %v", err)
	}

	if hex.EncodeToString(secret) != derive.GoldenOnionSecretFile {
		t.Fatalf("secret file mismatch")
	}
	if hex.EncodeToString(public) != derive.GoldenOnionPublicFile {
		t.Fatalf("public file mismatch")
	}
	if string(host) != derive.GoldenOnionAddress+"\n" {
		t.Fatalf("hostname = %q", host)
	}

	assertMode(t, filepath.Join(hs, secretKeyFile), hiddenServiceKeyMode)
	assertMode(t, filepath.Join(hs, publicKeyFile), hiddenServiceKeyMode)
	assertMode(t, filepath.Join(hs, hostnameFile), hiddenServiceHostMode)
}

func TestWriteHiddenServiceDirRejectsNil(t *testing.T) {
	t.Parallel()
	if err := writeHiddenServiceDir(t.TempDir(), nil); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

func TestExecuteMissingKey(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("missing key succeeded")
	}
	if !strings.Contains(err.Error(), "could not load SSH key") {
		t.Fatalf("error = %v", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if st.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, st.Mode().Perm(), want)
	}
}
