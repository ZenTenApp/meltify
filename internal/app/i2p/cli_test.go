package i2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestWriteKeysDat(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.I2P(&key)
	if err != nil {
		t.Fatalf("I2P: %v", err)
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "i2p")
	if err := writeKeysDat(out, keys); err != nil {
		t.Fatalf("writeKeysDat: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(out, keysDatFile)) //nolint:gosec // Test reads a temp keys.dat.
	if err != nil {
		t.Fatalf("read keys.dat: %v", err)
	}
	if got := hex.EncodeToString(data); got != derive.GoldenI2PPrivateKeyFile {
		t.Fatalf("keys.dat mismatch")
	}

	assertFileMode(t, out, destinationDirMode)
	assertFileMode(t, filepath.Join(out, keysDatFile), keysDatMode)
}

func TestWriteKeysDatRejectsNil(t *testing.T) {
	t.Parallel()
	if err := writeKeysDat(t.TempDir(), nil); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

func TestPrintKeyMaterialRejectsNil(t *testing.T) {
	t.Parallel()
	if err := printKeyMaterial(nil); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

func TestPrintKeyMaterialMatchesSeedify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.I2P(&key)
	if err != nil {
		t.Fatalf("I2P: %v", err)
	}

	out := captureStdout(t, func() {
		if err := printKeyMaterial(keys); err != nil {
			t.Errorf("printKeyMaterial: %v", err)
		}
	})

	want := fmt.Sprintf(
		"B32 Address  : %s\nX25519 PrivKey (hex): %x\nEd25519 Seed  (hex): %x\n",
		keys.B32Address, keys.X25519PrivKey, keys.Ed25519Seed,
	)
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close pipe writer: %v", closeErr)
	}
	os.Stdout = original

	data, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("read pipe: %v", readErr)
	}
	return string(data)
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if st.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, st.Mode().Perm(), want)
	}
}
