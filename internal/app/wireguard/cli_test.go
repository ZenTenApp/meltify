package wireguard

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestPrintKeyMaterialMatchesSeedify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.WireGuard(&key)
	if err != nil {
		t.Fatalf("WireGuard: %v", err)
	}

	out := captureStdout(t, func() {
		if err := printKeyMaterial(keys); err != nil {
			t.Errorf("printKeyMaterial: %v", err)
		}
	})

	want := fmt.Sprintf(
		"PrivateKey = %s\nPublicKey  = %s\n",
		keys.PrivateKey, keys.PublicKey,
	)
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestPrintKeyMaterialRejectsNil(t *testing.T) {
	t.Parallel()
	if err := printKeyMaterial(nil); err == nil {
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
