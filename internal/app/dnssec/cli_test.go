package dnssec

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestExecuteRejectsMissingDomain(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"--ksk", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("missing --domain succeeded")
	}
	if !strings.Contains(err.Error(), "--domain is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecuteRejectsKSKAndZSK(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"--ksk", "--zsk", "--domain", "example.com", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("--ksk with --zsk succeeded")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecuteRejectsInvalidBits(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"--domain", "example.com", "--algorithm", "RSASHA256", "--bits", "1024", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("invalid --bits succeeded")
	}
	if !strings.Contains(err.Error(), "invalid RSA bit size") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecuteRejectsInvalidAlgorithm(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"--domain", "example.com", "--algorithm", "bogus", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("invalid --algorithm succeeded")
	}
	if !strings.Contains(err.Error(), "invalid --algorithm") {
		t.Fatalf("error = %v", err)
	}
}

func TestExecuteEd25519IgnoresBits(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	// ED25519 is the default and has no RSA size, so an invalid --bits must not
	// be rejected before the key is loaded.
	err := Execute([]string{"--domain", "example.com", "--bits", "1024", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("missing key succeeded")
	}
	if !strings.Contains(err.Error(), "could not load SSH key") {
		t.Fatalf("error = %v", err)
	}
}

func TestWriteDNSSECDir(t *testing.T) {
	t.Parallel()
	pair := goldenDNSSECPair(t)

	dir := t.TempDir()
	if err := writeDNSSECDir(dir, pair); err != nil {
		t.Fatalf("writeDNSSECDir: %v", err)
	}

	keyPath := filepath.Join(dir, pair.FileBase+".key")
	privatePath := filepath.Join(dir, pair.FileBase+".private")
	dsPath := filepath.Join(dir, pair.FileBase+".ds")

	keyBytes, err := os.ReadFile(keyPath) //nolint:gosec // Test reads a temp DNSSEC key.
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	privateBytes, err := os.ReadFile(privatePath) //nolint:gosec // Test reads a temp DNSSEC key.
	if err != nil {
		t.Fatalf("read private: %v", err)
	}
	dsBytes, err := os.ReadFile(dsPath) //nolint:gosec // Test reads a temp DS record.
	if err != nil {
		t.Fatalf("read ds: %v", err)
	}

	if string(keyBytes) != string(pair.KeyFile) {
		t.Fatalf("key file = %q", keyBytes)
	}
	if string(privateBytes) != string(pair.PrivateKeyFile) {
		t.Fatal("private file mismatch")
	}
	if string(dsBytes) != pair.DSRecord+"\n" {
		t.Fatalf("ds file = %q", dsBytes)
	}

	assertMode(t, keyPath, dnssecKeyMode)
	assertMode(t, privatePath, dnssecPrivMode)
	assertMode(t, dsPath, dnssecDSMode)
}

func TestWriteDNSSECDirRejectsNil(t *testing.T) {
	t.Parallel()
	if err := writeDNSSECDir(t.TempDir(), nil); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

var (
	goldenDNSSECOnce sync.Once
	goldenDNSSECVal  *derive.DNSSECKeypair
	goldenDNSSECErr  error
)

func goldenDNSSECPair(t *testing.T) *derive.DNSSECKeypair {
	t.Helper()
	goldenDNSSECOnce.Do(func() {
		key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
		goldenPair, err := derive.DNSSEC(&key, "example.com", derive.DNSSECAlgorithmRSASHA256, derive.DNSSECKSKFlags, 2048)
		goldenDNSSECVal, goldenDNSSECErr = goldenPair, err
	})
	if goldenDNSSECErr != nil {
		t.Fatalf("DNSSEC: %v", goldenDNSSECErr)
	}
	return goldenDNSSECVal
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
