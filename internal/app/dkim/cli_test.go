package dkim

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

func TestExecuteRejectsEmptySelector(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	err := Execute([]string{"--selector", "", "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("empty --selector succeeded")
	}
	if !strings.Contains(err.Error(), "--selector is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestWriteDKIMDir(t *testing.T) {
	t.Chdir(t.TempDir())
	keys := goldenMailDKIM(t)
	if err := writeDKIMDir("example.com", "mail", keys); err != nil {
		t.Fatalf("writeDKIMDir: %v", err)
	}

	privPath := filepath.Join("config", "dkim", "example.com", "mail.private")
	pubPath := filepath.Join("config", "dkim", "example.com", "mail.public")
	priv, err := os.ReadFile(privPath) //nolint:gosec // Test reads a temp DKIM key.
	if err != nil {
		t.Fatalf("read private: %v", err)
	}
	pub, err := os.ReadFile(pubPath) //nolint:gosec // Test reads a temp DNS TXT file.
	if err != nil {
		t.Fatalf("read public: %v", err)
	}
	if string(priv) != string(keys.PrivateKeyPEM) {
		t.Fatal("private file mismatch")
	}
	if string(pub) != keys.DNSTXTRecord+"\n" {
		t.Fatalf("public file = %q", pub)
	}
	assertMode(t, privPath, dkimPrivMode)
	assertMode(t, pubPath, dkimPubMode)
}

func TestWriteDKIMDirRejectsTraversal(t *testing.T) {
	t.Parallel()
	keys := &derive.DKIMKeys{PrivateKeyPEM: []byte("x"), DNSTXTRecord: "v=DKIM1"}
	for _, domain := range []string{"../etc", "/etc", "example.com/evil", `example.com\evil`, ".."} {
		if err := writeDKIMDir(domain, "mail", keys); err == nil {
			t.Fatalf("domain %q succeeded", domain)
		}
	}
	if err := writeDKIMDir("example.com", "../mail", keys); err == nil {
		t.Fatal("selector traversal succeeded")
	}
}

func TestWriteDKIMDirRejectsNil(t *testing.T) {
	t.Parallel()
	if err := writeDKIMDir("example.com", "mail", nil); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

var (
	goldenMailOnce sync.Once
	goldenMailKeys *derive.DKIMKeys
	goldenMailErr  error
)

func goldenMailDKIM(t *testing.T) *derive.DKIMKeys {
	t.Helper()
	goldenMailOnce.Do(func() {
		key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
		goldenMailKeys, goldenMailErr = derive.DKIM(&key, derive.DefaultDKIMSelector, 2048)
	})
	if goldenMailErr != nil {
		t.Fatalf("DKIM: %v", goldenMailErr)
	}
	return goldenMailKeys
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
