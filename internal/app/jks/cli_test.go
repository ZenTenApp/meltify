package jks

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
)

func TestPrintSigningSecrets(t *testing.T) {
	const (
		path          = "zenten-release.jks"
		alias         = "zenten"
		storePassword = "changeit"
		keyPassword   = "changeit"
	)

	jksBytes := []byte{0xfe, 0xed, 0xfe, 0xed, 0x00}
	out := captureStdout(t, func() {
		printSigningSecrets(path, alias, storePassword, keyPassword, jksBytes)
	})

	want := "[Android signing secrets]\n" +
		"\n" +
		"ANDROID_KEYSTORE_BASE64\n" +
		"/u3+7QA=\n" +
		"(is the JKS file — base64-encoded contents of zenten-release.jks)\n" +
		"\n" +
		"ANDROID_KEY_ALIAS\n" +
		"zenten\n" +
		"(chosen when you created the keystore — set via --alias; verify with keytool -list -keystore zenten-release.jks)\n" +
		"\n" +
		"ANDROID_STORE_PASSWORD\n" +
		"changeit\n" +
		"(password you set when creating the keystore — required to open the file; cannot be extracted from the JKS)\n" +
		"\n" +
		"ANDROID_KEY_PASSWORD\n" +
		"changeit\n" +
		"(password for the key entry inside the keystore — set at creation; for meltify-jks this is the same as the store password)\n" +
		"\n"

	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestRunWithOptionsValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		alias    string
		output   string
		dn       string
		bits     int
		validity int
		wantErr  string
	}{
		{name: "invalid bits", alias: "zenten", output: "out.jks", bits: 1024, validity: 1, wantErr: "invalid --bits"},
		{name: "invalid validity", alias: "zenten", output: "out.jks", bits: 2048, validity: 0, wantErr: "invalid --validity"},
		{name: "missing output", alias: "zenten", output: "", bits: 2048, validity: 1, wantErr: "--output is required"},
		{name: "invalid dn", alias: "zenten", output: "out.jks", dn: "CN=", bits: 2048, validity: 1, wantErr: "invalid --dn"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := runWithOptions("-", "", tt.alias, tt.output, tt.dn, tt.bits, tt.validity, false, strings.NewReader(""))
			if err == nil {
				t.Fatalf("runWithOptions succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteMissingKey(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	out := filepath.Join(t.TempDir(), "out.jks")
	err := Execute([]string{"--alias", "zenten", "--output", out, "/no/such/key"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("missing key succeeded")
	}
	if !strings.Contains(err.Error(), "could not load SSH key") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("keystore written despite missing key: %v", statErr)
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
