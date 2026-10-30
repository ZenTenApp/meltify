package bitchat

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestPrintReportRejectsNil(t *testing.T) {
	t.Parallel()
	if err := printReport(nil); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

func TestPrintReportRejectsMissingNostr(t *testing.T) {
	t.Parallel()
	if err := printReport(&derive.BitChatKeys{}); err == nil {
		t.Fatal("keys without a Nostr slice succeeded")
	}
}

func TestPrintReportMatchesIdentity(t *testing.T) {
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}

	out := captureStdout(t, func() {
		if printErr := printReport(keys); printErr != nil {
			t.Errorf("printReport: %v", printErr)
		}
	})

	want := strings.Join([]string{
		"",
		"-----BEGIN NOISE STATIC (X25519)-----",
		derive.GoldenBitChatNoisePrivateKey,
		"-----END NOISE STATIC (X25519)-----",
		"",
		"",
		"-----BEGIN ED25519 SIGNING SEED-----",
		derive.GoldenBitChatSigningSeed,
		"-----END ED25519 SIGNING SEED-----",
		"",
		"",
		"-----BEGIN DEVICE SEED (GEOHASH HMAC)-----",
		derive.GoldenBitChatDeviceSeed,
		"-----END DEVICE SEED (GEOHASH HMAC)-----",
		"",
		"",
		"----- nSecKey / hexSecKey -----",
		derive.GoldenNsec,
		derive.GoldenPrivHex,
		"----- nSecKey / hexSecKey -----",
		"",
		"",
		"-----BEGIN PEER ID-----",
		derive.GoldenBitChatPeerID,
		"-----END PEER ID-----",
		"",
		"",
		"-----BEGIN NOISE FINGERPRINT-----",
		derive.GoldenBitChatNoiseFingerprint,
		"-----END NOISE FINGERPRINT-----",
		"",
		"",
		"-----BEGIN NOISE PUBLIC KEY-----",
		derive.GoldenBitChatNoisePublicKey,
		"-----END NOISE PUBLIC KEY-----",
		"",
		"",
		"-----BEGIN ED25519 SIGNING PUBLIC KEY-----",
		derive.GoldenBitChatSigningPublicKey,
		"-----END ED25519 SIGNING PUBLIC KEY-----",
		"",
		"",
		"----- nPubKey / hexPubKey -----",
		derive.GoldenNpub,
		derive.GoldenPubHex,
		"----- nPubKey / hexPubKey -----",
		"",
		"",
		"bitchat:" + derive.GoldenBitChatPeerID,
		"",
	}, "\n") + "\n"

	if out != want {
		t.Fatalf("stdout mismatch\n got: %q\nwant: %q", out, want)
	}
}

// TestPrintReportHidesNoSecrets checks that every secret block is printed as
// hex material rather than as a Go slice, and that the compact line carries
// only the peer ID.
func TestPrintReportCompactLine(t *testing.T) {
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	keys, err := derive.BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}

	out := captureStdout(t, func() {
		if printErr := printReport(keys); printErr != nil {
			t.Errorf("printReport: %v", printErr)
		}
	})

	if !strings.HasSuffix(out, "bitchat:"+hex.EncodeToString(keys.NoiseFingerprint[:8])+"\n\n") {
		t.Fatalf("compact line missing from output tail: %q", out)
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
