package info

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/ZenTenApp/seedify"
)

// TestDeriveWalletAddresses locks the deterministic wallet-address derivation
// for a fixed Ed25519 seed (00..1f).
//
// Golden values were cross-verified against the independent bip_utils Python
// reference implementation (BIP84 / BIP44 / SLIP-0010):
//
//	btc: bc1qslk39wvggqa0vl8nd6jckaz54dw3vk45c5w60m
//	eth: 0xF9297b542BDb5DA50C364f9AE4Cbe1F3933bA40F
//	sol: 5Pobwp6d9ihN9Nz38f87gVCEBFMgipFiSM2VtUhVit6w
//	trx: TQ8xLycC44dA9nnvME3K6X41iMjmR3J1Vz
func TestDeriveWalletAddresses(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)

	mnemonic, err := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)
	if err != nil {
		t.Fatalf("ToMnemonicWithLength: %v", err)
	}

	w, err := deriveWalletAddresses(mnemonic)
	if err != nil {
		t.Fatalf("deriveWalletAddresses: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"bitcoin (bc1)", w.Bitcoin, "bc1qslk39wvggqa0vl8nd6jckaz54dw3vk45c5w60m"},
		{"ethereum", w.Ethereum, "0xF9297b542BDb5DA50C364f9AE4Cbe1F3933bA40F"},
		{"solana", w.Solana, "5Pobwp6d9ihN9Nz38f87gVCEBFMgipFiSM2VtUhVit6w"},
		{"tron", w.Tron, "TQ8xLycC44dA9nnvME3K6X41iMjmR3J1Vz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestReportWalletSection renders the seedify-style wallet sections through
// termout and verifies the [section] header and field layout used by
// printReport.
func TestReportWalletSection(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := termout.New()
	captured := captureStdout(func() {
		out.Section("bitcoin addresses from 24 word seed")
		out.Blank()
		out.Field("bc1qtest", "native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0")
		out.Blank()
		out.AddressSection("ethereum address from 24 word seed", "0xtest")
	})

	for _, want := range []string{
		"[bitcoin addresses from 24 word seed]",
		"bc1qtest (native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0)",
		"[ethereum address from 24 word seed]",
		"0xtest",
	} {
		if !strings.Contains(captured, want) {
			t.Errorf("wallet section output missing %q\nfull output:\n%s", want, captured)
		}
	}
}

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}
