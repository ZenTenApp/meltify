package info

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/app/bchat"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"golang.org/x/crypto/ssh"
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

	mnemonic, err := derive.Mnemonic24(&key)
	if err != nil {
		t.Fatalf("Mnemonic24: %v", err)
	}

	w, err := deriveWalletAddresses(&key, mnemonic)
	if err != nil {
		t.Fatalf("deriveWalletAddresses: %v", err)
	}

	got := map[string]string{}
	for _, row := range w {
		got[row.label] = row.addr
	}
	tests := []struct {
		name string
		want string
	}{
		{"bitcoin", derive.GoldenBitcoin},
		{"bitcoincash", derive.GoldenBitcoinCash},
		{"ethereum", derive.GoldenEthereum},
		{"solana", derive.GoldenSolana},
		{"tron", derive.GoldenTron},
		{"arbitrum", derive.GoldenEthereum},
		{"litecoin", derive.GoldenLitecoin},
		{"dogecoin", derive.GoldenDogecoin},
		{"cosmos", derive.GoldenCosmos},
		{"ripple", derive.GoldenRipple},
		{"stellar", derive.GoldenStellar},
		{"sui", derive.GoldenSui},
		{"silentpayment", derive.GoldenSilentPayment},
		{"ton", derive.GoldenTon},
		{"monero", derive.GoldenMoneroLegacyPrimary},
		{"beldex", derive.GoldenBeldexLegacyPrimary},
		{"bchat", goldenBchat(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got[tt.name] != tt.want {
				t.Errorf("%s = %s, want %s", tt.name, got[tt.name], tt.want)
			}
		})
	}
}

// TestPrintReportSectionOrder locks the meltify-info export sequence:
// private material, fingerprint, public key, npub, then label:address lines.
func TestPrintReportSectionOrder(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	material := &sshkey.Material{
		Key:           &key,
		PrivateKeyPEM: pem.EncodeToMemory(block),
	}

	captured := captureStdout(func() {
		if err := printReport(material); err != nil {
			t.Errorf("printReport: %v", err)
		}
	})

	markers := []string{
		"BEGIN OPENSSH PRIVATE KEY",
		"BEGIN ED25519 SEED",
		"BEGIN 24-WORD SEED PHRASE",
		"nSecKey / hexSecKey",
		"BEGIN OPENSSH FINGERPRINT",
		"BEGIN OPENSSH PUBLIC KEY",
		"nPubKey / hexPubKey",
		"arbitrum:" + derive.GoldenEthereum,
		"arc:" + derive.GoldenEthereum,
		"avalanche:" + derive.GoldenEthereum,
		"base:" + derive.GoldenEthereum,
		"bchat:" + goldenBchat(t),
		"beldex:" + derive.GoldenBeldexLegacyPrimary,
		"bitcoin:" + derive.GoldenBitcoin,
		"bitcoincash:" + derive.GoldenBitcoinCash,
		"bnbchain:" + derive.GoldenEthereum,
		"celo:" + derive.GoldenEthereum,
		"cosmos:" + derive.GoldenCosmos,
		"cronos:" + derive.GoldenEthereum,
		"dogecoin:" + derive.GoldenDogecoin,
		"ethereum:" + derive.GoldenEthereum,
		"gnosis:" + derive.GoldenEthereum,
		"hyperevm:" + derive.GoldenEthereum,
		"litecoin:" + derive.GoldenLitecoin,
		"monad:" + derive.GoldenEthereum,
		"monero:" + derive.GoldenMoneroLegacyPrimary,
		"optimism:" + derive.GoldenEthereum,
		"plasma:" + derive.GoldenEthereum,
		"polygon:" + derive.GoldenEthereum,
		"ripple:" + derive.GoldenRipple,
		"silentpayment:" + derive.GoldenSilentPayment,
		"solana:" + derive.GoldenSolana,
		"stablechain:" + derive.GoldenEthereum,
		"stellar:" + derive.GoldenStellar,
		"sui:" + derive.GoldenSui,
		"ton:" + derive.GoldenTon,
		"tron:" + derive.GoldenTron,
		"worldchain:" + derive.GoldenEthereum,
	}
	last := -1
	for _, marker := range markers {
		idx := strings.Index(captured, marker)
		if idx < 0 {
			t.Errorf("output missing %q\nfull output:\n%s", marker, captured)
			continue
		}
		if idx < last {
			t.Errorf("marker %q appeared out of order (idx %d < %d)\nfull output:\n%s", marker, idx, last, captured)
		}
		last = idx
	}
}

func goldenBchat(t *testing.T) string {
	t.Helper()
	reduced, err := hex.DecodeString(derive.GoldenReducedSeedHex)
	if err != nil {
		t.Fatalf("GoldenReducedSeedHex: %v", err)
	}
	id, err := bchat.DeriveChatID(reduced)
	if err != nil {
		t.Fatalf("DeriveChatID: %v", err)
	}
	return id
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
