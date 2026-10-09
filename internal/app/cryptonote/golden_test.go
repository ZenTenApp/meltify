package cryptonote

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestLegacySeedMatchesGolden(t *testing.T) {
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)

	gotReduced := hex.EncodeToString(legacySeedBytesFromKey(&key))
	if gotReduced != derive.GoldenReducedSeedHex {
		t.Errorf("reduced seed = %s, want %s", gotReduced, derive.GoldenReducedSeedHex)
	}

	phrase, err := legacySeedFromKey(&key)
	if err != nil {
		t.Fatal(err)
	}
	if phrase != derive.GoldenLegacy25 {
		t.Errorf("legacy25 = %s, want %s", phrase, derive.GoldenLegacy25)
	}
}

func TestCakePhraseFromFixedSeed(t *testing.T) {
	key := ed25519.NewKeyFromSeed(derive.FixedSeed00to1f)
	mnemonic, err := derive.Mnemonic24(&key)
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := cakePhraseFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	if derive.GoldenCake25 == "" {
		t.Fatalf("fill GoldenCake25 = %s", phrase)
	}
	if phrase != derive.GoldenCake25 {
		t.Errorf("cake 25-word = %s, want %s", phrase, derive.GoldenCake25)
	}
	if phrase == derive.GoldenLegacy25 {
		t.Fatal("Cake 25-word matched CryptoNote legacy phrase")
	}

	xmr, err := MoneroConfig.DeriveAddresses(phrase, 1)
	if err != nil {
		t.Fatal(err)
	}
	if derive.GoldenCakePrimary == "" {
		t.Fatalf("fill GoldenCakePrimary = %s sub0 = %s", xmr.PrimaryAddress, xmr.Subaddresses[0])
	}
	if xmr.PrimaryAddress != derive.GoldenCakePrimary {
		t.Errorf("cake primary = %s, want %s", xmr.PrimaryAddress, derive.GoldenCakePrimary)
	}
	if len(xmr.Subaddresses) < 1 || xmr.Subaddresses[0] != derive.GoldenCakeSub0 {
		t.Errorf("cake sub0 = %v, want %s", xmr.Subaddresses, derive.GoldenCakeSub0)
	}
}

func TestCakeFlagRemoved(t *testing.T) {
	info := cliutil.VersionInfo{}
	for _, coin := range []CoinConfig{MoneroConfig, BeldexConfig} {
		if err := newRootCommand(nil, info, coin).ParseFlags([]string{"--cake"}); err == nil {
			t.Errorf("%s accepted the removed --cake flag", coin.BinaryName)
		}
	}
}

func TestLegacyAddressesMatchGolden(t *testing.T) {
	xmr, err := MoneroConfig.DeriveAddresses(derive.GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	if xmr.PrimaryAddress != derive.GoldenMoneroLegacyPrimary {
		t.Errorf("monero primary = %s, want %s", xmr.PrimaryAddress, derive.GoldenMoneroLegacyPrimary)
	}
	if len(xmr.Subaddresses) < 1 || xmr.Subaddresses[0] != derive.GoldenMoneroLegacySub0 {
		t.Errorf("monero sub0 = %v, want %s", xmr.Subaddresses, derive.GoldenMoneroLegacySub0)
	}

	bdx, err := BeldexConfig.DeriveAddresses(derive.GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bdx.PrimaryAddress != derive.GoldenBeldexLegacyPrimary {
		t.Errorf("beldex primary = %s, want %s", bdx.PrimaryAddress, derive.GoldenBeldexLegacyPrimary)
	}
	if len(bdx.Subaddresses) < 1 || bdx.Subaddresses[0] != derive.GoldenBeldexLegacySub0 {
		t.Errorf("beldex sub0 = %v, want %s", bdx.Subaddresses, derive.GoldenBeldexLegacySub0)
	}
}
