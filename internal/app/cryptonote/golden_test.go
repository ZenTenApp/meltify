package cryptonote

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/seedify"
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

func TestLegacyAddressesMatchSeedifyGolden(t *testing.T) {
	xmr, err := seedify.DeriveMoneroKeysFromLegacySeed(derive.GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	if xmr.PrimaryAddress != derive.GoldenMoneroLegacyPrimary {
		t.Errorf("monero primary = %s, want %s", xmr.PrimaryAddress, derive.GoldenMoneroLegacyPrimary)
	}
	if len(xmr.Subaddresses) < 1 || xmr.Subaddresses[0] != derive.GoldenMoneroLegacySub0 {
		t.Errorf("monero sub0 = %v, want %s", xmr.Subaddresses, derive.GoldenMoneroLegacySub0)
	}

	bdx, err := seedify.DeriveBeldexKeysFromLegacySeed(derive.GoldenLegacy25, 1)
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
