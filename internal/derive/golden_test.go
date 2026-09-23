package derive

import (
	"crypto/ed25519"
	"testing"
)

func fixedKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(FixedSeed00to1f)
}

func TestMnemonic24MatchesGolden(t *testing.T) {
	key := fixedKey()
	got, err := Mnemonic24(&key)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "Mnemonic24", got, GoldenMnemonic24)
}

func TestBraveSync25thWordForDateMatchesGolden(t *testing.T) {
	got, err := BraveSync25thWordForDate(BraveGoldenDate)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "BraveSync25thWordForDate", got, GoldenBrave25th)
}

func TestBitcoinNativeSegwitMatchesGolden(t *testing.T) {
	got, err := BitcoinNativeSegwit(GoldenMnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "bitcoin", got, GoldenBitcoin)
}

func TestEthereumMatchesGolden(t *testing.T) {
	got, err := Ethereum(GoldenMnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "ethereum", got, GoldenEthereum)
}

func TestSolanaMatchesGolden(t *testing.T) {
	got, err := Solana(GoldenMnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "solana", got, GoldenSolana)
}

func TestTronMatchesGolden(t *testing.T) {
	got, err := Tron(GoldenMnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "tron", got, GoldenTron)
}

func TestExtraChainsMatchGolden(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string, string) (string, error)
		want string
	}{
		{"bitcoincash", BitcoinCash, GoldenBitcoinCash},
		{"litecoin", Litecoin, GoldenLitecoin},
		{"dogecoin", Dogecoin, GoldenDogecoin},
		{"cosmos", Cosmos, GoldenCosmos},
		{"ripple", Ripple, GoldenRipple},
		{"stellar", Stellar, GoldenStellar},
		{"sui", Sui, GoldenSui},
		{"silentpayment", SilentPayment, GoldenSilentPayment},
		{"ton", Ton, GoldenTon},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fn(GoldenMnemonic24, "")
			if err != nil {
				t.Fatal(err)
			}
			assertEq(t, tt.name, got, tt.want)
		})
	}
}

func TestPolyseed16MatchesGolden(t *testing.T) {
	key := fixedKey()
	got, err := Polyseed16(&key, PolyseedGoldenBirthday)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "polyseed16", got, GoldenPolyseed16)

	epoch, err := Polyseed16(&key, PolyseedEpochBirthday)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "polyseedEpoch", epoch, GoldenPolyseedEpoch)
}

func TestMoneroFromPolyseedMatchesGolden(t *testing.T) {
	got, err := MoneroFromPolyseed(GoldenPolyseed16, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "monero_polyseed_primary", got.PrimaryAddress, GoldenMoneroPolyseedPrimary)
	if len(got.Subaddresses) < 1 {
		t.Fatal("expected 1 subaddress")
	}
	assertEq(t, "monero_polyseed_sub0", got.Subaddresses[0], GoldenMoneroPolyseedSub0)
}

func TestMoneroFromLegacyMatchesGolden(t *testing.T) {
	got, err := MoneroFromLegacy(GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "monero_legacy_primary", got.PrimaryAddress, GoldenMoneroLegacyPrimary)
	if len(got.Subaddresses) < 1 {
		t.Fatal("expected 1 subaddress")
	}
	assertEq(t, "monero_legacy_sub0", got.Subaddresses[0], GoldenMoneroLegacySub0)
}

func TestBeldexFromLegacyMatchesGolden(t *testing.T) {
	got, err := BeldexFromLegacy(GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "beldex_legacy_primary", got.PrimaryAddress, GoldenBeldexLegacyPrimary)
	if len(got.Subaddresses) < 1 {
		t.Fatal("expected 1 subaddress")
	}
	assertEq(t, "beldex_legacy_sub0", got.Subaddresses[0], GoldenBeldexLegacySub0)
}

func TestNostrKeysFromMnemonicMatchesGolden(t *testing.T) {
	got, err := NostrKeysFromMnemonic(GoldenMnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "npub", got.Npub, GoldenNpub)
	assertEq(t, "nsec", got.Nsec, GoldenNsec)
	assertEq(t, "pubHex", got.PubKeyHex, GoldenPubHex)
	assertEq(t, "privHex", got.PrivKeyHex, GoldenPrivHex)
}

func assertEq(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}
