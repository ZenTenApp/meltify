package derive

import (
	"crypto/ed25519"
	"testing"

	"github.com/ZenTenApp/seedify"
)

func fixedKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(FixedSeed00to1f)
}

// TestSeedifyCharacterization locks seedify v1.36.0 output for the functions
// meltify currently depends on (and the extra chain addresses we plan to add).
func TestSeedifyCharacterization(t *testing.T) {
	key := fixedKey()

	mnemonic24, err := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "mnemonic24", mnemonic24, GoldenMnemonic24)

	brave, err := seedify.BraveSync25thWordForDate(BraveGoldenDate)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "brave25th", brave, GoldenBrave25th)

	polyseed16, err := seedify.ToMnemonicWithLength(&key, 16, "", false, PolyseedGoldenBirthday)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "polyseed16", polyseed16, GoldenPolyseed16)

	polyseedEpoch, err := seedify.ToMnemonicWithLength(&key, 16, "", false, PolyseedEpochBirthday)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "polyseedEpoch", polyseedEpoch, GoldenPolyseedEpoch)

	nostr, err := seedify.DeriveNostrKeysWithHex(mnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "npub", nostr.Npub, GoldenNpub)
	assertEq(t, "nsec", nostr.Nsec, GoldenNsec)
	assertEq(t, "pubHex", nostr.PubKeyHex, GoldenPubHex)
	assertEq(t, "privHex", nostr.PrivKeyHex, GoldenPrivHex)

	type deriveFn func(string, string) (string, error)
	addrs := []struct {
		name string
		fn   deriveFn
		want string
	}{
		{"bitcoin", seedify.DeriveBitcoinAddressNativeSegwit, GoldenBitcoin},
		{"ethereum", seedify.DeriveEthereumAddress, GoldenEthereum},
		{"solana", seedify.DeriveSolanaAddress, GoldenSolana},
		{"tron", seedify.DeriveTronAddress, GoldenTron},
		{"litecoin", seedify.DeriveLitecoinAddress, GoldenLitecoin},
		{"dogecoin", seedify.DeriveDogecoinAddress, GoldenDogecoin},
		{"cosmos", seedify.DeriveCosmosAddress, GoldenCosmos},
		{"stellar", seedify.DeriveStellarAddress, GoldenStellar},
		{"ripple", seedify.DeriveRippleAddress, GoldenRipple},
		{"sui", seedify.DeriveSuiAddress, GoldenSui},
		{"silentpayment", seedify.DeriveSilentPaymentAddress, GoldenSilentPayment},
	}
	for _, tc := range addrs {
		got, err := tc.fn(mnemonic24, "")
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		assertEq(t, tc.name, got, tc.want)
	}

	xmr, err := seedify.DeriveMoneroKeys(polyseed16, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "monero_polyseed_primary", xmr.PrimaryAddress, GoldenMoneroPolyseedPrimary)
	if len(xmr.Subaddresses) < 1 {
		t.Fatal("monero polyseed: expected 1 subaddress")
	}
	assertEq(t, "monero_polyseed_sub0", xmr.Subaddresses[0], GoldenMoneroPolyseedSub0)

	xmrLegacy, err := seedify.DeriveMoneroKeysFromLegacySeed(GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "monero_legacy_primary", xmrLegacy.PrimaryAddress, GoldenMoneroLegacyPrimary)
	if len(xmrLegacy.Subaddresses) < 1 {
		t.Fatal("monero legacy: expected 1 subaddress")
	}
	assertEq(t, "monero_legacy_sub0", xmrLegacy.Subaddresses[0], GoldenMoneroLegacySub0)

	bdx, err := seedify.DeriveBeldexKeysFromLegacySeed(GoldenLegacy25, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "beldex_legacy_primary", bdx.PrimaryAddress, GoldenBeldexLegacyPrimary)
	if len(bdx.Subaddresses) < 1 {
		t.Fatal("beldex legacy: expected 1 subaddress")
	}
	assertEq(t, "beldex_legacy_sub0", bdx.Subaddresses[0], GoldenBeldexLegacySub0)
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
