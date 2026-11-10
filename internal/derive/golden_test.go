package derive

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// goldenCreated is the pinned creation timestamp used by golden tests. Derivation
// now stamps the real current time, so tests that assert byte-exact output pin a
// fixed time through the *At variants.
func goldenCreated() time.Time {
	return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
}

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

// TestBIP39PassphraseVectorsMatchSeedify locks the passphrase path against
// github.com/ZenTenApp/seedify v1.36.0 for the same seed and passphrase. A
// regression here means a wallet restored from the printed phrase plus
// passphrase would land on different addresses.
func TestBIP39PassphraseVectorsMatchSeedify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func(string, string) (string, error)
		want string
	}{
		{"bitcoin", BitcoinNativeSegwit, GoldenBIP39Bitcoin},
		{"ethereum", Ethereum, GoldenBIP39Ethereum},
		{"tron", Tron, GoldenBIP39Tron},
		{"solana", Solana, GoldenBIP39Solana},
		{"litecoin", Litecoin, GoldenBIP39Litecoin},
		{"dogecoin", Dogecoin, GoldenBIP39Dogecoin},
		{"cosmos", Cosmos, GoldenBIP39Cosmos},
		{"ripple", Ripple, GoldenBIP39Ripple},
		{"stellar", Stellar, GoldenBIP39Stellar},
		{"sui", Sui, GoldenBIP39Sui},
		{"silentpayment", SilentPayment, GoldenBIP39SilentPayment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.fn(GoldenMnemonic24, GoldenBIP39Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			assertEq(t, tt.name, got, tt.want)
		})
	}

	t.Run("nostr", func(t *testing.T) {
		t.Parallel()
		keys, err := NostrKeysFromMnemonic(GoldenMnemonic24, GoldenBIP39Passphrase)
		if err != nil {
			t.Fatal(err)
		}
		assertEq(t, "npub", keys.Npub, GoldenBIP39Npub)
		assertEq(t, "nsec", keys.Nsec, GoldenBIP39Nsec)
		assertEq(t, "pubkey hex", keys.PubKeyHex, GoldenBIP39PubHex)
		assertEq(t, "privkey hex", keys.PrivKeyHex, GoldenBIP39PrivHex)
	})

	t.Run("multisig", func(t *testing.T) {
		t.Parallel()
		fingerprint, err := BitcoinMasterFingerprint(GoldenMnemonic24, GoldenBIP39Passphrase)
		if err != nil {
			t.Fatal(err)
		}
		assertEq(t, "master fingerprint", fingerprint, GoldenBIP39MFP)

		keys, err := BitcoinMultisigAccount(GoldenMnemonic24, GoldenBIP39Passphrase, BitcoinMultisigNativeSegwitP2WSH)
		if err != nil {
			t.Fatal(err)
		}
		assertEq(t, "xpub", keys.StandardPublicKey, GoldenBIP39MultisigXpub)
		assertEq(t, "zpub", keys.ExtendedPublicKey, GoldenBIP39MultisigZpub)
	})

	t.Run("cake", func(t *testing.T) {
		t.Parallel()
		spend, err := CakeSpendKey(GoldenMnemonic24, GoldenBIP39Passphrase, 0)
		if err != nil {
			t.Fatal(err)
		}
		if GoldenBIP39CakeSpendKeyHex == "" {
			t.Fatalf("fill GoldenBIP39CakeSpendKeyHex = %s", hex.EncodeToString(spend))
		}
		assertEq(t, "cake spend key", hex.EncodeToString(spend), GoldenBIP39CakeSpendKeyHex)
	})
}

// TestBIP39PassphraseChangesDerivedKeys asserts the passphrase is actually
// mixed into the seed: every BIP39-derived value must differ from the
// no-passphrase value, while the printed mnemonic stays the same.
func TestBIP39PassphraseChangesDerivedKeys(t *testing.T) {
	t.Parallel()

	key := fixedKey()
	mnemonic, err := Mnemonic24(&key)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "mnemonic", mnemonic, GoldenMnemonic24)

	pairs := []struct {
		name      string
		fn        func(string, string) (string, error)
		plainWant string
		passWant  string
	}{
		{"bitcoin", BitcoinNativeSegwit, GoldenBitcoin, GoldenBIP39Bitcoin},
		{"ethereum", Ethereum, GoldenEthereum, GoldenBIP39Ethereum},
		{"solana", Solana, GoldenSolana, GoldenBIP39Solana},
	}
	for _, tt := range pairs {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plain, err := tt.fn(mnemonic, "")
			if err != nil {
				t.Fatal(err)
			}
			withPass, err := tt.fn(mnemonic, GoldenBIP39Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			assertEq(t, "no passphrase", plain, tt.plainWant)
			assertEq(t, "with passphrase", withPass, tt.passWant)
			if plain == withPass {
				t.Fatal("passphrase did not change the derived key")
			}
		})
	}
}
