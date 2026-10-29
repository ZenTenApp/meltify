package derive

import (
	"fmt"
	"strings"
	"testing"
)

func TestBitcoinMasterFingerprintMatchesGolden(t *testing.T) {
	t.Parallel()
	got, err := BitcoinMasterFingerprint(GoldenMnemonic24, "")
	if err != nil {
		t.Fatalf("BitcoinMasterFingerprint: %v", err)
	}
	assertEq(t, "master fingerprint", got, GoldenBitcoinMasterFingerprint)
}

func TestBitcoinMultisigAccountMatchesGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		scriptType  BitcoinMultisigScriptType
		xpub        string
		xprv        string
		slip132Pub  string
		slip132Priv string
	}{
		{
			name:        "legacy P2SH",
			scriptType:  BitcoinMultisigLegacyP2SH,
			xpub:        GoldenBitcoinMultisigLegacyXpub,
			xprv:        GoldenBitcoinMultisigLegacyXprv,
			slip132Pub:  GoldenBitcoinMultisigLegacyXpub,
			slip132Priv: GoldenBitcoinMultisigLegacyXprv,
		},
		{
			name:        "nested P2SH-P2WSH",
			scriptType:  BitcoinMultisigNestedSegwitP2SHP2WSH,
			xpub:        GoldenBitcoinMultisigNestedXpub,
			xprv:        GoldenBitcoinMultisigNestedXprv,
			slip132Pub:  GoldenBitcoinMultisigNestedYpub,
			slip132Priv: GoldenBitcoinMultisigNestedYprv,
		},
		{
			name:        "native P2WSH",
			scriptType:  BitcoinMultisigNativeSegwitP2WSH,
			xpub:        GoldenBitcoinMultisigNativeXpub,
			xprv:        GoldenBitcoinMultisigNativeXprv,
			slip132Pub:  GoldenBitcoinMultisigNativeZpub,
			slip132Priv: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			keys, err := BitcoinMultisigAccount(GoldenMnemonic24, "", test.scriptType)
			if err != nil {
				t.Fatalf("BitcoinMultisigAccount: %v", err)
			}
			assertEq(t, "xpub", keys.StandardPublicKey, test.xpub)
			assertEq(t, "xprv", keys.StandardPrivateKey, test.xprv)
			assertEq(t, "SLIP-0132 public key", keys.ExtendedPublicKey, test.slip132Pub)
			if test.slip132Priv != "" {
				assertEq(t, "SLIP-0132 private key", keys.ExtendedPrivateKey, test.slip132Priv)
			}
		})
	}
}

func TestBitcoinMultisigAccountDiffersByPassphrase(t *testing.T) {
	t.Parallel()
	withoutPassphrase, err := BitcoinMultisigAccount(GoldenMnemonic24, "", BitcoinMultisigNativeSegwitP2WSH)
	if err != nil {
		t.Fatalf("BitcoinMultisigAccount: %v", err)
	}
	withPassphrase, err := BitcoinMultisigAccount(GoldenMnemonic24, "wallet-passphrase", BitcoinMultisigNativeSegwitP2WSH)
	if err != nil {
		t.Fatalf("BitcoinMultisigAccount: %v", err)
	}
	if withoutPassphrase.StandardPublicKey == withPassphrase.StandardPublicKey {
		t.Fatal("BIP39 passphrase did not change the account key")
	}
}

func TestBitcoinMultisigAccountRejectsInvalidMnemonic(t *testing.T) {
	t.Parallel()
	if _, err := BitcoinMultisigAccount("not a mnemonic", "", BitcoinMultisigNativeSegwitP2WSH); err == nil {
		t.Fatal("invalid mnemonic succeeded")
	}
}

func TestBitcoinMultisigAddressMatchesGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scriptType BitcoinMultisigScriptType
		want       string
	}{
		{BitcoinMultisigLegacyP2SH, GoldenBitcoinMultisigLegacyAddr},
		{BitcoinMultisigNestedSegwitP2SHP2WSH, GoldenBitcoinMultisigNestedAddr},
		{BitcoinMultisigNativeSegwitP2WSH, GoldenBitcoinMultisigNativeAddr},
	}

	for _, test := range tests {
		got, err := BitcoinMultisigAddress(GoldenMnemonic24, "", test.scriptType)
		if err != nil {
			t.Fatalf("BitcoinMultisigAddress(%s): %v", test.scriptType, err)
		}
		assertEq(t, test.scriptType.String(), got, test.want)
	}
}

func TestBitcoinMultisigAddressRejectsInvalidMnemonic(t *testing.T) {
	t.Parallel()
	if _, err := BitcoinMultisigAddress("not a mnemonic", "", BitcoinMultisigNativeSegwitP2WSH); err == nil {
		t.Fatal("invalid mnemonic succeeded")
	}
}

func TestBitcoinMultisigDescriptorMatchesGolden(t *testing.T) {
	t.Parallel()

	nativeOrigin := "[" + GoldenBitcoinMasterFingerprint + "/48'/0'/0'/2']" + GoldenBitcoinMultisigNativeXpub + "/0/*"
	nestedOrigin := "[" + GoldenBitcoinMasterFingerprint + "/48'/0'/0'/1']" + GoldenBitcoinMultisigNestedXpub + "/0/*"
	legacyOrigin := "[" + GoldenBitcoinMasterFingerprint + "/48'/0'/0'/0']" + GoldenBitcoinMultisigLegacyXpub + "/0/*"

	tests := []struct {
		name       string
		scriptType BitcoinMultisigScriptType
		xpub       string
		want       string
	}{
		{"native P2WSH", BitcoinMultisigNativeSegwitP2WSH, GoldenBitcoinMultisigNativeXpub, "wsh(sortedmulti(1," + nativeOrigin + "))"},
		{"nested P2SH-P2WSH", BitcoinMultisigNestedSegwitP2SHP2WSH, GoldenBitcoinMultisigNestedXpub, "sh(wsh(sortedmulti(1," + nestedOrigin + ")))"},
		{"legacy P2SH", BitcoinMultisigLegacyP2SH, GoldenBitcoinMultisigLegacyXpub, "sh(sortedmulti(1," + legacyOrigin + "))"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := BitcoinMultisigDescriptor(test.scriptType, 1, []BitcoinMultisigCosigner{{
				AccountXPub:       test.xpub,
				MasterFingerprint: GoldenBitcoinMasterFingerprint,
			}})
			if err != nil {
				t.Fatalf("BitcoinMultisigDescriptor: %v", err)
			}
			assertEq(t, "descriptor", got, test.want)
		})
	}
}

func TestBitcoinMultisigDescriptorWithoutFingerprintOmitsOrigin(t *testing.T) {
	t.Parallel()
	got, err := BitcoinMultisigDescriptor(BitcoinMultisigNativeSegwitP2WSH, 1, []BitcoinMultisigCosigner{{
		AccountXPub: GoldenBitcoinMultisigNativeXpub,
	}})
	if err != nil {
		t.Fatalf("BitcoinMultisigDescriptor: %v", err)
	}
	want := "wsh(sortedmulti(1," + GoldenBitcoinMultisigNativeXpub + "/0/*))"
	assertEq(t, "descriptor", got, want)
}

func TestBitcoinMultisigDescriptorKeepsCosignerOrder(t *testing.T) {
	t.Parallel()
	got, err := BitcoinMultisigDescriptor(BitcoinMultisigNativeSegwitP2WSH, 2, []BitcoinMultisigCosigner{
		{AccountXPub: GoldenBitcoinMultisigNativeXpub, MasterFingerprint: GoldenBitcoinMasterFingerprint},
		{AccountXPub: GoldenBitcoinMultisigNestedXpub},
		{AccountXPub: GoldenBitcoinMultisigLegacyXpub, MasterFingerprint: "d219d86d"},
	})
	if err != nil {
		t.Fatalf("BitcoinMultisigDescriptor: %v", err)
	}

	wantPrefix := "wsh(sortedmulti(2,[" + GoldenBitcoinMasterFingerprint + "/48'/0'/0'/2']"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("descriptor = %q, want prefix %q", got, wantPrefix)
	}
	// sortedmulti sorts derived keys, not descriptor text, so the three keys
	// stay in the supplied order.
	if strings.Count(got, "/0/*") != 3 {
		t.Fatalf("descriptor = %q, want three wildcard keys", got)
	}
	if !strings.Contains(got, ","+GoldenBitcoinMultisigNestedXpub+"/0/*,") {
		t.Fatalf("descriptor = %q, want the foreign key in the middle", got)
	}
	// A cosigner that supplies a fingerprint but no derivation keeps the
	// script type's default origin path.
	wantSuffix := "[d219d86d/48'/0'/0'/2']" + GoldenBitcoinMultisigLegacyXpub + "/0/*))"
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("descriptor = %q, want suffix %q", got, wantSuffix)
	}
}

func TestBitcoinMultisigDescriptorRejectsBadInput(t *testing.T) {
	t.Parallel()

	valid := BitcoinMultisigCosigner{
		AccountXPub:       GoldenBitcoinMultisigNativeXpub,
		MasterFingerprint: GoldenBitcoinMasterFingerprint,
	}

	tests := []struct {
		name      string
		required  int
		cosigners []BitcoinMultisigCosigner
	}{
		{"zero required", 0, []BitcoinMultisigCosigner{valid}},
		{"more required than keys", 2, []BitcoinMultisigCosigner{valid}},
		{"no cosigners", 1, nil},
		{"empty xpub", 1, []BitcoinMultisigCosigner{{}}},
		{"garbage xpub", 1, []BitcoinMultisigCosigner{{AccountXPub: "xpub-not-a-key"}}},
		{"private key", 1, []BitcoinMultisigCosigner{{AccountXPub: GoldenBitcoinMultisigNativeXprv}}},
		{"short fingerprint", 1, []BitcoinMultisigCosigner{{AccountXPub: GoldenBitcoinMultisigNativeXpub, MasterFingerprint: "3e1f"}}},
		{"non-hex fingerprint", 1, []BitcoinMultisigCosigner{{AccountXPub: GoldenBitcoinMultisigNativeXpub, MasterFingerprint: "zzzzzzzz"}}},
		{"too many cosigners", 1, make([]BitcoinMultisigCosigner, MaxMultisigCosigners+1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := BitcoinMultisigDescriptor(BitcoinMultisigNativeSegwitP2WSH, test.required, test.cosigners); err == nil {
				t.Fatal("descriptor succeeded, want error")
			}
		})
	}
}

func TestBitcoinMultisigDescriptorRejectsUnknownScriptType(t *testing.T) {
	t.Parallel()
	cosigners := []BitcoinMultisigCosigner{{AccountXPub: GoldenBitcoinMultisigNativeXpub}}
	if _, err := BitcoinMultisigDescriptor(BitcoinMultisigScriptType(9), 1, cosigners); err == nil {
		t.Fatal("unknown script type succeeded, want error")
	}
}

func TestBitcoinMultisigAddressRejectsUnknownScriptType(t *testing.T) {
	t.Parallel()
	if _, err := BitcoinMultisigAddress(GoldenMnemonic24, "", BitcoinMultisigScriptType(9)); err == nil {
		t.Fatal("unknown script type succeeded, want error")
	}
}

func TestParseBitcoinMultisigScriptType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want BitcoinMultisigScriptType
	}{
		{"legacy", BitcoinMultisigLegacyP2SH},
		{"P2SH", BitcoinMultisigLegacyP2SH},
		{"0", BitcoinMultisigLegacyP2SH},
		{"nested", BitcoinMultisigNestedSegwitP2SHP2WSH},
		{"p2sh-p2wsh", BitcoinMultisigNestedSegwitP2SHP2WSH},
		{" 1 ", BitcoinMultisigNestedSegwitP2SHP2WSH},
		{"native", BitcoinMultisigNativeSegwitP2WSH},
		{"Bech32", BitcoinMultisigNativeSegwitP2WSH},
		{"2", BitcoinMultisigNativeSegwitP2WSH},
	}

	for _, test := range tests {
		got, err := ParseBitcoinMultisigScriptType(test.name)
		if err != nil {
			t.Fatalf("ParseBitcoinMultisigScriptType(%q): %v", test.name, err)
		}
		if got != test.want {
			t.Fatalf("ParseBitcoinMultisigScriptType(%q) = %d, want %d", test.name, got, test.want)
		}
	}

	for _, bad := range []string{"", "bogus", "3", "P2WPKH"} {
		if _, err := ParseBitcoinMultisigScriptType(bad); err == nil {
			t.Fatalf("ParseBitcoinMultisigScriptType(%q) succeeded, want error", bad)
		}
	}
}

func TestBitcoinMultisigScriptTypeNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scriptType BitcoinMultisigScriptType
		name       string
		path       string
	}{
		{BitcoinMultisigLegacyP2SH, "Legacy (P2SH)", "m/48'/0'/0'/0'"},
		{BitcoinMultisigNestedSegwitP2SHP2WSH, "Nested Segwit (P2SH-P2WSH)", "m/48'/0'/0'/1'"},
		{BitcoinMultisigNativeSegwitP2WSH, "Native Segwit (P2WSH)", "m/48'/0'/0'/2'"},
		{BitcoinMultisigScriptType(9), "Unknown", "m/48'/0'/0'/9'"},
	}

	for _, test := range tests {
		assertEq(t, "String", test.scriptType.String(), test.name)
		assertEq(t, "DerivationPath", test.scriptType.DerivationPath(), test.path)
	}
}

func TestMultisigRedeemScript(t *testing.T) {
	t.Parallel()

	pubKey := make([]byte, compressedKeyLen)
	pubKey[0] = 0x02

	script, err := multisigRedeemScript([][]byte{pubKey}, 1)
	if err != nil {
		t.Fatalf("multisigRedeemScript: %v", err)
	}
	if len(script) != 1+1+compressedKeyLen+1+1 {
		t.Fatalf("script length = %d, want %d", len(script), 1+1+compressedKeyLen+1+1)
	}
	if script[0] != opSmallIntBase+1 || script[len(script)-2] != opSmallIntBase+1 || script[len(script)-1] != opCheckMultiSig {
		t.Fatalf("script = %x, want OP_1 <key> OP_1 OP_CHECKMULTISIG", script)
	}

	if _, err := multisigRedeemScript(nil, 1); err == nil {
		t.Fatal("empty key set succeeded")
	}
	if _, err := multisigRedeemScript([][]byte{pubKey}, 2); err == nil {
		t.Fatal("2-of-1 succeeded")
	}
	if _, err := multisigRedeemScript([][]byte{make([]byte, 32)}, 1); err == nil {
		t.Fatal("uncompressed key succeeded")
	}
}

func TestBitcoinMultisigAddressesMatchSingleKeyGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scriptType BitcoinMultisigScriptType
		address    string
	}{
		{name: "legacy P2SH", scriptType: BitcoinMultisigLegacyP2SH, address: GoldenBitcoinMultisigLegacyAddr},
		{name: "nested P2SH-P2WSH", scriptType: BitcoinMultisigNestedSegwitP2SHP2WSH, address: GoldenBitcoinMultisigNestedAddr},
		{name: "native P2WSH", scriptType: BitcoinMultisigNativeSegwitP2WSH, address: GoldenBitcoinMultisigNativeAddr},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keys, err := BitcoinMultisigAccount(GoldenMnemonic24, "", test.scriptType)
			if err != nil {
				t.Fatalf("BitcoinMultisigAccount: %v", err)
			}

			set, err := BitcoinMultisigAddresses(test.scriptType, 1, []string{keys.StandardPublicKey}, 10)
			if err != nil {
				t.Fatalf("BitcoinMultisigAddresses: %v", err)
			}

			if len(set.Receive) != 10 || len(set.Change) != 10 {
				t.Fatalf("address counts = %d receive, %d change, want 10 each", len(set.Receive), len(set.Change))
			}
			// 1-of-1 /0/0 must stay identical to the pre-existing derivation.
			assertEq(t, "receive[0]", set.Receive[0], test.address)
			if set.Change[0] == set.Receive[0] {
				t.Fatalf("change[0] = receive[0] = %q", set.Change[0])
			}
			if set.Receive[0] == set.Receive[1] {
				t.Fatalf("receive[1] repeats receive[0] = %q", set.Receive[0])
			}
			if set.Change[0] == set.Change[1] {
				t.Fatalf("change[1] repeats change[0] = %q", set.Change[0])
			}
		})
	}
}

func TestBitcoinMultisigAddressesIgnoreCosignerOrder(t *testing.T) {
	t.Parallel()

	xpubs := make([]string, 0, 3)
	for _, scriptType := range []BitcoinMultisigScriptType{
		BitcoinMultisigLegacyP2SH,
		BitcoinMultisigNestedSegwitP2SHP2WSH,
		BitcoinMultisigNativeSegwitP2WSH,
	} {
		keys, err := BitcoinMultisigAccount(GoldenMnemonic24, "", scriptType)
		if err != nil {
			t.Fatalf("BitcoinMultisigAccount: %v", err)
		}
		xpubs = append(xpubs, keys.StandardPublicKey)
	}

	forward, err := BitcoinMultisigAddresses(BitcoinMultisigNativeSegwitP2WSH, 2, xpubs, 3)
	if err != nil {
		t.Fatalf("forward order: %v", err)
	}
	reversed := []string{xpubs[2], xpubs[1], xpubs[0]}
	backward, err := BitcoinMultisigAddresses(BitcoinMultisigNativeSegwitP2WSH, 2, reversed, 3)
	if err != nil {
		t.Fatalf("reversed order: %v", err)
	}

	for i := range forward.Receive {
		assertEq(t, fmt.Sprintf("receive[%d]", i), backward.Receive[i], forward.Receive[i])
	}
	for i := range forward.Change {
		assertEq(t, fmt.Sprintf("change[%d]", i), backward.Change[i], forward.Change[i])
	}
	// A 2-of-3 policy must not collapse to the 1-of-1 address.
	if forward.Receive[0] == GoldenBitcoinMultisigNativeAddr {
		t.Fatalf("2-of-3 receive[0] equals the 1-of-1 address %q", forward.Receive[0])
	}
}

func TestBitcoinMultisigAddressesRejectInvalidPolicy(t *testing.T) {
	t.Parallel()

	keys, err := BitcoinMultisigAccount(GoldenMnemonic24, "", BitcoinMultisigNativeSegwitP2WSH)
	if err != nil {
		t.Fatalf("BitcoinMultisigAccount: %v", err)
	}
	xpub := keys.StandardPublicKey

	if _, err := BitcoinMultisigAddresses(BitcoinMultisigNativeSegwitP2WSH, 2, []string{xpub}, 10); err == nil {
		t.Fatal("2-of-1 policy succeeded")
	}
	if _, err := BitcoinMultisigAddresses(BitcoinMultisigNativeSegwitP2WSH, 1, []string{xpub}, 0); err == nil {
		t.Fatal("zero address count succeeded")
	}
	if _, err := BitcoinMultisigAddresses(BitcoinMultisigNativeSegwitP2WSH, 1, []string{"not-an-xpub"}, 10); err == nil {
		t.Fatal("invalid cosigner xpub succeeded")
	}
	if _, err := BitcoinMultisigAddresses(BitcoinMultisigNativeSegwitP2WSH, 1, []string{keys.StandardPrivateKey}, 10); err == nil {
		t.Fatal("private cosigner key succeeded")
	}
}

func TestNormalizeBitcoinExtendedKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "Ypub", key: GoldenBitcoinMultisigNestedYpub, want: GoldenBitcoinMultisigNestedXpub},
		{name: "Zpub", key: GoldenBitcoinMultisigNativeZpub, want: GoldenBitcoinMultisigNativeXpub},
		{name: "xpub passthrough", key: GoldenBitcoinMultisigNativeXpub, want: GoldenBitcoinMultisigNativeXpub},
		{name: "xprv passthrough", key: GoldenBitcoinMultisigNativeXprv, want: GoldenBitcoinMultisigNativeXprv},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeBitcoinExtendedKey("  " + test.key + "  ")
			if err != nil {
				t.Fatalf("NormalizeBitcoinExtendedKey: %v", err)
			}
			assertEq(t, "normalized key", got, test.want)
		})
	}

	if _, err := NormalizeBitcoinExtendedKey(""); err == nil {
		t.Fatal("empty key succeeded")
	}
	if _, err := NormalizeBitcoinExtendedKey("not-a-key"); err == nil {
		t.Fatal("garbage key succeeded")
	}
	// Flip a payload byte so the base58 checksum no longer matches.
	tampered := GoldenBitcoinMultisigNativeZpub[:len(GoldenBitcoinMultisigNativeZpub)-1] + "2"
	if _, err := NormalizeBitcoinExtendedKey(tampered); err == nil {
		t.Fatal("tampered key succeeded")
	}
}

func TestBitcoinMultisigAddressesGolden(t *testing.T) {
	t.Parallel()

	// receive[0] is the seedify golden address; the remaining values pin the
	// chain/index derivation on both the external (0) and internal (1) chains.
	tests := []struct {
		name       string
		scriptType BitcoinMultisigScriptType
		receive1   string
		receive9   string
		change0    string
		change9    string
	}{
		{
			name:       "legacy P2SH",
			scriptType: BitcoinMultisigLegacyP2SH,
			receive1:   "3A2J8kcr1eXCEiZMarYkiHM3PbfS7U2QoE",
			receive9:   "33WZ4rtUsJMyLajHe3P14mHAfwX5YMDZWf",
			change0:    "3KsNd1UySJBWmSe7GiUp3hTiNzcsbuyJu5",
			change9:    "3AikiRVSgXiC8RoVKhSzvsxxAgUEmWsEX9",
		},
		{
			name:       "nested P2SH-P2WSH",
			scriptType: BitcoinMultisigNestedSegwitP2SHP2WSH,
			receive1:   "3M1cxaExyNotBxLiEMvmcGbik23t8GLAQt",
			receive9:   "3LuCPUQzK73ftNb2g87fxC8tT7KBqn741x",
			change0:    "35FqQA9THY8KfP3MfqxyNz8xDeg7Q6Hi8x",
			change9:    "3FxuAvm3aCgVoR5e87ziyeAAqdqxPSnHVR",
		},
		{
			name:       "native P2WSH",
			scriptType: BitcoinMultisigNativeSegwitP2WSH,
			receive1:   "bc1qslcvf06a6g5qs99ph4dm7rqvlxkekhmudzhs5j78tkjgdgg93e9qsrx9u0",
			receive9:   "bc1q6mxnemxdhlp2ykcex6wqeukcxw34wp40l980fe08nyv7zm7gh9fspw05r0",
			change0:    "bc1qd807vgpapuzxg60wh88x6f2gp53cfunjqzskts5sjhdg0jg252gs2x0ytd",
			change9:    "bc1q8w8g0yapxruqxq28nj6wceu9ggyyhchvl4xa8a65aaal3jgwd8zq7vcd9j",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keys, err := BitcoinMultisigAccount(GoldenMnemonic24, "", test.scriptType)
			if err != nil {
				t.Fatalf("BitcoinMultisigAccount: %v", err)
			}
			set, err := BitcoinMultisigAddresses(test.scriptType, 1, []string{keys.StandardPublicKey}, 10)
			if err != nil {
				t.Fatalf("BitcoinMultisigAddresses: %v", err)
			}

			assertEq(t, "receive[1]", set.Receive[1], test.receive1)
			assertEq(t, "receive[9]", set.Receive[9], test.receive9)
			assertEq(t, "change[0]", set.Change[0], test.change0)
			assertEq(t, "change[9]", set.Change[9], test.change9)
		})
	}
}
