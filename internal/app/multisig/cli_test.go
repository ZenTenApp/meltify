package multisig

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
)

func TestPrintPolicyBlockMatchesGolden(t *testing.T) {
	opts := &options{scriptType: "native", required: 1}

	out := captureStdout(t, func() {
		if err := printPolicyBlock(derive.GoldenMnemonic24, derive.BitcoinMultisigNativeSegwitP2WSH, "npub1", opts); err != nil {
			t.Errorf("printPolicyBlock: %v", err)
		}
	})

	xpub := derive.GoldenBitcoinMultisigNativeXpub
	fingerprint := derive.GoldenBitcoinMasterFingerprint
	want := "===== BITCOIN =====\n" +
		"Policy Type: Multi Signature HD\n" +
		"Cosigners: 1\n" +
		"M of N: 1 /1\n" +
		"Script Type: Native Segwit (P2WSH)\n" +
		"Descriptor: wsh(sortedmulti(1,[" + fingerprint + "/48'/0'/0'/2']" + xpub + "/0/*))\n" +
		"Type: Software wallet\n" +
		"Label: npub1\n" +
		"Master fingerprint: " + fingerprint + "\n" +
		"Derivation: m/48'/0'/0'/2'\n" +
		"xpub: " + xpub + "\n" +
		"===== BITCOIN =====\n"

	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestPrintPolicyBlockLegacyAndNestedScriptTypes(t *testing.T) {
	tests := []struct {
		name       string
		scriptType derive.BitcoinMultisigScriptType
		scriptText string
		derivation string
		descriptor string
	}{
		{
			name:       "legacy",
			scriptType: derive.BitcoinMultisigLegacyP2SH,
			scriptText: "Script Type: Legacy (P2SH)",
			derivation: "Derivation: m/48'/0'/0'/0'",
			descriptor: "Descriptor: sh(sortedmulti(1,[" + derive.GoldenBitcoinMasterFingerprint + "/48'/0'/0'/0']" +
				derive.GoldenBitcoinMultisigLegacyXpub + "/0/*))",
		},
		{
			name:       "nested",
			scriptType: derive.BitcoinMultisigNestedSegwitP2SHP2WSH,
			scriptText: "Script Type: Nested Segwit (P2SH-P2WSH)",
			derivation: "Derivation: m/48'/0'/0'/1'",
			descriptor: "Descriptor: sh(wsh(sortedmulti(1,[" + derive.GoldenBitcoinMasterFingerprint + "/48'/0'/0'/1']" +
				derive.GoldenBitcoinMultisigNestedXpub + "/0/*)))",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := &options{scriptType: test.name, required: 1}
			out := captureStdout(t, func() {
				if err := printPolicyBlock(derive.GoldenMnemonic24, test.scriptType, "cold", opts); err != nil {
					t.Errorf("printPolicyBlock: %v", err)
				}
			})
			for _, want := range []string{test.scriptText, test.derivation, test.descriptor} {
				if !strings.Contains(out, want+"\n") {
					t.Fatalf("stdout missing %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestPrintPolicyBlockSlip132(t *testing.T) {
	opts := &options{scriptType: "native", required: 1, slip132: true}
	out := captureStdout(t, func() {
		if err := printPolicyBlock(derive.GoldenMnemonic24, derive.BitcoinMultisigNativeSegwitP2WSH, "cold", opts); err != nil {
			t.Errorf("printPolicyBlock: %v", err)
		}
	})

	if !strings.Contains(out, "\nxpub: "+derive.GoldenBitcoinMultisigNativeZpub+"\n") {
		t.Fatalf("stdout missing the SLIP-0132 zpub:\n%s", out)
	}
	// The descriptor always stays on the standard xpub regardless of --slip132.
	if !strings.Contains(out, derive.GoldenBitcoinMultisigNativeXpub+"/0/*") {
		t.Fatalf("descriptor missing the standard xpub:\n%s", out)
	}
}

func TestPrintPolicyBlockWithCosigners(t *testing.T) {
	opts := &options{
		scriptType: "native",
		required:   2,
		cosigners:  []string{derive.GoldenBitcoinMultisigNestedXpub},
	}
	out := captureStdout(t, func() {
		if err := printPolicyBlock(derive.GoldenMnemonic24, derive.BitcoinMultisigNativeSegwitP2WSH, "cold", opts); err != nil {
			t.Errorf("printPolicyBlock: %v", err)
		}
	})

	for _, want := range []string{"Cosigners: 2", "M of N: 2 /2", "sortedmulti(2,", derive.GoldenBitcoinMultisigNestedXpub + "/0/*)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestPrintPolicyBlockRejectsTooFewCosigners(t *testing.T) {
	opts := &options{scriptType: "native", required: 2}
	err := printPolicyBlock(derive.GoldenMnemonic24, derive.BitcoinMultisigNativeSegwitP2WSH, "cold", opts)
	if err == nil {
		t.Fatal("2-of-1 succeeded")
	}
	if !strings.Contains(err.Error(), "could not build multisig descriptor") {
		t.Fatalf("error = %v", err)
	}
}

func TestPrintPolicyBlockRejectsZeroRequired(t *testing.T) {
	opts := &options{scriptType: "native", required: 0}
	if err := printPolicyBlock(derive.GoldenMnemonic24, derive.BitcoinMultisigNativeSegwitP2WSH, "cold", opts); err == nil {
		t.Fatal("zero required signatures succeeded")
	}
}

func TestPolicyDescriptorRejectsNilKeys(t *testing.T) {
	t.Parallel()
	if _, err := policyDescriptor(derive.BitcoinMultisigNativeSegwitP2WSH, "3e1f3ae0", nil, &options{required: 1}); err == nil {
		t.Fatal("nil keys succeeded")
	}
}

func TestKeystoreLabelDefaultsToNpubSuffix(t *testing.T) {
	t.Parallel()
	got, err := keystoreLabel("", derive.GoldenMnemonic24)
	if err != nil {
		t.Fatalf("keystoreLabel: %v", err)
	}
	if want := "3vq7"; got != want {
		t.Fatalf("label = %q, want %q", got, want)
	}
	if !strings.HasSuffix(derive.GoldenNpub, got) {
		t.Fatalf("label %q is not the npub tail", got)
	}
	if len(got) > 16 {
		t.Fatalf("label %q exceeds Sparrow's 16-character limit", got)
	}
}

func TestNpubLabelSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		npub string
		want string
	}{
		{name: "golden npub", npub: derive.GoldenNpub, want: "3vq7"},
		{name: "exactly four", npub: "npub", want: "npub"},
		{name: "shorter than four", npub: "ab", want: "ab"},
		{name: "empty", npub: "", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := npubLabelSuffix(test.npub); got != test.want {
				t.Fatalf("npubLabelSuffix(%q) = %q, want %q", test.npub, got, test.want)
			}
		})
	}
}

func TestKeystoreLabelUsesFlag(t *testing.T) {
	t.Parallel()
	got, err := keystoreLabel("  cold-storage  ", derive.GoldenMnemonic24)
	if err != nil {
		t.Fatalf("keystoreLabel: %v", err)
	}
	if got != "cold-storage" {
		t.Fatalf("label = %q, want %q", got, "cold-storage")
	}
}

func TestRunWithOptionsRejectsInvalidScriptType(t *testing.T) {
	t.Parallel()
	err := runWithOptions(&options{keyPath: "-", scriptType: "bogus", required: 1}, strings.NewReader(""))
	if err == nil {
		t.Fatal("invalid script type succeeded")
	}
	if !strings.Contains(err.Error(), "unknown script type") {
		t.Fatalf("error = %v", err)
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

func TestExecuteScriptTypeFlagIsParsed(t *testing.T) {
	t.Parallel()
	info := cliutil.VersionInfo{Version: "test", Commit: "none", Date: "unknown"}
	// The script type is validated before the key is loaded, so a bogus value
	// fails without touching the filesystem.
	err := Execute([]string{"/no/such/key", "--script-type", "bogus"}, strings.NewReader(""), info)
	if err == nil {
		t.Fatal("bogus script type succeeded")
	}
	if !strings.Contains(err.Error(), "unknown script type") {
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
