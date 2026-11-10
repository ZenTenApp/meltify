package cliutil

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/spf13/cobra"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out)
}

// newFlagCommand builds a minimal command carrying the shared passphrase flag.
func newFlagCommand(target *string) *cobra.Command {
	cmd := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return nil }}
	AddBIP39PassphraseFlag(cmd, target)
	return cmd
}

func TestAddBIP39PassphraseFlag(t *testing.T) {
	t.Parallel()

	var value string
	cmd := newFlagCommand(&value)
	flag := cmd.Flags().Lookup(BIP39PassphraseFlag)
	if flag == nil {
		t.Fatalf("flag %q not registered", BIP39PassphraseFlag)
	}
	if flag.DefValue != "" {
		t.Errorf("default = %q, want empty (no passphrase)", flag.DefValue)
	}
	if flag.Shorthand != BIP39PassphraseShorthand {
		t.Errorf("shorthand = %q, want %q", flag.Shorthand, BIP39PassphraseShorthand)
	}
	if got := cmd.Flags().ShorthandLookup(BIP39PassphraseShorthand); got == nil || got.Name != BIP39PassphraseFlag {
		t.Errorf("shorthand %q does not resolve to %q", BIP39PassphraseShorthand, BIP39PassphraseFlag)
	}
	if !strings.Contains(flag.Usage, "25th word") {
		t.Errorf("usage does not explain the flag: %q", flag.Usage)
	}
	if !strings.Contains(flag.Usage, "visible in process arguments") {
		t.Errorf("usage hides that the value is visible in argv: %q", flag.Usage)
	}

	if err := cmd.Flags().Set(BIP39PassphraseFlag, "correct horse"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if value != "correct horse" {
		t.Errorf("value = %q, want %q", value, "correct horse")
	}

}

// TestBIP39PassphraseShorthandParses asserts cobra parses -e exactly like the
// long form, which is the shape a typo would silently drop.
func TestBIP39PassphraseShorthandParses(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"-" + BIP39PassphraseShorthand, "--" + BIP39PassphraseFlag} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()

			var value string
			cmd := newFlagCommand(&value)
			captureStdout(t, func() {
				cmd.SetArgs([]string{arg, "TREZOR"})
				if err := cmd.Execute(); err != nil {
					t.Errorf("execute %s: %v", arg, err)
				}
			})
			if value != "TREZOR" {
				t.Fatalf("value = %q, want %q", value, "TREZOR")
			}
			if !cmd.Flags().Changed(BIP39PassphraseFlag) {
				t.Errorf("%s did not mark %q as changed", arg, BIP39PassphraseFlag)
			}
		})
	}
}

func TestValidateBIP39Passphrase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		set     bool
		value   string
		wantErr bool
	}{
		{name: "unset", set: false, value: "", wantErr: false},
		{name: "empty", set: true, value: "", wantErr: true},
		{name: "spaces only", set: true, value: "   ", wantErr: false},
		{name: "value", set: true, value: "correct horse", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var value string
			cmd := newFlagCommand(&value)
			if tt.set {
				if err := cmd.Flags().Set(BIP39PassphraseFlag, tt.value); err != nil {
					t.Fatalf("set: %v", err)
				}
				value = tt.value
			}
			err := ValidateBIP39Passphrase(cmd, value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateBIP39Passphrase(%q) error = %v, wantErr %v", value, err, tt.wantErr)
			}
		})
	}
}

func TestPrintBIP39Passphrase(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	t.Run("unset prints nothing", func(t *testing.T) {
		out := captureStdout(t, func() {
			PrintBIP39Passphrase(termout.New(), "")
		})
		if out != "" {
			t.Fatalf("output = %q, want empty", out)
		}
	})

	t.Run("set prints a secret block", func(t *testing.T) {
		out := captureStdout(t, func() {
			PrintBIP39Passphrase(termout.New(), "correct horse")
		})
		want := "-----BEGIN BIP39 PASSPHRASE (WALLET 25TH WORD)-----\n" +
			"correct horse\n" +
			"-----END BIP39 PASSPHRASE (WALLET 25TH WORD)-----\n\n\n"
		if out != want {
			t.Fatalf("output = %q, want %q", out, want)
		}
	})
}
