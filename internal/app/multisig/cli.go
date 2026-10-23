// Package multisig provides the meltify-multisig CLI executable logic.
package multisig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/spf13/cobra"
)

const (
	binaryName      = "meltify-multisig"
	defaultScript   = "native"
	policyTypeLabel = "Multi Signature HD"
	walletTypeLabel = "Software wallet"
)

// options holds the parsed CLI state for one run.
type options struct {
	keyPath    string
	subaccount string
	label      string
	scriptType string
	slip132    bool
	required   int
	cosigners  []string
}

// Execute runs the meltify-multisig CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	opts := &options{}

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a BIP48 multisig keystore policy block from an Ed25519 OpenSSH key",
		Long: `meltify-multisig derives a BIP48 Bitcoin multisig keystore policy from an
Ed25519 OpenSSH private key and prints it as a wallet-import block:

  ===== BITCOIN =====
  Policy Type: Multi Signature HD
  Cosigners: 1
  M of N: 1 /1
  Script Type: Native Segwit (P2WSH)
  Descriptor: wsh(sortedmulti(1,[<fingerprint>/48'/0'/0'/2']<xpub>/0/*))
  Type: Software wallet
  Label: <label>
  Master fingerprint: <fingerprint>
  Derivation: m/48'/0'/0'/2'
  xpub: <xpub>
  ===== BITCOIN =====

The account xpub, master fingerprint, and descriptor come from the same master
seed as the SSH key, so this block is reproducible for a given key and script
type. Script types follow BIP48: legacy (0', P2SH), nested (1',
P2SH-P2WSH), and native (2', P2WSH — the default).

Only this key's account xpub can be derived here. A multisig policy that needs
other cosigners takes one --cosigner-xpub per additional key; the block then
reports the combined M of N and emits a descriptor with every key. Descriptor
keys keep the supplied order, because sortedmulti sorts derived public keys at
derivation time rather than in the descriptor text.

The default Label is this key's Nostr npub. The OpenSSH private key must be
password-protected; meltify-multisig prompts for that passphrase. Use
--subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-multisig ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-multisig
  meltify-multisig ~/.ssh/id_ed25519 --script-type nested --label cold
  meltify-multisig ~/.ssh/id_ed25519 -m 2 --cosigner-xpub xpub6... --cosigner-xpub xpub6...`,
		Version:      info.String(),
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && stdin == os.Stdin {
				if fi, statErr := os.Stdin.Stat(); statErr == nil && (fi.Mode()&os.ModeNamedPipe) == 0 {
					return cmd.Help()
				}
			}

			opts.keyPath = "-"
			if len(args) > 0 {
				opts.keyPath = args[0]
			}
			return runWithOptions(opts, stdin)
		},
	}

	rootCmd.Flags().StringVarP(&opts.subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&opts.label, "label", "", "Keystore label shown in the block (default: this key's Nostr npub)")
	rootCmd.Flags().StringVarP(&opts.scriptType, "script-type", "t", defaultScript, "BIP48 script type: native (P2WSH), nested (P2SH-P2WSH), or legacy (P2SH)")
	rootCmd.Flags().BoolVar(&opts.slip132, "slip132", false, "Print the SLIP-0132 account key (ypub/zpub) instead of the standard xpub")
	rootCmd.Flags().IntVarP(&opts.required, "required", "m", 1, "Required signatures (the m of the m-of-n policy)")
	rootCmd.Flags().StringArrayVar(&opts.cosigners, "cosigner-xpub", nil, "Additional cosigner account xpub; repeat once per cosigner")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(opts *options, stdin io.Reader) error {
	scriptType, err := derive.ParseBitcoinMultisigScriptType(opts.scriptType)
	if err != nil {
		return fmt.Errorf("could not parse --script-type: %w", err)
	}

	material, err := sshkey.LoadEd25519Key(opts.keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(opts.subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}

	mnemonic, err := derive.Mnemonic24(material.Key)
	if err != nil {
		return fmt.Errorf("could not generate 24-word MELT mnemonic: %w", err)
	}

	label, err := keystoreLabel(opts.label, mnemonic)
	if err != nil {
		return err
	}
	return printPolicyBlock(mnemonic, scriptType, label, opts)
}

// keystoreLabel resolves the block label, defaulting to the key's Nostr npub.
func keystoreLabel(flagValue, mnemonic string) (string, error) {
	if trimmed := strings.TrimSpace(flagValue); trimmed != "" {
		return trimmed, nil
	}

	nostrKeys, err := derive.NostrKeysFromMnemonic(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("could not derive Nostr npub for the default label: %w", err)
	}
	return nostrKeys.Npub, nil
}

// printPolicyBlock renders the ===== BITCOIN ===== policy block.
func printPolicyBlock(mnemonic string, scriptType derive.BitcoinMultisigScriptType, label string, opts *options) error {
	if opts.required < 1 {
		return fmt.Errorf("--required must be at least 1, got %d", opts.required)
	}

	fingerprint, err := derive.BitcoinMasterFingerprint(mnemonic, "")
	if err != nil {
		return fmt.Errorf("could not derive master fingerprint: %w", err)
	}

	keys, err := derive.BitcoinMultisigAccount(mnemonic, "", scriptType)
	if err != nil {
		return fmt.Errorf("could not derive BIP48 account keys: %w", err)
	}

	descriptor, err := policyDescriptor(scriptType, fingerprint, keys, opts)
	if err != nil {
		return err
	}

	displayedKey := keys.StandardPublicKey
	if opts.slip132 {
		displayedKey = keys.ExtendedPublicKey
	}

	cosignerCount := 1 + len(opts.cosigners)
	out := termout.New()
	out.RawBorderBlock("===== BITCOIN =====", []termout.BlockLine{
		{Text: "Policy Type: " + policyTypeLabel},
		{Text: fmt.Sprintf("Cosigners: %d", cosignerCount)},
		{Text: fmt.Sprintf("M of N: %d /%d", opts.required, cosignerCount)},
		{Text: "Script Type: " + scriptType.String()},
		{Text: "Descriptor: " + descriptor},
		{Text: "Type: " + walletTypeLabel},
		{Text: "Label: " + label},
		{Text: "Master fingerprint: " + fingerprint},
		{Text: "Derivation: " + scriptType.DerivationPath()},
		{Text: "xpub: " + displayedKey},
	})
	return nil
}

// policyDescriptor builds the multisig descriptor for this key plus every
// supplied cosigner xpub.
func policyDescriptor(scriptType derive.BitcoinMultisigScriptType, fingerprint string, keys *derive.BitcoinMultisigExtendedKeys, opts *options) (string, error) {
	if keys == nil {
		return "", errors.New("BIP48 account key material is incomplete")
	}

	cosigners := make([]derive.BitcoinMultisigCosigner, 0, 1+len(opts.cosigners))
	cosigners = append(cosigners, derive.BitcoinMultisigCosigner{
		AccountXPub:       keys.StandardPublicKey,
		MasterFingerprint: fingerprint,
		Derivation:        scriptType.DerivationPath(),
	})
	for _, xpub := range opts.cosigners {
		cosigners = append(cosigners, derive.BitcoinMultisigCosigner{AccountXPub: xpub})
	}

	descriptor, err := derive.BitcoinMultisigDescriptor(scriptType, opts.required, cosigners)
	if err != nil {
		return "", fmt.Errorf("could not build multisig descriptor: %w", err)
	}
	return descriptor, nil
}
