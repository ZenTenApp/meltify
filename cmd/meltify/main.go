// Package main provides the meltify CLI.
package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/seedify"
	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const openSSHBcryptKDFRounds = 1

// Populated at build time via -ldflags (set by GoReleaser).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var out = newCLIOut()

func main() {
	if err := execute(os.Args[1:], os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "meltify: "+err.Error())
		os.Exit(1)
	}
}

func execute(args []string, stdin io.Reader) error {
	cmd := newRootCommand(stdin)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader) *cobra.Command {
	var subaccount string
	var braveSync bool

	rootCmd := &cobra.Command{
		Use:   "meltify [key-path]",
		Short: "Export compact Nostr/SSH/MELT seed material from an Ed25519 OpenSSH key",
		Long: `meltify prints a compact, colored export from an Ed25519 OpenSSH private key:

- OpenSSH public key fingerprint
- OpenSSH public key with derived npub comment
- Nostr npub / hex public key
- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr nsec / hex secret key

Use --brave-sync to print only the MELT seed phrase with Brave Sync's daily 25th word appended.
Encrypted keys prompt for the existing SSH key passphrase.`,
		Example: `  meltify ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify
  meltify --subaccount account-name ~/.ssh/id_ed25519
  meltify --brave-sync ~/.ssh/id_ed25519`,
		Version:      fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && stdin == os.Stdin {
				if fi, statErr := os.Stdin.Stat(); statErr == nil && (fi.Mode()&os.ModeNamedPipe) == 0 {
					return cmd.Help()
				}
			}

			keyPath := "-"
			if len(args) > 0 {
				keyPath = args[0]
			}
			return runWithOptions(keyPath, subaccount, braveSync, stdin)
		},
	}
	rootCmd.Flags().StringVar(&subaccount, "subaccount", "", "Derive a deterministic subaccount key from the source key and subaccount name")
	rootCmd.Flags().BoolVar(&braveSync, "brave-sync", false, "Print only the MELT seed phrase with Brave Sync's daily 25th word appended")
	rootCmd.AddCommand(newManCommand(rootCmd))
	rootCmd.AddCommand(newCompletionCommand(rootCmd))
	return rootCmd
}

func newManCommand(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:          "man",
		Args:         cobra.NoArgs,
		Short:        "generate man pages",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			manPage, err := mcobra.NewManPage(1, rootCmd)
			if err != nil {
				return fmt.Errorf("could not generate man page: %w", err)
			}
			manPage = manPage.WithSection("Copyright", "Released under MIT license.")
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), manPage.Build(roff.NewDocument())); err != nil {
				return fmt.Errorf("could not write man page: %w", err)
			}
			return nil
		},
	}
}

func newCompletionCommand(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for meltify.

To load completions:

Bash:
  $ source <(meltify completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ meltify completion bash > /etc/bash_completion.d/meltify
  # macOS:
  $ meltify completion bash > $(brew --prefix)/etc/bash_completion.d/meltify

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ meltify completion zsh > "${fpath[1]}/_meltify"

Fish:
  $ meltify completion fish | source

  # To load completions for each session, execute once:
  $ meltify completion fish > ~/.config/fish/completions/meltify.fish

PowerShell:
  PS> meltify completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> meltify completion powershell > meltify.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(out)
			case "zsh":
				return rootCmd.GenZshCompletion(out)
			case "fish":
				return rootCmd.GenFishCompletion(out, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(out)
			default:
				return fmt.Errorf("unknown shell: %s", args[0])
			}
		},
	}
}

func runWithOptions(keyPath, subaccount string, braveSync bool, stdin io.Reader) error {
	keyBytes, err := readKey(keyPath, stdin)
	if err != nil {
		return err
	}

	key, sourcePass, err := parsePossiblyEncryptedEd25519Key(keyBytes, keyPath)
	if err != nil {
		return err
	}

	privateKeyPEM := keyBytes
	if subaccount != "" {
		key, privateKeyPEM, err = activateSubaccountSSHKey(key, subaccount, sourcePass)
		if err != nil {
			return err
		}
	}

	return printMeltifyOutput(key, privateKeyPEM, braveSync)
}

func readKey(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("could not read key from stdin: %w", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // User-provided key path.
	if err != nil {
		return nil, fmt.Errorf("could not read key %s: %w", path, err)
	}
	return b, nil
}

func parsePossiblyEncryptedEd25519Key(keyBytes []byte, keyPath string) (*ed25519.PrivateKey, []byte, error) {
	key, err := parsePrivateKey(keyBytes, nil)
	var pass []byte
	if err != nil && isPasswordError(err) {
		pass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return nil, nil, err
		}
		key, err = parsePrivateKey(keyBytes, pass)
		if err != nil {
			return nil, nil, fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return nil, nil, fmt.Errorf("could not parse key: %w", err)
	}

	edKey, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return nil, nil, unsupportedKeyTypeError(key)
	}
	return edKey, pass, nil
}

func parsePrivateKey(bts, pass []byte) (interface{}, error) {
	if len(pass) == 0 {
		return ssh.ParseRawPrivateKey(bts) //nolint:wrapcheck // Callers add parse context.
	}
	return ssh.ParseRawPrivateKeyWithPassphrase(bts, pass) //nolint:wrapcheck // Callers add parse context.
}

func isPasswordError(err error) bool {
	var kerr *ssh.PassphraseMissingError
	return errors.As(err, &kerr)
}

func askKeyPassphrase(keyPath string) ([]byte, error) {
	label := keyPath
	if label == "" || label == "-" {
		label = "stdin"
	}
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", label)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	return pass, nil
}

func unsupportedKeyTypeError(key interface{}) error {
	msg := fmt.Sprintf("only Ed25519 SSH keys are supported (got %T)", key)
	if _, ok := key.(*rsa.PrivateKey); ok {
		msg += "; RSA keys are not supported by meltify"
	}
	return errors.New(msg)
}

func activateSubaccountSSHKey(sourceKey *ed25519.PrivateKey, subaccount string, sourcePass []byte) (*ed25519.PrivateKey, []byte, error) {
	if len(sourcePass) == 0 {
		return nil, nil, errors.New("--subaccount requires the source key to be password-protected so meltify can keep the same passphrase")
	}

	derivedKey := deriveSubaccountSSHKey(sourceKey, subaccount)
	pemBlock, err := marshalOpenSSHEd25519PrivateKeyWithPassphraseKDFRounds(derivedKey, "", sourcePass, openSSHBcryptKDFRounds)
	if err != nil {
		return nil, nil, fmt.Errorf("could not encode subaccount SSH key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(pemBlock)
	if privateKeyPEM == nil {
		return nil, nil, errors.New("could not encode subaccount SSH key PEM")
	}
	return &derivedKey, privateKeyPEM, nil
}

func deriveSubaccountSSHKey(sourceKey *ed25519.PrivateKey, subaccount string) ed25519.PrivateKey {
	subaccountHash := sha256.Sum256([]byte(subaccount))
	seedMaterial := append(subaccountHash[:], sourceKey.Seed()...)
	derivedSeed := sha256.Sum256(seedMaterial)
	return ed25519.NewKeyFromSeed(derivedSeed[:])
}

func printMeltifyOutput(key *ed25519.PrivateKey, privateKeyPEM []byte, braveSync bool) error {
	sshPubKey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to encode SSH public key: %w", err)
	}

	mnemonic24, err := seedify.ToMnemonicWithLength(key, 24, "", false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word MELT mnemonic: %w", err)
	}

	if braveSync {
		braveWord, err := seedify.BraveSync25thWord()
		if err != nil {
			return fmt.Errorf("could not get Brave Sync word: %w", err)
		}

		fmt.Println()
		out.doubleDelimitedBlock("25-WORD SEED PHRASE (charmbracelet/MELT + Brave Sync)", mnemonic24+" "+braveWord, true)
		return nil
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic24, "")
	if err != nil {
		return fmt.Errorf("could not derive Nostr keys: %w", err)
	}

	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return errors.New("failed to decode OpenSSH private key PEM block")
	}

	pubB64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())
	publicKeyLine := "ssh-ed25519 " + pubB64 + " " + nostrKeys.Npub
	privB64 := base64.StdEncoding.EncodeToString(privateKeyBlock.Bytes)
	seedHex := hex.EncodeToString(key.Seed())

	fmt.Println()
	out.block("OPENSSH FINGERPRINT", ssh.FingerprintSHA256(sshPubKey), false)
	out.blankPair()
	out.block("OPENSSH PUBLIC KEY", publicKeyLine, false)
	out.blankPair()
	out.rawBorderBlock("----- nPubKey / hexPubKey -----", []blockLine{
		{text: nostrKeys.Npub},
		{text: nostrKeys.PubKeyHex},
	})
	out.blankPair()
	out.block("OPENSSH PRIVATE KEY", privB64, true)
	out.blankPair()
	out.block("ED25519 SEED", seedHex, true)
	out.blankPair()
	out.doubleDelimitedBlock("24-WORD SEED PHRASE (charmbracelet/MELT)", mnemonic24, true)
	out.blankPair()
	out.rawBorderBlock("----- nSecKey / hexSecKey -----", []blockLine{
		{text: nostrKeys.Nsec, sensitive: true},
		{text: nostrKeys.PrivKeyHex, sensitive: true},
	})
	out.blankPair()

	return nil
}
