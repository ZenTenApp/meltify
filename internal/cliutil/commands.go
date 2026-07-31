// Package cliutil provides shared Cobra command helpers.
package cliutil

import (
	"fmt"

	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	"github.com/spf13/cobra"
)

// VersionInfo contains build-time version metadata.
type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

// String formats version metadata for Cobra.
func (v VersionInfo) String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", v.Version, v.Commit, v.Date)
}

// NewManCommand creates a hidden manpage-generation command.
func NewManCommand(rootCmd *cobra.Command) *cobra.Command {
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

// NewCompletionCommand creates a shell-completion command for a binary.
func NewCompletionCommand(rootCmd *cobra.Command, binaryName string) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: fmt.Sprintf(`Generate shell completion script for %[1]s.

To load completions:

Bash:
  $ source <(%[1]s completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ %[1]s completion bash > /etc/bash_completion.d/%[1]s
  # macOS:
  $ %[1]s completion bash > $(brew --prefix)/etc/bash_completion.d/%[1]s

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ %[1]s completion zsh > "${fpath[1]}/_%[1]s"

Fish:
  $ %[1]s completion fish | source

  # To load completions for each session, execute once:
  $ %[1]s completion fish > ~/.config/fish/completions/%[1]s.fish

PowerShell:
  PS> %[1]s completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> %[1]s completion powershell > %[1]s.ps1
  # and source this file from your PowerShell profile.
`, binaryName),
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
