// Package termout provides terminal-aware block output helpers.
package termout

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

// CLIOut renders meltify-style blocks with optional terminal colors.
type CLIOut struct {
	color          bool
	borderStyle    lipgloss.Style
	valueStyle     lipgloss.Style
	sensitiveStyle lipgloss.Style
}

// New creates a CLI output renderer for stdout.
func New() *CLIOut {
	color := isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == ""
	o := &CLIOut{color: color}
	if !color {
		return o
	}

	palette := terminalPalette()
	o.borderStyle = lipgloss.NewStyle().Bold(true).Foreground(palette.text)
	o.valueStyle = lipgloss.NewStyle().Foreground(palette.public)
	o.sensitiveStyle = lipgloss.NewStyle().Foreground(palette.private)
	return o
}

type cliPalette struct {
	text    lipgloss.Color
	public  lipgloss.Color
	private lipgloss.Color
}

func terminalPalette() cliPalette {
	if terminalHasDarkBackground() {
		return cliPalette{
			text:    lipgloss.Color(completeColor("#FFFFFF", "15", "15")),
			public:  lipgloss.Color(completeColor("#7CFC00", "118", "10")),
			private: lipgloss.Color(completeColor("#FF5555", "203", "9")),
		}
	}
	return cliPalette{
		text:    lipgloss.Color(completeColor("#111111", "233", "0")),
		public:  lipgloss.Color(completeColor("#006B00", "22", "2")),
		private: lipgloss.Color(completeColor("#B00020", "124", "1")),
	}
}

func terminalHasDarkBackground() bool {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return true
	}
	return termenv.HasDarkBackground()
}

func completeColor(truecolor, ansi256, ansi string) string {
	//nolint:exhaustive
	switch lipgloss.ColorProfile() {
	case termenv.TrueColor:
		return truecolor
	case termenv.ANSI256:
		return ansi256
	}
	return ansi
}

func (o *CLIOut) render(style lipgloss.Style, s string) string {
	if !o.color {
		return s
	}
	return style.Render(s)
}

// Blank prints one blank line.
func (o *CLIOut) Blank() {
	fmt.Println()
}

// BlankPair prints two blank lines.
func (o *CLIOut) BlankPair() {
	fmt.Println()
	fmt.Println()
}

// Block prints a ----- delimited block.
func (o *CLIOut) Block(label, content string, sensitive bool) {
	o.delimitedBlock("-----", label, content, sensitive)
}

// DoubleDelimitedBlock prints a ===== delimited block.
func (o *CLIOut) DoubleDelimitedBlock(label, content string, sensitive bool) {
	o.delimitedBlock("=====", label, content, sensitive)
}

func (o *CLIOut) delimitedBlock(delimiter, label, content string, sensitive bool) {
	begin := delimiter + "BEGIN " + label + delimiter
	end := delimiter + "END " + label + delimiter
	contentStyle := o.valueStyle
	if sensitive {
		contentStyle = o.sensitiveStyle
	}
	fmt.Println(o.render(o.borderStyle, begin))
	fmt.Println(o.render(contentStyle, content))
	fmt.Println(o.render(o.borderStyle, end))
}

// RawBorderBlock prints a block where the same border line appears before and after the lines.
func (o *CLIOut) RawBorderBlock(border string, lines []BlockLine) {
	fmt.Println(o.render(o.borderStyle, border))
	for _, line := range lines {
		style := o.valueStyle
		if line.Sensitive {
			style = o.sensitiveStyle
		}
		fmt.Println(o.render(style, line.Text))
	}
	fmt.Println(o.render(o.borderStyle, border))
}

// BlockLine is a line rendered inside a raw-border block.
type BlockLine struct {
	Text      string
	Sensitive bool
}
