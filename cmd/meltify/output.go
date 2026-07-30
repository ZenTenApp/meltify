package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

type cliOut struct {
	color          bool
	borderStyle    lipgloss.Style
	valueStyle     lipgloss.Style
	sensitiveStyle lipgloss.Style
}

func newCLIOut() *cliOut {
	color := isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == ""
	o := &cliOut{color: color}
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

func (o *cliOut) render(style lipgloss.Style, s string) string {
	if !o.color {
		return s
	}
	return style.Render(s)
}

func (o *cliOut) blankPair() {
	fmt.Println()
	fmt.Println()
}

func (o *cliOut) block(label, content string, sensitive bool) {
	o.delimitedBlock("-----", label, content, sensitive)
}

func (o *cliOut) doubleDelimitedBlock(label, content string, sensitive bool) {
	o.delimitedBlock("=====", label, content, sensitive)
}

func (o *cliOut) delimitedBlock(delimiter, label, content string, sensitive bool) {
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

func (o *cliOut) rawBorderBlock(border string, lines []blockLine) {
	fmt.Println(o.render(o.borderStyle, border))
	for _, line := range lines {
		style := o.valueStyle
		if line.sensitive {
			style = o.sensitiveStyle
		}
		fmt.Println(o.render(style, line.text))
	}
	fmt.Println(o.render(o.borderStyle, border))
}

type blockLine struct {
	text      string
	sensitive bool
}
