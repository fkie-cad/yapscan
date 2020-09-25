package yapscan

import "github.com/fatih/color"

func init() {
	// Deactivate color on windows, it doesn't work.
	color.NoColor = true
}
