package style

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	// HeavyGreenCheckMark unicode.
	HeavyGreenCheckMark = "\u2705"
	// HeavyRedCrossMark unicode.
	HeavyRedCrossMark = "\u274C"
	// ProgressBar cell.
	ProgressBarCell = "▉"
)

var (
	// infobar.
	InfoBarItemFgColor = tcell.ColorSilver
	// main views.
	FgColor              = tcell.ColorFloralWhite
	BgColor              = tview.Styles.PrimitiveBackgroundColor
	BorderColor          = tcell.NewRGBColor(135, 175, 146) //nolint:mnd
	HelpHeaderFgColor    = tcell.NewRGBColor(135, 175, 146) //nolint:mnd
	MenuBgColor          = tcell.ColorMediumSeaGreen
	PageHeaderBgColor    = tcell.ColorMediumSeaGreen
	PageHeaderFgColor    = tcell.ColorFloralWhite
	RunningStatusFgColor = tcell.NewRGBColor(95, 215, 0)  //nolint:mnd
	PausedStatusFgColor  = tcell.NewRGBColor(255, 175, 0) //nolint:mnd
	// dialogs.
	DialogBgColor            = tcell.NewRGBColor(38, 38, 38) //nolint:mnd
	DialogBorderColor        = tcell.ColorMediumSeaGreen
	DialogFgColor            = tcell.ColorFloralWhite
	DialogSubBoxBorderColor  = tcell.ColorDimGray
	ErrorDialogBgColor       = tcell.NewRGBColor(215, 0, 0) //nolint:mnd
	ErrorDialogButtonBgColor = tcell.ColorDarkRed
	// terminal.
	TerminalFgColor     = tcell.ColorFloralWhite
	TerminalBgColor     = tcell.NewRGBColor(5, 5, 5) //nolint:mnd
	TerminalBorderColor = tcell.ColorDimGray
	// table header.
	TableHeaderBgColor = tcell.ColorMediumSeaGreen
	TableHeaderFgColor = tcell.ColorFloralWhite
	// progress bar.
	PrgBgColor       = tcell.ColorDimGray
	PrgBarColor      = tcell.ColorDarkOrange
	PrgBarEmptyColor = tcell.ColorWhite
	PrgBarOKColor    = tcell.ColorGreen
	PrgBarWarnColor  = tcell.ColorOrange
	PrgBarCritColor  = tcell.ColorRed
	// dropdown.
	DropDownUnselected = tcell.StyleDefault.Background(tcell.ColorWhiteSmoke).Foreground(tcell.ColorBlack)
	DropDownSelected   = tcell.StyleDefault.Background(tcell.ColorLightSlateGray).Foreground(tcell.ColorWhite)
	// other primitives.
	InputFieldBgColor = tcell.ColorGray
	ButtonBgColor     = tcell.ColorMediumSeaGreen
)

// GetColorName returns convert tcell color to its name.
func GetColorName(color tcell.Color) string {
	for name, c := range tcell.ColorNames {
		if c == color {
			return name
		}
	}

	return ""
}

// GetColorHex returns convert tcell color to its hex useful for textview primitives.
func GetColorHex(color tcell.Color) string {
	return fmt.Sprintf("#%x", color.Hex())
}
