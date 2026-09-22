package components

import "github.com/a-h/templ"

type ButtonVariant string
type ButtonSize string
type Tone string

const (
	ButtonPrimary     ButtonVariant = "primary"
	ButtonSecondary   ButtonVariant = "secondary"
	ButtonOutline     ButtonVariant = "outline"
	ButtonGhost       ButtonVariant = "ghost"
	ButtonDestructive ButtonVariant = "destructive"

	ButtonSmall  ButtonSize = "small"
	ButtonMedium ButtonSize = "medium"
	ButtonIcon   ButtonSize = "icon"

	ToneNeutral     Tone = "neutral"
	TonePrimary     Tone = "primary"
	ToneSuccess     Tone = "success"
	ToneWarning     Tone = "warning"
	ToneDestructive Tone = "destructive"
)

type ButtonProps struct {
	Variant ButtonVariant
	Size    ButtonSize
	Attrs   templ.Attributes
}

type ButtonLinkProps struct {
	Href string
	ButtonProps
}

type CardProps struct {
	Attrs templ.Attributes
}

type CardHeaderProps struct {
	Title, Description, Icon string
	Responsive               bool
	Attrs                    templ.Attributes
}

type FieldProps struct {
	Label, Hint string
	Attrs       templ.Attributes
}

type InputProps struct {
	Icon  string
	Attrs templ.Attributes
}

type TooltipPosition string

const (
	TooltipAbove TooltipPosition = "above"
	TooltipBelow TooltipPosition = "below"
	TooltipLeft  TooltipPosition = "left"
	TooltipRight TooltipPosition = "right"
)

type TooltipProps struct {
	ID, Content string
	Position    TooltipPosition
	Attrs       templ.Attributes
}

type DialogProps struct {
	Attrs templ.Attributes
}

type DialogHeaderProps struct {
	Title, Description string
	Attrs              templ.Attributes
}

type PillProps struct {
	Tone  Tone
	Attrs templ.Attributes
}

type SegmentProps struct {
	Active bool
	Attrs  templ.Attributes
}

type EmptyStateProps struct {
	Icon, Title, Description string
	Compact, Muted           bool
	Attrs                    templ.Attributes
}

type MetricProps struct {
	Label, Value, Meta, Icon string
	Attrs                    templ.Attributes
}
