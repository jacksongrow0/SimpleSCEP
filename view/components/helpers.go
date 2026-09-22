package components

import (
	"strings"

	"github.com/a-h/templ"
)

func mergeAttrs(base string, extra templ.Attributes) templ.Attributes {
	attrs := templ.Attributes{"class": base}
	for key, value := range extra {
		if key == "class" {
			attrs[key] = strings.TrimSpace(base + " " + templ.Classes(value).String())
		} else {
			attrs[key] = value
		}
	}
	return attrs
}

func withDefault(attrs templ.Attributes, key string, value any) templ.Attributes {
	out := make(templ.Attributes, len(attrs)+1)
	for k, v := range attrs {
		out[k] = v
	}
	if _, ok := out[key]; !ok {
		out[key] = value
	}
	return out
}

func buttonClass(props ButtonProps) string {
	base := "btn inline-flex cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-md border text-sm font-medium transition-[filter,box-shadow] duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:pointer-events-none disabled:opacity-50"
	variant := map[ButtonVariant]string{
		ButtonSecondary:   "border-0 bg-secondary text-secondary-foreground shadow-[0_1px_2px_#0003] hover:brightness-[.92]",
		ButtonOutline:     "border-border bg-background text-foreground shadow-[0_1px_2px_#0003] hover:brightness-[.92]",
		ButtonGhost:       "border-transparent bg-transparent text-foreground shadow-none hover:bg-accent",
		ButtonDestructive: "border-0 bg-destructive text-destructive-foreground shadow-[0_1px_2px_#0003] hover:brightness-[.92]",
	}[props.Variant]
	if variant == "" {
		variant = "border-0 bg-primary text-primary-foreground bg-[linear-gradient(180deg,color-mix(in_oklch,var(--color-primary)_90%,white),color-mix(in_oklch,var(--color-primary)_92%,transparent))] shadow-[inset_0_1px_0_color-mix(in_oklch,white_22%,transparent),0_2px_5px_#0004] ring-1 ring-inset ring-white/15 backdrop-blur-[2px] hover:brightness-[.96] hover:shadow-[inset_0_1px_0_color-mix(in_oklch,white_28%,transparent),0_3px_8px_#0005]"
	}
	size := map[ButtonSize]string{
		ButtonSmall: "h-8 px-3 text-xs",
		ButtonIcon:  "size-9 p-0",
	}[props.Size]
	if size == "" {
		size = "h-9 px-4"
	}
	return base + " " + variant + " " + size
}

func cardHeaderClass(responsive bool) string {
	base := "card-head flex flex-col gap-1.5 p-6 [&_h3]:m-0 [&_h3]:text-base [&_h3]:leading-none [&_h3]:font-semibold [&_h3]:tracking-[-.015em] [&_p]:m-0 [&_p]:text-sm [&_p]:text-muted-foreground"
	if responsive {
		return base + " sm:flex-row sm:items-center sm:justify-between"
	}
	return base
}

func segmentClass(name string, active bool) string {
	class := name + " h-7 cursor-pointer rounded-md border-0 bg-transparent px-3 text-sm text-muted-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:pointer-events-none disabled:opacity-50"
	if active {
		class += " active"
	}
	return class
}

func pillClass(tone Tone) string {
	base := "badge inline-flex items-center whitespace-nowrap rounded-md border px-2.5 py-0.5 text-xs font-semibold"
	class := map[Tone]string{
		TonePrimary:     "border-[color-mix(in_oklch,var(--color-primary)_40%,transparent)] text-primary",
		ToneSuccess:     "border-[color-mix(in_oklch,var(--color-success)_40%,transparent)] text-success",
		ToneWarning:     "border-[color-mix(in_oklch,var(--color-warning)_40%,transparent)] text-warning",
		ToneDestructive: "border-[color-mix(in_oklch,var(--color-destructive)_40%,transparent)] text-destructive",
	}[tone]
	if class == "" {
		class = "border-border text-foreground"
	}
	return base + " " + class
}

func inputClass() string {
	return "h-9 w-full rounded-md border border-border bg-transparent px-3 py-1 text-foreground outline-none shadow-[0_1px_2px_#0002] placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50"
}

func emptyStateClass(props EmptyStateProps) string {
	class := "empty m-0 rounded-xl border border-dashed border-border p-10 text-center [&_h3]:mt-4 [&_h3]:mb-0 [&_h3]:text-base [&_h3]:font-medium [&_p]:mx-auto [&_p]:mt-1.5 [&_p]:mb-0 [&_p]:max-w-md [&_p]:text-sm [&_p]:text-muted-foreground [&>.btn]:mt-5 [&>button]:mt-5"
	if props.Compact {
		class += " p-8"
	}
	if props.Muted {
		class += " text-sm text-muted-foreground"
	}
	return class
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
