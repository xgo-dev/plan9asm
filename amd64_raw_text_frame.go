package plan9asm

import (
	"fmt"
	"strings"
)

// Naked emission preserves the raw directive bytes, not obj6's additional
// Go frame, wrapper or stack-split prologue. Keep this source boundary explicit
// even when the body's bytes are data rather than decodable instructions.
func validateX86AddressSensitiveRawText(fn Func, goarch string) error {
	if fn.FrameSize != 0 || fn.ArgSize != 0 {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs its source Go frame/argument transport contract", ErrProbeNeedsContext)
	}
	if len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs an actual source TEXT header", ErrProbeNeedsContext)
	}
	_, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) != 2 && len(parts) != 3 {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs a resolved source header", ErrProbeNeedsContext)
	}
	if !strings.HasPrefix(strings.TrimSpace(parts[len(parts)-1]), "$") {
		return fmt.Errorf("%w: address-sensitive raw TEXT needs a known source frame", ErrProbeNeedsContext)
	}
	frame, args, err := parseTEXTFrame(parts)
	if err != nil || frame != fn.FrameSize || args != fn.ArgSize {
		return fmt.Errorf("%w: address-sensitive raw TEXT source frame differs from its retained metadata", ErrProbeNeedsContext)
	}
	var flags uint64
	if len(parts) == 3 {
		expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
			if value, known := goTextFlagValues[name]; known {
				return value
			}
			return name
		})
		var known bool
		flags, known = parseImmExpr(strings.TrimSpace(expression))
		if !known {
			return fmt.Errorf("%w: address-sensitive raw TEXT flags need actual Go source context", ErrProbeNeedsContext)
		}
	}
	if flags & ^uint64(2|4|512) != 0 {
		return fmt.Errorf("%w: address-sensitive raw TEXT requires unmodeled Go prologue/entry flags", ErrProbeNeedsContext)
	}
	if goarch == "386" && flags&4 == 0 {
		return fmt.Errorf("%w: address-sensitive 386 raw TEXT cannot omit Go's stack-split prologue", ErrProbeNeedsContext)
	}
	return nil
}
