package plan9asm

import "strings"

// Only the actual retained TEXT may distinguish unspecified args from zero.
// This does not infer a layout: the ordinary typed declaration and every FP
// access still need their complete independent bounds and input checks.
func x86TEXTArgumentsUnspecified(fn Func) bool {
	if fn.ArgSize != 0 || len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return false
	}
	op, rest := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if !strings.EqualFold(op, "TEXT") || len(parts) < 2 || len(parts) > 3 ||
		!strings.HasPrefix(strings.TrimSpace(parts[len(parts)-1]), "$") {
		return false
	}
	frame, err := parseTEXTFrameSpec(parts)
	return err == nil && !frame.argsSpecified && frame.frameSize == fn.FrameSize
}

// The native listing must retain the original TEXT's specified/unspecified
// distinction. An omitted size obtains its layout only from the Go declaration.
func goAMD64FrameArgumentsMatch(fn Func, native int64) bool {
	if x86TEXTArgumentsUnspecified(fn) {
		return native == -0x80000000 // objabi.ArgsSizeUnknown
	}
	return native == fn.ArgSize
}
