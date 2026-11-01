package plan9asm

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

var x86ResultAUTOLiteral = regexp.MustCompile(`^(.+)\(\s*SP\s*\)$`)

// This replays the original source spelling before observing logical AUTO
// bytes. Its extent is not an allocator size, physical SP, native backing,
// alignment, caller region or address-lifetime certificate.
func x86ResultAUTOExtent(fn Func, arch string) (int, error) {
	return x86ResultAUTOExtentWithPrivateStack(fn, arch, false)
}

func x86ResultAUTOExtentWithPrivateStack(fn Func, arch string, privateStack bool) (int, error) {
	needed := false
	for _, ins := range fn.Instrs {
		if _, _, private := x86ResultPrivateStackXORForm(ins, arch); privateStack && private {
			continue // Only the separately bound, reaching private stack owns this access.
		}
		for _, arg := range ins.Args {
			if _, outgoing := x86ABI0BoolOutgoingOffset(arg, fn.x86BoolCalls); outgoing {
				continue
			}
			if _, static := x86SBMemoryAddressRole(arg, arch); static {
				continue // A 386 named Reg annotation is not a logical AUTO base.
			}
			needed = needed || arg.Kind == OpMem && arg.Mem.Base == SP
		}
	}
	if !needed {
		return 0, nil
	}
	fail := func(reason string) (int, error) {
		return 0, fmt.Errorf("%w: result initialization AUTO: %s", ErrProbeNeedsContext, reason)
	}
	if fn.x86RawReplay != nil {
		if err := fn.x86RawReplay.validate(fn, arch); err != nil {
			return 0, err
		}
	}
	if fn.FrameSize <= 0 || fn.FrameSize > 4096 || len(fn.Instrs) == 0 || len(fn.Instrs) > 8192 || fn.Instrs[0].Op != OpTEXT {
		return fail("requires complete bounded positive original TEXT")
	}
	if fn.x86RawReplay == nil {
		var source strings.Builder
		for _, ins := range fn.Instrs {
			if ins.Raw == "" || len(ins.Raw) > (1<<20)-source.Len()-1 {
				return fail("missing or oversized original literal")
			}
			source.WriteString(ins.Raw)
			source.WriteByte('\n')
		}
		parsed, err := Parse(ArchAMD64, source.String())
		if err != nil || len(parsed.Funcs) != 1 || len(parsed.UnlinkedPrelude) != 0 || len(parsed.Data) != 0 || len(parsed.Globl) != 0 {
			return fail("original source cannot be replayed as one unchanged function")
		}
		original := parsed.Funcs[0]
		instructions, err := x86ResultAUTOReplayInstructions(fn, arch)
		if err != nil {
			return 0, err
		}
		if original.Sym != fn.Sym || original.FrameSize != fn.FrameSize || original.ArgSize != fn.ArgSize ||
			!reflect.DeepEqual(original.Instrs, instructions) {
			return fail("TEXT, operands or source roles changed after parsing")
		}
	}
	for _, ins := range fn.Instrs {
		if _, _, private := x86ResultPrivateStackXORForm(ins, arch); privateStack && private {
			continue
		}
		for index, arg := range ins.Args {
			if _, outgoing := x86ABI0BoolOutgoingOffset(arg, fn.x86BoolCalls); outgoing {
				continue
			}
			if _, static := x86SBMemoryAddressRole(arg, arch); static {
				continue
			}
			if arg.Kind != OpMem || arg.Mem.Base != SP {
				continue
			}
			fields := strings.Fields(ins.Raw)
			if len(fields) < 2 {
				return fail("AUTO operand lacks its original instruction")
			}
			operands := splitTopLevelCSV(strings.TrimSpace(ins.Raw[len(fields[0]):]))
			if len(operands) != len(ins.Args) {
				return fail("AUTO operand ordinal changed")
			}
			literal := x86ResultAUTOLiteral.FindStringSubmatch(operands[index])
			if literal == nil {
				return fail("physical or indexed SP is not logical AUTO")
			}
			offset, named := parseNamedStackConstantOffset(literal[1])
			if !named || offset != arg.Mem.Off || arg.Mem.Sym != "" || arg.Mem.OffRaw != "" ||
				arg.Mem.Index != "" || arg.Mem.IndexExt != "" || arg.Mem.Segment != "" || arg.Mem.Scale != 0 {
				return fail("AUTO role, offset or address is not closed")
			}
			// Reuse the native-width observer's complete typed row. This local
			// width projection is never passed to a translator or source loader;
			// the actual original AUTO role and source remain unchanged above.
			observation := ins
			observation.Args = append([]Operand(nil), ins.Args...)
			observation.Args[index] = Operand{Kind: OpFP}
			width, _, known := X86FPAccessBytes(observation, index, arch)
			if !known || width <= 0 || width > fn.FrameSize || offset < -fn.FrameSize || offset > -width {
				return fail("unknown native width or access outside logical AUTO extent")
			}
		}
	}
	return int(fn.FrameSize), nil
}

func x86ResultAUTOOffset(arg Operand, width int64, extent int) (int, bool) {
	if extent <= 0 || arg.Kind != OpMem || arg.Mem.Base != SP || arg.Mem.Sym != "" || arg.Mem.OffRaw != "" ||
		arg.Mem.Index != "" || arg.Mem.IndexExt != "" || arg.Mem.Segment != "" || arg.Mem.Scale != 0 ||
		width <= 0 || width > int64(extent) || arg.Mem.Off < -int64(extent) || arg.Mem.Off > -width {
		return 0, false
	}
	return extent + int(arg.Mem.Off), true
}
