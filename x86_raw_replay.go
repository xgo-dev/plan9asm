package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// x86RawReplaySource retains the exact raw TEXT spelling and the two
// normalization checkpoints needed by the logical AUTO observer. It is
// deliberately private: JSON/source reconstruction cannot manufacture this
// identity or any machine-state permission.
type x86RawReplaySource struct {
	source     string
	goarch     string
	sym        string
	frame      int64
	args       int64
	original   []Instr
	decoded    []Instr
	normalized []Instr
}

func x86HasRawReplayDirectives(fn Func) bool {
	for _, ins := range fn.Instrs {
		if isX86RawDirective(ins) {
			return true
		}
	}
	return false
}

func x86RawReplaySourceText(fn Func) (string, bool) {
	if len(fn.Instrs) == 0 {
		return "", false
	}
	var source strings.Builder
	for _, ins := range fn.Instrs {
		if ins.Raw == "" || len(ins.Raw) > (1<<20)-source.Len()-1 {
			return "", false
		}
		source.WriteString(ins.Raw)
		source.WriteByte('\n')
	}
	return source.String(), true
}

func newX86RawReplaySource(original, decoded Func, goarch string) *x86RawReplaySource {
	if !x86HasRawReplayDirectives(original) {
		return nil
	}
	source, ok := x86RawReplaySourceText(original)
	if !ok {
		return nil
	}
	return &x86RawReplaySource{
		source:   source,
		goarch:   goarch,
		sym:      original.Sym,
		frame:    original.FrameSize,
		args:     original.ArgSize,
		original: cloneX86ReplayInstrs(original.Instrs),
		decoded:  cloneX86ReplayInstrs(decoded.Instrs),
	}
}

func (replay *x86RawReplaySource) withNormalized(fn Func) *x86RawReplaySource {
	if replay == nil {
		return nil
	}
	copy := *replay
	copy.normalized = cloneX86ReplayInstrs(fn.Instrs)
	return &copy
}

func cloneX86ReplayInstrs(input []Instr) []Instr {
	if input == nil {
		return nil
	}
	output := make([]Instr, len(input))
	for index, instruction := range input {
		output[index] = instruction
		output[index].Args = append([]Operand(nil), instruction.Args...)
		if instruction.x86SourceRaw != nil {
			copy := *instruction.x86SourceRaw
			copy.args = append([]Operand(nil), instruction.x86SourceRaw.args...)
			output[index].x86SourceRaw = &copy
		}
		if instruction.x86RawNearReturn != nil {
			copy := *instruction.x86RawNearReturn
			output[index].x86RawNearReturn = &copy
		}
		output[index].x86SourceStackFP = cloneX86ReplayInt64Map(instruction.x86SourceStackFP)
		output[index].x86CallerMemory = cloneX86ReplayCallerMemory(instruction.x86CallerMemory)
		output[index].x86FixedLocalMemory = cloneX86ReplayFixedLocalMemory(instruction.x86FixedLocalMemory)
		output[index].x86RIPLiteralData = append([]byte(nil), instruction.x86RIPLiteralData...)
		output[index].x86RIPAddressData = append([]byte(nil), instruction.x86RIPAddressData...)
		output[index].x86RIPMemoryRead = instruction.x86RIPMemoryRead
		output[index].x86RIPMemoryRead.args = append([]Operand(nil), instruction.x86RIPMemoryRead.args...)
	}
	return output
}

func cloneX86ReplayInt64Map(input map[int]int64) map[int]int64 {
	if input == nil {
		return nil
	}
	output := make(map[int]int64, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneX86ReplayCallerMemory(input map[int]x86CallerMemoryAccess) map[int]x86CallerMemoryAccess {
	if input == nil {
		return nil
	}
	output := make(map[int]x86CallerMemoryAccess, len(input))
	for key, value := range input {
		value.args = append([]Operand(nil), value.args...)
		output[key] = value
	}
	return output
}

func cloneX86ReplayFixedLocalMemory(input map[int]x86FixedLocalAccess) map[int]x86FixedLocalAccess {
	if input == nil {
		return nil
	}
	output := make(map[int]x86FixedLocalAccess, len(input))
	for key, value := range input {
		value.iterationOffsets = append([][8]int64(nil), value.iterationOffsets...)
		output[key] = value
	}
	return output
}

// Repeated normalization may preserve a sealed checkpoint, never replace it
// with edited instructions. Full source replay remains the consumer's check.
func (replay *x86RawReplaySource) validateNormalized(fn Func, arch string) error {
	if replay == nil || x86SourceStackScalarArch(replay.goarch) != x86SourceStackScalarArch(arch) ||
		fn.Sym != replay.sym || fn.FrameSize != replay.frame || fn.ArgSize != replay.args || len(replay.normalized) == 0 {
		return fmt.Errorf("%w: result initialization AUTO: original raw source identity changed", ErrProbeNeedsContext)
	}
	if !reflect.DeepEqual(fn.Instrs, replay.normalized) {
		return fmt.Errorf("%w: result initialization AUTO: normalized raw source identity changed", ErrProbeNeedsContext)
	}
	return nil
}

func (replay *x86RawReplaySource) validate(fn Func, arch string) error {
	if err := replay.validateNormalized(fn, arch); err != nil {
		return err
	}
	parsed, err := Parse(ArchAMD64, replay.source)
	if err != nil || parsed == nil || len(parsed.Funcs) != 1 || len(parsed.UnlinkedPrelude) != 0 || len(parsed.Data) != 0 || len(parsed.Globl) != 0 {
		return fmt.Errorf("%w: result initialization AUTO: original raw source cannot be replayed", ErrProbeNeedsContext)
	}
	original := parsed.Funcs[0]
	if original.Sym != replay.sym || original.FrameSize != replay.frame || original.ArgSize != replay.args || !reflect.DeepEqual(original.Instrs, replay.original) {
		return fmt.Errorf("%w: result initialization AUTO: original raw source identity changed", ErrProbeNeedsContext)
	}
	decoded, err := decodeX86RawDirectives(original, arch)
	if err != nil || !reflect.DeepEqual(decoded.Instrs, replay.decoded) {
		return fmt.Errorf("%w: result initialization AUTO: normalized raw source identity changed", ErrProbeNeedsContext)
	}
	return nil
}
