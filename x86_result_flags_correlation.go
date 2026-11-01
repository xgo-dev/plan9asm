package plan9asm

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Zero is a defined bit, 1..32 identify an unknown entry FLAGS bit, and 255
// is an untracked expression. XOR by a defined value preserves dependency;
// XOR of identical tracked dependencies cancels it. No numerical value is
// inferred, and two untracked expressions can never cancel each other.
const x86FlagsUntracked = uint8(255)

type x86ResultFlagsCorrelation struct {
	flags  [32]uint8
	bytes  [][8]uint8 // Same descending-byte order as the private value stack.
	popped [32]uint8  // Only the immediately following instruction may consume it.
}

func x86FlagsXOROrigin(left, right uint8) uint8 {
	if left == 0 {
		return right
	}
	if right == 0 {
		return left
	}
	if left == right && left != x86FlagsUntracked {
		return 0
	}
	return x86FlagsUntracked
}

func x86ResultPrivateStackXORForm(ins Instr, arch string) (x86LockScalarRMWForm, int, bool) {
	if arch != "386" || !x86ResultNamedPredicateInstruction(ins) {
		return x86LockScalarRMWForm{}, 0, false
	}
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || form.spec.stem != "XOR" {
		return form, 0, false
	}
	for index, arg := range []Operand{form.source, form.destination} {
		if arg.Kind != OpMem || arg.Mem.Base != SP {
			continue
		}
		m := arg.Mem
		if m.Sym != "" || m.OffRaw != "" || m.Index != "" || m.IndexExt != "" ||
			m.Scale != 0 || m.Segment != "" || m.Off < 0 || m.Off > int64(x86ResultValueStackLimit(arch)) {
			return form, 0, false
		}
		// Parsing intentionally erases AUTO names. Do not mistake saved+0(SP)
		// for an offset within the private PUSH storage.
		fields := strings.Fields(ins.Raw)
		if len(fields) < 2 {
			return form, 0, false
		}
		args := splitTopLevelCSV(strings.TrimSpace(ins.Raw[len(fields[0]):]))
		if len(args) != 2 {
			return form, 0, false
		}
		if strings.TrimSpace(args[index]) == "(SP)" {
			return form, index, m.Off == 0
		}
		literal := x86ResultAUTOLiteral.FindStringSubmatch(args[index])
		if literal == nil {
			return form, 0, false
		}
		offset, err := strconv.ParseInt(strings.TrimSpace(literal[1]), 0, 64)
		return form, index, err == nil && offset == m.Off
	}
	return form, 0, false
}

// Called only by the paired lowerer. Source replay and the shared CFG bind
// the actual PUSH-owned byte storage; a declaration-only query gains nothing.
func x86ResultPrivateFlagsSource(fn Func, arch string) (*x86ResultValueStack, error) {
	if arch != "386" {
		return nil, nil
	}
	needed := false
	for _, ins := range fn.Instrs {
		_, _, valid := x86ResultPrivateStackXORForm(ins, arch)
		needed = needed || valid
	}
	if !needed {
		return nil, nil
	}
	fail := func() (*x86ResultValueStack, error) {
		return nil, fmt.Errorf("%w: private FLAGS correlation requires unchanged ordinary mode32 source", ErrProbeNeedsContext)
	}
	if len(fn.Instrs) == 0 || len(fn.Instrs) > 4096 || fn.Instrs[0].Op != OpTEXT ||
		strings.Contains(fn.Sym, "<") || len(fn.X86RawText) != 0 || fn.x86RawReplay != nil ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil ||
		fn.x86ContinuationFlow != nil || fn.x86BoolCalls != nil {
		return fail()
	}
	var source strings.Builder
	for _, ins := range fn.Instrs {
		if !x86ResultNamedPredicateInstruction(ins) || ins.Raw == "" || len(ins.Raw) > (1<<20)-source.Len()-1 {
			return fail()
		}
		source.WriteString(ins.Raw)
		source.WriteByte('\n')
	}
	parsed, err := Parse(ArchAMD64, source.String())
	if err != nil || len(parsed.Funcs) != 1 || len(parsed.UnlinkedPrelude) != 0 || len(parsed.Data) != 0 || len(parsed.Globl) != 0 {
		return fail()
	}
	original := parsed.Funcs[0]
	instructions, err := x86ResultAUTOReplayInstructions(fn, arch)
	if err != nil || original.Sym != fn.Sym || original.FrameSize != fn.FrameSize || original.ArgSize != fn.ArgSize ||
		!reflect.DeepEqual(original.Instrs, instructions) {
		return fail()
	}
	correlation := new(x86ResultFlagsCorrelation)
	for bit := range correlation.flags {
		correlation.flags[bit] = uint8(bit + 1)
	}
	return &x86ResultValueStack{correlation: correlation}, nil
}

func x86ResultFlagsStackPush(stack *x86ResultValueStack, known uint64, storage int, flags bool) {
	if stack.correlation == nil {
		return
	}
	for index := storage - 1; index >= 0; index-- {
		var origins [8]uint8
		for bit := range origins {
			position := index*8 + bit
			if known&(uint64(1)<<uint(position)) == 0 {
				origins[bit] = x86FlagsUntracked
				if flags && position < 32 {
					origins[bit] = stack.correlation.flags[position]
				}
			}
		}
		stack.correlation.bytes = append(stack.correlation.bytes, origins)
	}
}

func x86ResultFlagsStackPop(stack *x86ResultValueStack, storage int) [32]uint8 {
	var origins [32]uint8
	if stack.correlation == nil {
		return origins
	}
	for bit := range origins {
		origins[bit] = x86FlagsUntracked
	}
	bytes := stack.correlation.bytes
	for index := 0; index < storage; index++ {
		copy(origins[index*8:], bytes[len(bytes)-1-index][:])
	}
	stack.correlation.bytes = bytes[:len(bytes)-storage]
	return origins
}

func x86ResultPrivateStackXORStep(ins Instr, popped x86ResultPoppedWord, poppedOrigins [32]uint8,
	state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, memory, known := x86ResultPrivateStackXORForm(ins, arch)
	if !known {
		return false, false
	}
	stack := state.valueStack
	if stack == nil || stack.correlation == nil || stack.invalid {
		return false, true
	}
	width := form.spec.bits / 8
	args := [2]Operand{form.source, form.destination}
	offset := int(args[memory].Mem.Off)
	if !state.shapeOnly && (offset+width > len(stack.bytes) || len(stack.correlation.bytes) != len(stack.bytes)) {
		return false, true
	}
	var inputs [2][32]uint8
	for index, arg := range args {
		if state.shapeOnly || arg.Kind == OpImm {
			continue
		}
		for bit := 0; bit < width*8; bit++ {
			if index == memory {
				inputs[index][bit] = stack.correlation.bytes[len(stack.bytes)-1-offset-bit/8][bit%8]
				continue
			}
			root, mask, valid := x86ResultGP(arg.Reg, int64(width), arch)
			if arg.Kind != OpReg || !valid || x86LogicalSourceFrameRegister(arg.Reg, arch) {
				return false, true
			}
			shift := 0
			if width == 1 && mask == 2 {
				shift = 8
			}
			if state.gp[root]&(1<<uint((bit+shift)/8)) == 0 {
				inputs[index][bit] = x86FlagsUntracked
				if popped.valid && popped.register == root {
					inputs[index][bit] = poppedOrigins[bit+shift]
				}
			}
		}
	}
	allKnown := true
	if memory == 1 && !state.shapeOnly {
		stack.revokePointerCells(len(stack.bytes)-offset-width, len(stack.bytes)-offset,
			int(x86ResultPointerWord(arch)))
	}
	for b := 0; b < width; b++ {
		var origins [8]uint8
		var bits uint8
		for bit := range origins {
			origins[bit] = x86FlagsXOROrigin(inputs[0][b*8+bit], inputs[1][b*8+bit])
			if origins[bit] == 0 {
				bits |= 1 << uint(bit)
			}
		}
		allKnown = allKnown && bits == 255
		if memory == 1 && !state.shapeOnly {
			position := len(stack.bytes) - 1 - offset - b
			stack.correlation.bytes[position] = origins
			stack.bytes[position] = bits
			if stack.refinable != nil {
				stack.refinable[position] &= bits
			}
		}
	}
	if memory == 0 {
		// A numeric GP consumer may observe only a fully canceled value.
		// Unknown copies stay confined to the private storage transport.
		if !allKnown || !x86ResultStore(form.destination, int64(width), state, owned, resultOffset, arch) {
			return false, true
		}
	}
	state.flags = x86ByteFlagCF | x86ByteFlagOF
	if allKnown {
		state.flags |= x86ByteFlagPF | x86ByteFlagZF | x86ByteFlagSF
	}
	return true, true
}

func x86ResultFlagsCorrelationAfter(ins Instr, state *x86ResultState, arch string) {
	if state.valueStack == nil || state.valueStack.correlation == nil || state.shapeOnly {
		return
	}
	if _, stack, _ := x86StackWidthProperties(ins, arch); stack {
		return // The checked byte copy already retained the exact relation.
	}
	writes := uint8(x86ByteFlagsAll)
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		writes = effect.flagsDefined | effect.flagsKilled
	} else if ins.Op == OpJMP || isAMD64ConditionalBranch(ins.Op) || ins.Op == "NOP" || x86RawReturnScalarMoveBytes(ins.Op) != 0 {
		writes = 0
	}
	for index, bit := range []int{0, 2, 4, 6, 7, 11} {
		if state.flags&(1<<uint(index)) != 0 {
			state.valueStack.correlation.flags[bit] = 0
		} else if writes&(1<<uint(index)) != 0 {
			state.valueStack.correlation.flags[bit] = x86FlagsUntracked
		}
	}
	correlation := state.valueStack.correlation
	if state.direction != x86ResultDirectionUnknown {
		correlation.flags[10] = 0
	} else if correlation.flags[10] == 0 || ins.Op == OpCALL {
		correlation.flags[10] = x86FlagsUntracked
	}
	if state.valueStack.id {
		correlation.flags[21] = 0
	} else if correlation.flags[21] == 0 || ins.Op == OpCALL {
		correlation.flags[21] = x86FlagsUntracked
	}
}

func x86ResultIntersectFlagsCorrelation(left, right *x86ResultValueStack) {
	if left.correlation == nil {
		return
	}
	if left.invalid || right == nil || right.correlation == nil ||
		len(left.correlation.bytes) != len(right.correlation.bytes) {
		left.correlation = nil
		return
	}
	merge := func(left, right []uint8) {
		for index := range left {
			if left[index] != right[index] {
				left[index] = x86FlagsUntracked
			}
		}
	}
	merge(left.correlation.flags[:], right.correlation.flags[:])
	merge(left.correlation.popped[:], right.correlation.popped[:])
	for index := range left.correlation.bytes {
		merge(left.correlation.bytes[index][:], right.correlation.bytes[index][:])
	}
}
