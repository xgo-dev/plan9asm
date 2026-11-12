package plan9asm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
)

type x86RawNearReturnForm struct {
	nativeWidth bool
	cleanup     uint16
}

// x86RawStaticRead is produced only by a source-local RIP decoder after its
// complete encoding grammar and access width have been validated. It is not a
// mnemonic whitelist, a general pointer contract, or permission to store.
type x86RawStaticRead struct {
	op     Op
	source int
	width  int64
	symbol string
	offset int64
	object []byte
	args   []Operand
}

// Only the normalizer's symbol relocation may change a proved operand. Keep
// an independent snapshot so a caller's edited File cannot authorize a wider
// vector access, a different mask, or an out-of-range proof index.
func rebindX86RawStaticRead(ins *Instr, source int, symbol string) error {
	if source < 0 || source >= len(ins.Args) {
		return fmt.Errorf("%w: invalid raw static read operand", ErrProbeNeedsContext)
	}
	read := ins.x86RIPMemoryRead
	if read.width != 0 {
		if read.source != source || read.op != ins.Op || !reflect.DeepEqual(read.args, ins.Args) {
			return fmt.Errorf("%w: changed raw static read cannot inherit decoder proof", ErrProbeNeedsContext)
		}
		read.args = append([]Operand(nil), read.args...)
		read.args[source].Sym = symbol
		read.symbol = symbol
		ins.x86RIPMemoryRead = read
	}
	ins.Args[source].Sym = symbol
	return nil
}

// C3 and C2 imm16 use the target's native return-PC width. Operand-size
// overrides and other prefixes require their own physical entry contract;
// successful decoding alone does not make them ordinary Go/C returns.
func x86RawNearReturnEncoding(code []byte) x86RawNearReturnForm {
	if len(code) == 1 && code[0] == 0xc3 {
		return x86RawNearReturnForm{nativeWidth: true}
	}
	if len(code) == 3 && code[0] == 0xc2 {
		return x86RawNearReturnForm{nativeWidth: true, cleanup: binary.LittleEndian.Uint16(code[1:])}
	}
	return x86RawNearReturnForm{}
}

func validateX86RawNearReturns(fn Func, file *File, opt Options, bindFrame bool) error {
	hasReturn := false
	for _, ins := range fn.Instrs {
		form := ins.x86RawNearReturn
		if form == nil {
			continue
		}
		hasReturn = true
		if !form.nativeWidth || form.cleanup != 0 {
			return fmt.Errorf("%w: raw near RET needs a physical return-width and caller-stack cleanup contract: %q", ErrProbeNeedsContext, ins.Raw)
		}
	}
	if !hasReturn {
		return nil
	}
	name := fn.Sym
	if opt.ResolveSym != nil {
		name = opt.ResolveSym(name)
	}
	if bindFrame && x86SourceStackBoolCandidate(fn, opt.Sigs[name]) &&
		(fn.x86SourceStack == nil || fn.x86SourceStack.scalarResult == nil) {
		return fmt.Errorf("%w: raw ABI0 bool RET requires its complete typed canonical source-stack proof; %s", ErrProbeNeedsContext, fn.x86SourceStackFailure)
	}
	// The raw instruction bypasses obj6's RET epilogue. A zero-sized,
	// stack-unobserving leaf has the same return-PC location as its caller.
	// All other cases need a native frame/continuation contract, not a guessed
	// epilogue or an inline RET inside LLVM's independently allocated frame.
	if fn.FrameSize != 0 || (!x86RawReturnLeafStackUnobserved(fn) && fn.x86SourceStack == nil) {
		diagnostic := ""
		if fn.x86SourceStackFailure != "" {
			diagnostic = "; " + fn.x86SourceStackFailure
		}
		return fmt.Errorf("%w: raw near RET requires a proved source stack/continuation; Go's TEXT frame epilogue is not encoded in raw bytes%s", ErrProbeNeedsContext, diagnostic)
	}
	if !x86RawReturnMemoryBound(fn, file, opt, bindFrame) {
		return fmt.Errorf("%w: raw near RET needs bounded typed FP/static memory; ordinary pointers have no native return-PC nonalias contract", ErrProbeNeedsContext)
	}
	return nil
}

// This bounded contract does not infer noalias from a Go pointer type or a
// register value. It proves only scalar MOV accesses to bound FP slots or a
// same-file static object, and shared raw decoders' exact source-local reads.
// Other memory forms need their own complete effects and access-range proof.
// In particular, this is not a general store whitelist.
func x86RawReturnMemoryBound(fn Func, file *File, opt Options, bindFrame bool) bool {
	name := fn.Sym
	if opt.ResolveSym != nil {
		name = opt.ResolveSym(name)
	}
	sig := opt.Sigs[name]
	caller := bindFrame && x86CallerNormalizedSourceMatches(fn, sig)
	if fn.x86SourceStack != nil && fn.x86SourceStack.caller != nil && !caller {
		return false
	}
	for _, ins := range fn.Instrs {
		if ins.x86RawMOVSXDNeedsCaller && !caller {
			return false // A native width is not an initialized GP-input proof.
		}
		read := ins.x86RIPMemoryRead
		if read.width != 0 && (opt.Goarch == "386" || !x86RawReturnDecodedReadBound(ins, file)) {
			return false
		}
		op := Op(normalizeInstructionOpcode(ins.Op))
		if _, extension := amd64ScalarExtensionMoveSpecs[op]; extension && !caller && !ins.x86Encoded {
			// A named extension gains new source-frame effects only through
			// actual typed caller input availability. Keep the old separately
			// bound physical/RIP decoder contract distinct from that producer.
			return false
		}
		if _, _, _, memory := x86StringProperties(op); memory {
			return false
		}
		if _, _, memory := x86PortStringProperties(op); memory {
			return false
		}
		if _, memory := amd64ImplicitMaskMoveSpecs[op]; memory || op == "XLAT" {
			return false
		}
		for index, arg := range ins.Args {
			switch arg.Kind {
			case OpMem:
				if caller {
					if !x86CallerMemoryCertified(ins, index) && op != "LEAW" && op != "LEAL" && op != "LEAQ" {
						return false
					}
					// Caller pointers require their own exact access certificate,
					// including physical-SP imports. The old numerical FP proof
					// is not an alternative permission after that certificate is lost.
					continue
				}
				if offset, proved := ins.x86SourceStackFP[index]; bindFrame && fn.x86SourceStack != nil && proved &&
					x86RawReturnFPBound(offset, x86ScalarMoveMemoryBytes(ins, index, opt.Goarch), sig, opt.Goarch) {
					continue // Instruction-local, freshly recomputed physical-SP slot proof.
				}
				if !bindFrame && fn.x86SourceStack != nil && x86RawReturnStackMemory(arg.Mem) && x86ScalarMoveMemoryBytes(ins, index, opt.Goarch) != 0 {
					continue // Pure preparation; final normalization binds the exact slot for lowering.
				}
				// Even a static symbol plus an index is not a bounded object.
				// Address-only register expressions have no dereference, but
				// their later uses still have to satisfy this same contract.
				if op != "LEAW" && op != "LEAL" && op != "LEAQ" {
					return false
				}
			case OpFP:
				if caller {
					if !x86CallerMemoryCertified(ins, index) {
						return false
					}
					continue
				}
				if !bindFrame {
					continue // Pure prepartition normalization retains metadata.
				}
				if fn.x86SourceStack == nil && fn.x86FixedLocal == nil &&
					x86RawReturnMaskParameterReadBound(ins, index, sig, opt.Goarch) {
					continue // Exact logical numeric input bytes, not native frame/pointer permission.
				}
				width := x86ScalarMoveMemoryBytes(ins, index, opt.Goarch)
				if width == 0 || !x86RawReturnFPBound(arg.FPOffset, width, sig, opt.Goarch) {
					return false
				}
			case OpSym:
				if read.width != 0 && read.source == index {
					continue // Exact source and allocated bytes were checked above.
				}
				symbol := strings.TrimSpace(arg.Sym)
				if strings.HasPrefix(symbol, "$") || ins.Op == OpTEXT || ins.Op == OpLABEL {
					continue
				}
				if op == "LEAW" || op == "LEAL" || op == "LEAQ" {
					continue // Address formation, like OpMem LEA; not a read.
				}
				base, offset, static := parseSBRef(symbol)
				if !static {
					continue // Non-memory control operands retain their own checks.
				}
				if !x86RawReturnStaticBound(base, offset, x86ScalarMoveMemoryBytes(ins, index, opt.Goarch), file) {
					return false
				}
			}
		}
	}
	return true
}

func x86RawReturnDecodedReadIdentity(ins Instr) bool {
	read := ins.x86RIPMemoryRead
	if !ins.x86Encoded || !ins.x86RIPLiteral ||
		read.op != ins.Op || read.source < 0 || read.source >= len(ins.Args) ||
		!reflect.DeepEqual(read.args, ins.Args) ||
		read.width <= 0 || read.offset < 0 ||
		read.width > int64(len(read.object)) || read.offset > int64(len(read.object))-read.width {
		return false
	}
	operand := ins.Args[read.source]
	if operand.Kind != OpSym || operand.Sym != read.symbol {
		return false
	}
	if len(ins.x86RIPLiteralData) != 0 &&
		!bytes.Equal(ins.x86RIPLiteralData, read.object[read.offset:read.offset+read.width]) {
		return false
	}
	return true
}

func x86RawReturnDecodedReadBound(ins Instr, file *File) bool {
	if file == nil || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	read := ins.x86RIPMemoryRead
	symbol, offset, ok := parseSBRef(ins.Args[read.source].Sym)
	if !ok || offset != read.offset || !x86RawReturnStaticBound(symbol, offset, read.width, file) {
		return false
	}
	// Re-normalization and bounded module partitioning retain the data. Do
	// not use stale constant-specialization bytes after a caller changes it.
	matched := false
	for _, datum := range file.Data {
		if datum.Sym != symbol {
			continue
		}
		if matched || datum.Off != 0 || datum.Width != int64(len(read.object)) || datum.Addr != "" ||
			!bytes.Equal(datum.Payload, read.object) {
			return false
		}
		matched = true
	}
	return matched
}

func x86RawReturnScalarMoveBytes(op Op) int64 {
	switch op {
	case "MOVB":
		return 1
	case "MOVW":
		return 2
	case "MOVL":
		return 4
	case "MOVQ":
		return 8
	default:
		return 0
	}
}

func x86RawReturnFPBound(offset, width int64, sig FuncSig, goarch string) bool {
	if offset < 0 || width <= 0 {
		return false
	}
	const maxOffset = int64(1<<63 - 1)
	var checked []FrameSlot
	matched := false
	for group, slots := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for _, slot := range slots {
			size := x86RawReturnSlotBytes(slot.Type, goarch)
			if !x86RawReturnSlotMatchesSignature(slot, group, sig) || size == 0 ||
				slot.Offset < 0 || slot.Offset > maxOffset-size {
				return false
			}
			for _, previous := range checked {
				previousSize := x86RawReturnSlotBytes(previous.Type, goarch)
				if slot.Offset < previous.Offset+previousSize && previous.Offset < slot.Offset+size {
					return false
				}
			}
			checked = append(checked, slot)
			// Exact whole-slot moves avoid relying on generic partial FP writes
			// preserving the untouched high bytes. This does not repair those
			// writes elsewhere in the translator.
			matched = matched || slot.Offset == offset && width == size
		}
	}
	return matched
}

func x86RawReturnSlotMatchesSignature(slot FrameSlot, group int, sig FuncSig) bool {
	if slot.Index < 0 {
		return false
	}
	path := frameSlotFields(slot)
	if group == 0 {
		if slot.Index >= len(sig.Args) {
			return false
		}
		typ := sig.Args[slot.Index]
		if len(path) != 0 {
			// Reuse the existing flat literal-aggregate grammar. Nested paths
			// and arrays need a richer validated binding, not a new guessed
			// layout parser inside the native-return proof.
			fields, aggregate := parseLiteralStructFields(typ)
			if !aggregate || len(path) != 1 || path[0] < 0 || path[0] >= len(fields) {
				return false
			}
			typ = fields[path[0]]
		}
		return slot.Type == typ
	}
	// Classic result slots index the already flattened return tuple. Field
	// paths are parameter extraction metadata, not a result-slot binding.
	if sig.Ret == Void || sig.Ret == "" || len(path) != 0 {
		return false
	}
	if fields, aggregate := parseLiteralStructFields(sig.Ret); aggregate {
		return slot.Index < len(fields) && slot.Type == fields[slot.Index]
	}
	return slot.Index == 0 && slot.Type == sig.Ret
}

func x86RawReturnSlotBytes(typ LLVMType, goarch string) int64 {
	return x86FrameScalarBytes(typ, goarch)
}

func x86RawReturnStaticBound(symbol string, offset, width int64, file *File) bool {
	if file == nil || offset < 0 || width <= 0 {
		return false
	}
	var size int64
	for _, object := range file.Globl {
		if object.Sym != symbol {
			continue
		}
		if object.SizeRaw != "" || object.Size < 0 || object.Size > maxDataGlobalSize {
			return false
		}
		if object.Size > size {
			size = object.Size
		}
	}
	// Match the actual DATA allocation consumer. DATA without a GLOBL still
	// creates a same-file byte object; holes are initialized to zero. Reuse
	// its existing checked extent rather than guessing a fixed object size.
	for _, datum := range file.Data {
		if datum.Sym != symbol {
			continue
		}
		end, err := dataStmtEnd(datum)
		if err != nil {
			return false
		}
		if end > size {
			size = end
		}
	}
	return size >= width && offset <= size-width
}

func x86RawReturnLeafStackUnobserved(fn Func) bool {
	hasText := false
	for _, ins := range fn.Instrs {
		if ins.Op == OpTEXT {
			hasText = true
			_, rest := splitOpcode(ins.Raw)
			parts := strings.Split(rest, ",")
			if len(parts) == 3 {
				expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
					if value, ok := goTextFlagValues[name]; ok {
						return value
					}
					return name
				})
				flags, known := parseImmExpr(strings.TrimSpace(expression))
				if !known || flags & ^uint64(2|4|512) != 0 {
					return false
				}
			} else if len(parts) != 2 {
				return false
			}
			continue
		}
		if x86SourceGOperand(ins) {
			// Stack-unobserving does not mean native-context-unobserving.
			// Incoming g is opaque; numerical use or clobber needs the same
			// complete caller and exact saved-identity proof as a framed leaf.
			return false
		}
		op := strings.ToUpper(string(ins.Op))
		if strings.HasPrefix(op, "PUSH") || strings.HasPrefix(op, "POP") ||
			strings.HasPrefix(op, "IRET") || strings.HasPrefix(op, "RETF") {
			return false
		}
		switch Op(op) {
		case OpCALL, "ADJSP", "ENTER", "ENTERL", "ENTERQ", "ENTERW", "LEAVEL", "LEAVEQ", "LEAVEW":
			return false
		case OpRET:
			if len(ins.Args) != 0 {
				return false
			}
		case OpJMP:
			if len(ins.Args) != 1 || (ins.Args[0].Kind != OpIdent && ins.Args[0].Kind != OpLabel) {
				return false
			}
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpFPAddr || (operand.Kind == OpFP && operand.FPOffset < 0) {
				return false
			}
			if operand.Kind == OpReg && x86RawReturnStackRegister(operand.Reg) {
				return false
			}
			if operand.Kind == OpMem && x86RawReturnStackMemory(operand.Mem) {
				return false
			}
			// Go's effective-address immediate is OpSym, not OpMem. Use the
			// same parser and typed register roots as its actual lowering.
			if operand.Kind == OpSym {
				symbol := strings.TrimSpace(operand.Sym)
				if strings.HasPrefix(symbol, "$") {
					address, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(symbol, "$")))
					if ok && x86RawReturnStackMemory(address) {
						return false
					}
				}
			}
		}
	}
	return hasText
}

func x86RawReturnStackRegister(reg Reg) bool {
	root, known := amd64FullRegBase(reg)
	return known && (root == SP || root == BP)
}

func x86RawReturnStackMemory(memory MemRef) bool {
	return x86RawReturnStackRegister(memory.Base) || x86RawReturnStackRegister(memory.Index)
}
