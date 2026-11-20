package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type x86EnqueueForm struct {
	native      string
	source      Operand
	destination Operand
	addressBits int
	wordBits    int
}

// Both instructions use m512 and a read-only GP address. REX.W and 66 do
// not select that register's width; the address-size attribute does.
func x86EnqueueProperties(op Op, ins Instr, arch string) (x86EnqueueForm, bool, error) {
	name := strings.ToUpper(string(op))
	base := strings.SplitN(name, ".", 2)[0]
	if _, known := x86EnqueueOps[base]; !known {
		return x86EnqueueForm{}, false, nil
	}
	fail := func() (x86EnqueueForm, bool, error) {
		return x86EnqueueForm{}, true, fmt.Errorf("%s %s requires an exact memory/GP enqueue address form: %q", arch, op, ins.Raw)
	}
	if name != base || arch != "amd64" && arch != "386" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) || len(ins.Args) != 2 {
		return fail()
	}
	form := x86EnqueueForm{native: strings.ToLower(base), source: ins.Args[0], destination: ins.Args[1], wordBits: 64}
	if arch == "386" {
		form.wordBits = 32
	}
	form.addressBits = ins.x86AddressBits
	if form.addressBits == 0 {
		form.addressBits = form.wordBits
	}
	if form.addressBits != form.wordBits && form.addressBits != form.wordBits/2 ||
		!reflect.DeepEqual(form.destination, Operand{Kind: OpReg, Reg: form.destination.Reg}) ||
		!isX86YrlRegisterForArch(form.destination.Reg, arch) {
		return fail()
	}
	source := form.source
	switch source.Kind {
	case OpMem:
		memory := source.Mem
		if !reflect.DeepEqual(source, Operand{Kind: OpMem, Mem: memory}) ||
			memory.OffRaw != "" || memory.IndexExt != "" || !x86MemoryRegistersValidForArch(memory, arch) ||
			!x86EnqueueAddressEncoding(memory, form.addressBits) ||
			memory.Segment != "" && memory.Segment != FS && memory.Segment != GS ||
			memory.Index == SP || memory.Index == "" && memory.Scale != 0 ||
			memory.Index != "" && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
			return fail()
		}
	case OpSym:
		if source.Sym == "" || !reflect.DeepEqual(source, Operand{Kind: OpSym, Sym: source.Sym}) {
			return fail()
		}
	case OpFP:
		if !reflect.DeepEqual(source, Operand{Kind: OpFP, FPName: source.FPName, FPOffset: source.FPOffset}) {
			return fail()
		}
	default:
		return fail()
	}
	return form, true, nil
}

func x86EnqueueAddressEncoding(memory MemRef, bits int) bool {
	if bits == 16 {
		if memory.Off < -1<<15 || memory.Off > 1<<16-1 {
			return false
		}
		if memory.Index != "" {
			return (memory.Base == BX || memory.Base == BP) &&
				(memory.Index == SI || memory.Index == DI) && memory.Scale == 1
		}
		return memory.Base == "" || memory.Base == BX || memory.Base == BP || memory.Base == SI || memory.Base == DI
	}
	maximum := int64(1<<31 - 1)
	if bits == 32 {
		maximum = 1<<32 - 1
	}
	return memory.Off >= -1<<31 && memory.Off <= maximum
}

// This exact ordinary-address source boundary is shared by the paired native
// continuation and its storage post-consumers, never by declaration queries.
func x86EnqueueSourceForm(ins Instr, arch string) (x86EnqueueForm, bool) {
	form, known, err := x86EnqueueProperties(ins.Op, ins, arch)
	if !known || err != nil || form.addressBits != form.wordBits || form.source.Kind != OpMem ||
		form.source.Mem.Segment != "" || ins.x86Encoded || ins.x86RawNearReturn != nil ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 || ins.x86NumericalRead != nil {
		return form, false
	}
	origin := ins.x86SourceRaw
	if origin == nil {
		return form, ins.x86AddressBits == 0
	}
	return form, ins.x86AddressBits == form.wordBits &&
		strings.EqualFold(string(origin.op), string(ins.Op)) && reflect.DeepEqual(origin.args, ins.Args)
}

// Only the accepted transfer establishes inputs. This predicate preserves
// existing DF/ID/private storage; it creates no memory or entry permission.
func x86EnqueuePreservesStorage(ins Instr) bool {
	arch := "amd64"
	if ins.x86AddressBits == 32 {
		arch = "386"
	}
	_, valid := x86EnqueueSourceForm(ins, arch)
	return valid
}

func x86LoweredEnqueueResultStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	_, known, err := x86EnqueueProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	form, valid := x86EnqueueSourceForm(ins, arch)
	if !valid || !x86ResultIncomingPointerAddressIdentity(form.source, state, arch) {
		return false, true
	}
	device := Operand{Kind: OpMem, Mem: MemRef{Base: form.destination.Reg}}
	if !x86ResultIncomingPointerAddressIdentity(device, state, arch) {
		return false, true
	}
	// The original hardware opcode either faults or returns retry status. No
	// successful submission, PASID, privilege, pointee or future read follows.
	state.flags = x86ByteFlagsAll
	return true, true
}
