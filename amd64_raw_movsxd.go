package plan9asm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Opcode 63 is ARPL outside 64-bit mode. In 64-bit mode its default
// operation is a 32-bit copy, 66 selects a 16-bit copy, and effective
// REX.W selects a 32-to-64-bit sign extension. See Intel SDM volume 2B,
// MOVSX/MOVSXD. A 16-bit memory operand remains Context: Intel's r/m16
// and AMD/x86asm's r/m32 descriptions do not establish one read extent.
func decodedX86MOVSXD(inst x86asm.Inst, encoding []byte) (string, error) {
	fail := func(reason string) (string, error) {
		return "", fmt.Errorf("%w: raw MOVSXD %s", ErrProbeNeedsContext, reason)
	}
	if inst.Op != x86asm.MOVSXD || inst.Mode != 64 || inst.Len != len(encoding) {
		return fail("requires its complete 64-bit-mode physical encoding")
	}
	physical, decodeErr := x86asm.Decode(encoding, 64)
	if decodeErr != nil || physical != inst {
		return fail("does not match the independently decoded original bytes")
	}
	// Bind the effective size and register extension to actual bytes, not a
	// public DataSize or a widthless mnemonic. Deliberately leave unregistered
	// ignored/repeated/segment/address prefixes outside this closed grammar.
	index, bits := 0, 32
	if index < len(encoding) && encoding[index] == 0x66 {
		bits = 16
		index++
	}
	if index < len(encoding) && encoding[index]&0xf0 == 0x40 {
		if encoding[index]&8 != 0 {
			bits = 64
		}
		index++
	}
	if index+1 >= len(encoding) || encoding[index] != 0x63 || inst.DataSize != bits || inst.AddrSize != 64 {
		return fail("has an unregistered prefix, opcode or effective size")
	}
	destination, register := inst.Args[0].(x86asm.Reg)
	if !register || decodedX86RegisterBits(destination) != bits || inst.Args[2] != nil || inst.Args[3] != nil {
		return fail("has inconsistent destination or extra operands")
	}
	switch source := inst.Args[1].(type) {
	case x86asm.Reg:
		// The pinned decoder describes every 63 source as r/m32, including
		// 66 register forms. The latter consume only its low sixteen bits.
		if decodedX86RegisterBits(source) != 32 || encoding[index+1]&0xc0 != 0xc0 {
			return fail("has inconsistent register source or ModRM")
		}
		if bits == 16 {
			inst.Args[1] = x86asm.AX + (source - x86asm.EAX)
		}
	case x86asm.Mem:
		if encoding[index+1]&0xc0 == 0xc0 || inst.MemBytes != 4 || source.Segment != 0 {
			return fail("has inconsistent memory source or native read extent")
		}
		if bits == 16 {
			return fail("16-bit memory needs a source-bound vendor read-width contract")
		}
	default:
		return fail("requires a register or memory source")
	}
	if bits == 64 {
		// Go has a width-specific name for the genuine sign extension.
		syntax := x86asm.GoSyntax(inst, 0, nil)
		return "MOVLQSX" + syntax[len("MOVSXD"):], nil
	}
	inst.Op = x86asm.MOV
	if bits == 16 {
		inst.MemBytes = 2
	}
	return x86asm.GoSyntax(inst, 0, nil), nil
}

func x86RawDwordLiteralInput(ins Instr) bool {
	// This is only the source-stack transfer's input-availability check. The
	// final consumer must still bind the exact bytes to the allocated DATA
	// object through x86RawReturnDecodedReadBound; no GP input is inferred.
	read := ins.x86RIPMemoryRead
	if ins.Op != "MOVL" && ins.Op != "MOVLQSX" || read.source != 0 || read.width != 4 || len(ins.Args) != 2 ||
		ins.Args[1].Kind != OpReg || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	result, valid := x86CallerGP(ins.Args[1].Reg)
	return valid && result != SP && result != BP && result == ins.Args[1].Reg
}
