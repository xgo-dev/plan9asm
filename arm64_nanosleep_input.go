package plan9asm

import (
	"reflect"
	"strings"
)

// The Linux A64 nanosleep request is two native int64 fields. With R1=NULL
// the kernel copies these 16 input bytes and never writes a user remainder,
// including on interruption. This does not grant an arbitrary syscall, native
// entry, output buffer, return/NZCV observation or a caller-frame address.
// See Linux v6.12 include/uapi/linux/time_types.h and kernel/time/hrtimer.c.
const arm64NanosleepRequestBytes = int64(16)

type arm64NanosleepInput struct {
	form arm64SyscallForm
	span arm64PrivateDataSpan
}

type arm64NanosleepInputProof struct {
	identity *arm64NanosleepInputProof
	owner    *arm64Ctx
	source   Func
	sig      FuncSig
	target   string
	inputs   map[[2]int]arm64NanosleepInput
	sealed   map[[2]int]arm64NanosleepInput
	required bool // a diagnostic obligation, never a permission
}

func arm64NanosleepCloneSource(fn Func) Func {
	fn.Instrs = append([]Instr(nil), fn.Instrs...)
	for i := range fn.Instrs {
		fn.Instrs[i].Args = append([]Operand(nil), fn.Instrs[i].Args...)
		for j := range fn.Instrs[i].Args {
			fn.Instrs[i].Args[j].RegList = append([]Reg(nil), fn.Instrs[i].Args[j].RegList...)
		}
	}
	return fn
}

func arm64NanosleepCloneSignature(sig FuncSig) FuncSig {
	sig.Args = append([]LLVMType(nil), sig.Args...)
	sig.ArgRegs = append([]Reg(nil), sig.ArgRegs...)
	sig.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
	sig.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
	for i := range sig.Frame.Params {
		sig.Frame.Params[i].Fields = append([]int(nil), sig.Frame.Params[i].Fields...)
	}
	for i := range sig.Frame.Results {
		sig.Frame.Results[i].Fields = append([]int(nil), sig.Frame.Results[i].Fields...)
	}
	return sig
}

func (proof *arm64NanosleepInputProof) matchesSource(fn Func, sig FuncSig, target string) bool {
	return proof != nil && proof.identity == proof && proof.target == target &&
		reflect.DeepEqual(proof.source, fn) && reflect.DeepEqual(proof.sig, sig) &&
		reflect.DeepEqual(proof.inputs, proof.sealed)
}

// Reuse the existing bounded private-data CFG interpreter, store grammar,
// disjunctive joins and convergence budget. The collector is not a certificate:
// publication occurs only after every original component closes successfully.
func arm64NanosleepInputForSource(fn Func, transport *arm64PrivateFrameTransport, target string) (*arm64NanosleepInputProof, bool) {
	hasTrap, required := false, false
	for _, original := range fn.Instrs {
		ins := arm64ControlDecode(original)
		hasTrap = hasTrap || arm64ControlOp(ins) == "SVC"
		if form, known := parseARM64GPRegisterMove(ins); known &&
			ins.Args[1].Reg == "R8" && form.source.Kind == OpImm && form.source.Imm == 101 {
			// An exact literal declaration creates only a denial obligation.
			// It cannot publish a certificate, restore undefined inputs or
			// bypass the complete CFG, declaration and kernel target checks.
			required = true
		}
	}
	required = required && hasTrap
	if transport == nil || !arm64SourceGoFrame(fn).present || fn.FrameSize < 0 ||
		strings.HasSuffix(fn.Sym, "<ABIInternal>") || transport.entry.Ret != Void ||
		transport.entry.ARM64GoRegisterABI != nil || transport.entry.ARM64ClosureABI != nil ||
		len(transport.entry.ArgRegs) != 0 || len(transport.entry.Frame.Results) != 0 ||
		fn.arm64PrivateSourceAdded != 0 || fn.arm64PrivateCallSource != nil {
		return nil, required
	}
	for _, typ := range transport.entry.Args {
		if typ != I1 && typ != I8 && typ != I16 && typ != I32 && typ != I64 {
			return nil, required
		}
	}
	for _, original := range fn.Instrs {
		op := arm64ControlOp(arm64ControlDecode(original))
		if op == "CALL" || op == "BL" || op == "BLR" {
			return nil, required
		}
	}
	if !hasTrap {
		return nil, false
	}
	proof := &arm64NanosleepInputProof{source: arm64NanosleepCloneSource(fn),
		sig: arm64NanosleepCloneSignature(transport.entry), target: target,
		inputs: make(map[[2]int]arm64NanosleepInput), required: required}
	query := *transport // value-only query; no caller/source or resource owner
	query.nanosleep = proof
	if _, err := arm64PrivateDataProofDetails(fn, &query); err != nil || len(proof.inputs) == 0 {
		return nil, proof.required
	}
	proof.identity = proof
	proof.sealed = make(map[[2]int]arm64NanosleepInput, len(proof.inputs))
	for point, input := range proof.inputs {
		proof.sealed[point] = input
	}
	return proof, proof.required
}

func arm64NanosleepExactNumber(value arm64PrivateDataValue, number uint64) bool {
	return !value.frame && value.interval.low == number && value.interval.high == number
}

// An unsealed collector and a sealed replay use the same operand roles. The
// sealed replay may not modify its inventory or acquire a new initialized span.
func (proof *arm64NanosleepInputProof) consume(state *arm64PrivateDataState, fn Func, point [2]int, ins Instr) bool {
	if proof == nil || !reflect.DeepEqual(proof.source, fn) {
		return false
	}
	if proof.identity == nil && arm64NanosleepExactNumber(state.value("R8"), 101) {
		proof.required = true
	}
	form, err := parseARM64SyscallForm(proof.target, ins)
	if err != nil || form.os != arm64SyscallLinux || form.number != "R8" || form.trap != 0 ||
		len(ins.Args) == 1 && ins.Args[0].Imm != 0 ||
		!arm64NanosleepExactNumber(state.value("R8"), 101) ||
		!arm64NanosleepExactNumber(state.value("R1"), 0) {
		return false
	}
	address := state.value("R0")
	if !address.frame || address.mixed || address.interval.low != address.interval.high ||
		address.interval.low < 8 || fn.FrameSize > arm64MaxLocalStackSpan ||
		address.interval.high > uint64(fn.FrameSize+8-arm64NanosleepRequestBytes) {
		return false
	}
	input := arm64NanosleepInput{form: form, span: arm64PrivateDataSpan{
		low: int64(address.interval.low), end: int64(address.interval.low) + arm64NanosleepRequestBytes}}
	if proof.identity == nil {
		for offset := input.span.low; offset < input.span.end; offset++ {
			if !state.initialized[offset] {
				return false
			}
		}
		if previous, present := proof.inputs[point]; present && previous != input {
			return false
		}
		proof.inputs[point] = input
	} else if proof.identity != proof || proof.inputs[point] != input {
		return false
	}
	// Linux normal return overwrites only R0. Do not wash R1, other GP aliases,
	// global escaped addresses, continuation cells or the NZCV bank clean.
	state.assign("R0", arm64PrivateDataUnknown)
	return true
}

func arm64NanosleepNumericalInstruction(ins Instr) bool {
	op := arm64ControlOp(ins)
	if op == OpTEXT || op == OpLABEL || op == "NOP" || op == "CMP" || op == "CMPW" {
		return true
	}
	if _, known := arm64PrivateDataMemory(ins); known {
		return true
	}
	if _, known := parseARM64GPRegisterMove(ins); known {
		return true
	}
	if _, handled, err := parseARM64GPDataForm(op, ins); handled {
		return err == nil
	}
	if _, handled, err := parseARM64GPImmediateForm(op, ins); handled {
		return err == nil
	}
	if _, handled, err := parseARM64RegisterAddressForm(op, ins); handled {
		return err == nil
	}
	// FP reads use the existing exact numerical declaration and lowerer. This
	// does not authorize a memory pointer, symbol or hidden native state.
	if op == "MOVD" || op == "MOVW" || op == "MOVWU" || op == "MOVH" || op == "MOVHU" || op == "MOVB" || op == "MOVBU" {
		return len(ins.Args) == 2 && ins.Args[0].Kind == OpFP && ins.Args[1].Kind == OpReg
	}
	return false
}

func (c *arm64Ctx) nanosleepInputAt(point [2]int) (arm64NanosleepInput, bool) {
	proof, original := c.nanosleepInput, c.nanosleepOriginal
	if proof == nil || proof.owner != c || !proof.matchesSource(c.normalizedSource, c.sig, c.targetTriple) ||
		original == nil || original.owner != c || !original.matchesSource(c.nanosleepOriginalSource, c.sig, c.targetTriple) {
		return arm64NanosleepInput{}, false
	}
	input, present := proof.inputs[point]
	if !present || !reflect.DeepEqual(c.blocks, arm64SplitBlocks(c.normalizedSource)) {
		return arm64NanosleepInput{}, false
	}
	return input, true
}
