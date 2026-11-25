package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// ABI0EffectReport summarizes the result of static ABI0 effect checking on an
// x86/amd64 function using the declarative OpTable.
type ABI0EffectReport struct {
	InitializedGP  map[asm.Reg]bool
	InitializedVec map[int]bool
	WrittenResults map[int64]bool
}

// CheckABI0ResultInit verifies that a Go ABI0 x86/amd64 function obeys basic
// register initialization, private stack-pointer confinement, and raw-directive
// provenance rules before emitting code.
//
// Driven directly by OpTable so adding new instructions automatically participates
// in effect tracking without per-opcode boilerplate.
func CheckABI0ResultInit(fn asm.Func, sig asm.FuncSig, goarch string) (*ABI0EffectReport, error) {
	return CheckABI0ResultInitWithSigs(fn, sig, goarch, nil, nil)
}

// CheckABI0ResultInitWithSigs extends CheckABI0ResultInit with callee ABI0
// signatures so outgoing CALLs can verify outgoing parameter slots and mark
// callee ABI0 result stack slots initialized.
func CheckABI0ResultInitWithSigs(fn asm.Func, sig asm.FuncSig, goarch string, resolve func(string) string, sigs map[string]asm.FuncSig) (*ABI0EffectReport, error) {
	instrs, err := DecodeRawDirectives(fn.Instrs, goarch)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", asm.ErrProbeNeedsContext, err)
	}

	gpInit := map[asm.Reg]bool{}
	gpTaintedSP := map[asm.Reg]bool{} // true if reg holds private SP address
	vecInit := map[int]bool{}
	vecFromRaw := map[int]bool{}
	writtenResults := map[int64]bool{}
	localSlotsInit := map[int64]bool{}

	// Explicit ArgRegs (register-ABI helpers) start initialized.
	for _, r := range sig.ArgRegs {
		gpInit[canonicalGP(r)] = true
	}

	resultOffsets := map[int64]bool{}
	for _, s := range sig.Frame.Results {
		resultOffsets[s.Offset] = true
	}
	paramOffsets := map[int64]bool{}
	for _, s := range sig.Frame.Params {
		paramOffsets[s.Offset] = true
	}

	checkRead := func(op asm.Operand, raw string) error {
		switch op.Kind {
		case asm.OpReg:
			if op.Reg == asm.SP {
				return nil
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				if !vecInit[idx] {
					return fmt.Errorf("%w: %s reads uninitialized vector register %s", asm.ErrProbeNeedsContext, raw, op.Reg)
				}
				return nil
			}
			r := canonicalGP(op.Reg)
			if !gpInit[r] {
				return fmt.Errorf("%w: %s reads uninitialized register %s", asm.ErrProbeNeedsContext, raw, op.Reg)
			}
		case asm.OpMem:
			if op.Mem.Base == asm.SP && op.Mem.Off >= 0 {
				if !localSlotsInit[op.Mem.Off] {
					return fmt.Errorf("%w: %s reads uninitialized stack slot %d(SP)", asm.ErrProbeNeedsContext, raw, op.Mem.Off)
				}
				return nil
			}
			if op.Mem.Base != "" && op.Mem.Base != asm.SP && op.Mem.Base != asm.PC {
				if !gpInit[canonicalGP(op.Mem.Base)] {
					return fmt.Errorf("%w: %s reads uninitialized base register %s", asm.ErrProbeNeedsContext, raw, op.Mem.Base)
				}
			}
			if op.Mem.Index != "" && !gpInit[canonicalGP(op.Mem.Index)] {
				return fmt.Errorf("%w: %s reads uninitialized index register %s", asm.ErrProbeNeedsContext, raw, op.Mem.Index)
			}
		}
		return nil
	}

	markWrite := func(op asm.Operand, fromRaw bool, taintSP bool) error {
		switch op.Kind {
		case asm.OpReg:
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				vecInit[idx] = true
				vecFromRaw[idx] = fromRaw
				return nil
			}
			r := canonicalGP(op.Reg)
			gpInit[r] = true
			gpTaintedSP[r] = taintSP
		case asm.OpFP:
			if resultOffsets[op.FPOffset] {
				if taintSP {
					return fmt.Errorf("%w: private frame address escapes to result slot +%d(FP)", asm.ErrProbeNeedsContext, op.FPOffset)
				}
				if fromRaw {
					return fmt.Errorf("%w: raw-decoded value written to result slot +%d(FP)", asm.ErrProbeNeedsContext, op.FPOffset)
				}
				writtenResults[op.FPOffset] = true
			}
		case asm.OpMem:
			if op.Mem.Base == asm.SP && op.Mem.Off >= 0 {
				if taintSP {
					return fmt.Errorf("%w: private frame address escapes to stack slot %d(SP)", asm.ErrProbeNeedsContext, op.Mem.Off)
				}
				localSlotsInit[op.Mem.Off] = true
			}
		}
		return nil
	}

	for _, ins := range instrs {
		op := asm.Op(strings.ToUpper(string(ins.Op)))
		if op == asm.OpTEXT || op == asm.OpLABEL || op == "NOP" || op == "PCALIGN" ||
			op == "NO_LOCAL_POINTERS" || op == "FUNCDATA" || op == "PCDATA" || op == "GO_ARGS" {
			continue
		}
		if op == asm.OpRET {
			// Verify every declared ABI0 result slot was initialized cleanly.
			for off := range resultOffsets {
				if !writtenResults[off] {
					return nil, fmt.Errorf("%w: RET with uninitialized result slot +%d(FP)", asm.ErrProbeNeedsContext, off)
				}
			}
			continue
		}
		if op == "CALL" {
			// Outgoing ABI0 call: if callee ABI0 frame layout is known, verify
			// its incoming stack parameters and mark its stack result slots initialized.
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym && resolve != nil && sigs != nil {
				raw := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
				callee := resolve(raw)
				if csig, ok := sigs[callee]; ok && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) > 0 {
					for _, ps := range csig.Frame.Params {
						if !localSlotsInit[ps.Offset] {
							return nil, fmt.Errorf("%w: %s reads uninitialized outgoing ABI0 arg slot %d(SP)", asm.ErrProbeNeedsContext, ins.Raw, ps.Offset)
						}
					}
					for _, rs := range csig.Frame.Results {
						localSlotsInit[rs.Offset] = true
					}
				}
			}
			gpInit[asm.AX] = true
			gpTaintedSP[asm.AX] = false
			continue
		}

		// Any raw-decoded instruction cannot supply proven ABI0 result initialization
		// on its own until explicitly validated against the lowering contract.
		if ins.DecodedFromRaw {
			return nil, fmt.Errorf("%w: decoded raw directive %q requires verified lowering provenance for ABI0 result initialization", asm.ErrProbeNeedsContext, ins.Raw)
		}

		spec, ok := OpTable.Lookup(op)
		if !ok {
			// Conservative fallback for instructions not yet in OpTable:
			// treat all non-last operands as reads and the last operand as write.
			spec = asm.OpSpec{Op: op, Effect: asm.EffectWriteOnly}
		}

		// Self-XOR idiom (XORL AX, AX / PXOR X0, X0 / VPXOR X0, X0, X0) initializes dst to zero.
		if isZeroingIdiom(op, ins.Args) {
			if err := markWrite(ins.Args[len(ins.Args)-1], false, false); err != nil {
				return nil, err
			}
			continue
		}

		// Check source operands.
		n := len(ins.Args)
		readEnd := n - 1
		if spec.Effect == asm.EffectReadOnly || spec.Effect == asm.EffectReadWrite {
			readEnd = n
		}
		srcTaintSP := false
		srcFromRaw := false
		for i := 0; i < readEnd && i < n; i++ {
			a := ins.Args[i]
			if a.Kind == asm.OpReg && a.Reg == asm.SP {
				srcTaintSP = true
			}
			if a.Kind == asm.OpReg && gpTaintedSP[canonicalGP(a.Reg)] {
				srcTaintSP = true
			}
			if a.Kind == asm.OpReg {
				if idx, ok := anyVecRegIndex(a.Reg); ok && vecFromRaw[idx] {
					srcFromRaw = true
				}
			}
			if a.Kind == asm.OpMem && a.Mem.Base == asm.SP && (op == "LEAQ" || op == "LEAL") {
				srcTaintSP = true
			}
			// FP parameter reads are always initialized by the Go caller.
			if a.Kind == asm.OpFP && paramOffsets[a.FPOffset] {
				continue
			}
			if err := checkRead(a, ins.Raw); err != nil {
				return nil, err
			}
		}

		if n > 0 && spec.Effect != asm.EffectReadOnly && spec.Effect != asm.EffectNone {
			if err := markWrite(ins.Args[n-1], srcFromRaw, srcTaintSP); err != nil {
				return nil, err
			}
		}
	}

	return &ABI0EffectReport{
		InitializedGP:  gpInit,
		InitializedVec: vecInit,
		WrittenResults: writtenResults,
	}, nil
}

func isZeroingIdiom(op asm.Op, args []asm.Operand) bool {
	switch op {
	case "XORB", "XORW", "XORL", "XORQ", "SUBB", "SUBW", "SUBL", "SUBQ",
		"PXOR", "XORPS", "XORPD":
		return len(args) == 2 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[0].Reg == args[1].Reg
	case "VPXOR", "VPXORD", "VPXORQ", "VXORPS", "VXORPD":
		return len(args) == 3 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[0].Reg == args[1].Reg
	default:
		return false
	}
}

func canonicalGP(r asm.Reg) asm.Reg {
	switch asm.Reg(strings.ToUpper(string(r))) {
	case asm.AL, asm.AH, asm.AX:
		return asm.AX
	case asm.BL, asm.BH, asm.BX:
		return asm.BX
	case asm.CL, asm.CH, asm.CX:
		return asm.CX
	case asm.DL, asm.DH, asm.DX:
		return asm.DX
	default:
		return asm.Reg(strings.ToUpper(string(r)))
	}
}

func anyVecRegIndex(r asm.Reg) (int, bool) {
	if idx, ok := amd64ParseXReg(r); ok {
		return idx, true
	}
	if idx, ok := amd64ParseYReg(r); ok {
		return idx, true
	}
	if idx, ok := amd64ParseZReg(r); ok {
		return idx, true
	}
	return 0, false
}
