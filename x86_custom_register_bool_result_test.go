package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CustomRegisterBoolAPI(t *testing.T, body string, sig FuncSig, api string) (string, error) {
	t.Helper()
	source := "TEXT ·custom(SB),4,$0-0\n" + body + "\nRET\n"
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		// ManualSig selects a logical custom register assignment. The actual
		// Go type is retained, but this is not a physical Go caller/entry proof.
		goTypes := map[LLVMType]string{Ptr: "*uint64", I1: "bool", I8: "uint8", I16: "uint16", I32: "uint32"}
		var params []string
		for index, typ := range sig.Args {
			goType, found := goTypes[typ]
			if !found {
				t.Fatal("fixture needs an actual matching scalar Go declaration", typ)
			}
			params = append(params, fmt.Sprintf("a%d %s", index, goType))
		}
		pkg := mustGoPackage(t, "custom", "package custom\nfunc custom("+strings.Join(params, ",")+") bool\n")
		module, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve,
			ManualSig: func(name string) (FuncSig, bool) { return sig, name == "custom" },
		})
		if module != nil && !module.Module.IsNil() {
			defer module.Module.Dispose()
			return module.Module.String(), err
		}
		return "", err
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: map[string]FuncSig{"custom": sig}}
	if api == "text" {
		return Translate(file, options)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

func TestX86Mode32CustomRegisterBoolPairedEffectHasNoNewAuthority(t *testing.T) {
	for _, op := range []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHG8B"} {
		t.Run(op, func(t *testing.T) {
			body := op + " CX,(SI)"
			if op == "CMPXCHG8B" {
				body = op + " (SI)"
			}
			file, err := Parse(ArchAMD64, "TEXT ·custom(SB),4,$0-0\n"+body+"\nSETEQ AX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			before := x86DirectTailSnapshot(file)
			observed := false
			transfer := func(ordinal int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
				if accepted, known := x86LoweredCompareExchangeResultStep(ins, state, owned, arch); known {
					if !state.shapeOnly {
						observed = true
						wantFlags := uint8(x86ByteFlagsAll)
						if op == "CMPXCHG8B" {
							wantFlags = x86ByteFlagZF
						}
						if !accepted || state.gp[0] != 15 || state.gp[2] != 15 || state.flags != wantFlags ||
							state.canonicalGP[0] != 0 || len(state.fp) != 0 || len(state.auto) != 0 || len(state.canonicalFP) != 0 || len(state.resultAddressSlots) != 0 {
							t.Fatal("paired operation invented canonical/high/FP/AUTO/alias facts", state)
						}
					}
					return accepted
				}
				return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
			}
			if err := checkX86CustomRegisterBoolResultInitialization(file.Funcs[0], x86CustomRegisterBoolSignature(), "386", transfer); err != nil || !observed {
				t.Fatal("actual declared custom entry and full typed effect not reached", err)
			}
			if !reflect.DeepEqual(before, file) {
				t.Fatal("proof rewrote the complete original source")
			}
		})
	}
	for _, input := range []int{1, 2, 3, 4} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("narrow-implicit-%d/%s", input, api), func(t *testing.T) {
				sig := x86CustomRegisterBoolSignature()
				sig.Args[input] = I8
				if ir, err := x86CustomRegisterBoolAPI(t, "CMPXCHG8B (SI)\nSETEQ AX", sig, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("an implicit CAS input borrowed undeclared upper bytes", input, err)
				}
			})
		}
	}
	// The ordinary declaration-only checker must not borrow the private
	// logical register role or the paired lowering continuation's native read.
	file, err := Parse(ArchAMD64, "TEXT ·custom(SB),4,$0-0\nCMPXCHG8B (SI)\nSETEQ AX\nRET\n")
	if err != nil || !errors.Is(CheckX86ABI0ResultInitialization(file.Funcs[0], x86CustomRegisterBoolSignature(), "386"), ErrProbeNeedsContext) {
		t.Fatal("public ABI0 observer acquired custom register/memory authority", err)
	}
}

func x86CustomRegisterBoolSignature() FuncSig {
	return FuncSig{Name: "custom", Args: []LLVMType{Ptr, I32, I32, I32, I32}, Ret: I1, ArgRegs: []Reg{SI, AX, DX, BX, CX}}
}

func TestX86Mode32CustomRegisterBoolCanonicalThreeAPIs(t *testing.T) {
	for _, condition := range amd64RegisterBoolConditions {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(condition+"/"+api, func(t *testing.T) {
				ir, err := x86CustomRegisterBoolAPI(t, "CMPL AX,BX\n"+condition+" AX", x86CustomRegisterBoolSignature(), api)
				if err != nil || ir == "" {
					t.Fatal("complete registered SETcc canonical transport", err)
				}
			})
		}
	}
	for name, row := range map[string]struct {
		body string
		good bool
	}{
		"atomic-original":       {"LOCK\nCMPXCHG8B (SI)\nSETEQ AX", true},
		"zero":                  {"MOVB $0,AX", true},
		"one":                   {"MOVB $1,AX", true},
		"comparison":            {"CMPL AX,BX\nSETNE AX", true},
		"raw-restored":          {"MOVB $3,AX\nTESTB AX,AX\nSETNE AX", true},
		"all-edges":             {"CMPL AX,BX\nJE yes\nMOVB $0,AX\nJMP end\nyes:\nMOVB $1,AX\nend:", true},
		"two":                   {"MOVB $2,AX", false},
		"three":                 {"MOVB $3,AX", false},
		"ff":                    {"MOVB $255,AX", false},
		"integer-entry":         {"MOVB AX,AX", false},
		"unknown-flags":         {"SETEQ AX", false},
		"unknown-upper":         {"MOVB $1,AX\nCMPL DI,BX\nSETEQ AX", false},
		"one-raw-edge":          {"CMPL AX,BX\nJE yes\nMOVB $3,AX\nJMP end\nyes:\nMOVB $1,AX\nend:", false},
		"frame-not-owned":       {"MOVB $1,ret+0(FP)", false},
		"call-no-contract":      {"MOVB $1,AX\nCALL other(SB)", false},
		"cas-not-canonical":     {"CMPXCHG8B (SI)", false},
		"pair-no-carry":         {"CMPXCHG8B (SI)\nSETCS AX", false},
		"pair-preserves-carry":  {"CMPL AX,BX\nCMPXCHG8B (SI)\nSETCS AX", true},
		"register-cas":          {"CMPXCHGL CX,BX\nSETEQ AX", true},
		"implicit-unknown":      {"MOVB $1,AX\nCMPXCHG8B (DI)\nSETEQ AX", false},
		"pointer-overwritten":   {"MOVL $0,SI\nCMPXCHG8B (SI)\nSETEQ AX", false},
		"pointer-index":         {"CMPXCHG8B (SI)(DI*2)\nSETEQ AX", false},
		"numeric-pointer-mixed": {"CMPXCHGL SI,BX\nSETEQ AX", false},
		"detached-lock":         {"LOCK\nNOP\nCMPXCHG8B (SI)\nSETEQ AX", false},
		"split-lock":            {"LOCK\nnext:\nCMPXCHG8B (SI)\nSETEQ AX", false},
		"cas-slot-not-owned":    {"CMPXCHG8B ret+0(FP)\nSETEQ AX", false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				ir, err := x86CustomRegisterBoolAPI(t, row.body, x86CustomRegisterBoolSignature(), api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("custom register canonical result/ABI0 separation", row.good, len(ir), err)
				}
			})
		}
	}
}

func TestX86Mode32CustomRegisterBoolRoleAndByteViews(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·custom(SB),4,$0-0\nMOVB $1,AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	fn, sig := file.Funcs[0], x86CustomRegisterBoolSignature()
	transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
		return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
	}
	if err := checkX86CustomRegisterBoolResultInitialization(fn, sig, "386", transfer); err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("ordinary-BP-assignment/"+api, func(t *testing.T) {
			ordinary := x86CustomRegisterBoolSignature()
			ordinary.ArgRegs[4] = BP
			if _, err := x86CustomRegisterBoolAPI(t, "CMPL AX,BP\nSETEQ AX", ordinary, api); err != nil {
				t.Fatal("explicit mode32 BP bytes were mistaken for a native frame", err)
			}
		})
	}
	for name, mutate := range map[string]func(*Func, *FuncSig){
		"missing-assignment":   func(_ *Func, sig *FuncSig) { sig.ArgRegs = sig.ArgRegs[:4] },
		"extra-assignment":     func(_ *Func, sig *FuncSig) { sig.ArgRegs = append(sig.ArgRegs, DI) },
		"duplicate-register":   func(_ *Func, sig *FuncSig) { sig.ArgRegs[4] = AX },
		"byte-assignment":      func(_ *Func, sig *FuncSig) { sig.ArgRegs[4] = CL },
		"stack-register":       func(_ *Func, sig *FuncSig) { sig.ArgRegs[4] = SP },
		"mode-invalid-byte-BP": func(_ *Func, sig *FuncSig) { sig.ArgRegs[4] = BPB },
		"out-of-mode":          func(_ *Func, sig *FuncSig) { sig.ArgRegs[4] = "R8" },
		"wide-input":           func(_ *Func, sig *FuncSig) { sig.Args[4] = I64 },
		"float-input":          func(_ *Func, sig *FuncSig) { sig.Args[4] = LLVMType("float") },
		"aggregate-input":      func(_ *Func, sig *FuncSig) { sig.Args[4] = LLVMType("{ i32, i32 }") },
		"FP-parameter":         func(_ *Func, sig *FuncSig) { sig.Frame.Params = []FrameSlot{{Type: I32, Field: -1}} },
		"FP-result":            func(_ *Func, sig *FuncSig) { sig.Frame.Results = []FrameSlot{{Type: I1, Field: -1}} },
		"frame":                func(fn *Func, _ *FuncSig) { fn.FrameSize = 4 },
		"argsize":              func(fn *Func, _ *FuncSig) { fn.ArgSize = 1 },
		"internal-selector":    func(fn *Func, _ *FuncSig) { fn.Sym += "<ABIInternal>" },
		"raw-source":           func(fn *Func, _ *FuncSig) { fn.Instrs[1].x86Encoded = true },
		"address-override":     func(fn *Func, _ *FuncSig) { fn.Instrs[1].x86AddressBits = 16 },
		"segment":              func(fn *Func, _ *FuncSig) { fn.Instrs[1].x86SegmentPrefix = 0x64 },
		"wasm":                 func(_ *Func, sig *FuncSig) { sig.WASMNative = true },
		"borrowed-tail":        func(_ *Func, sig *FuncSig) { sig.x86BorrowedBoolTail = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed, signature := x86DirectTailSnapshot(file).Funcs[0], sig
			signature.ArgRegs = append([]Reg(nil), sig.ArgRegs...)
			signature.Args = append([]LLVMType(nil), sig.Args...)
			mutate(&changed, &signature)
			before := x86DirectTailSnapshot(&File{Arch: ArchAMD64, Funcs: []Func{changed}}).Funcs[0]
			if err := checkX86CustomRegisterBoolResultInitialization(changed, signature, "386", transfer); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("different role obtained register-result permission", err)
			}
			if !reflect.DeepEqual(before, changed) {
				t.Fatal("result proof rewrote the original source")
			}
		})
	}
	for _, typ := range []LLVMType{I1, I8, I16} {
		for _, api := range []string{"text", "module", "Go"} {
			for _, byteRead := range []bool{false, true} {
				t.Run(fmt.Sprintf("input-%s/low-only=%t/%s", typ, byteRead, api), func(t *testing.T) {
					signature := x86CustomRegisterBoolSignature()
					signature.Args[1] = typ
					body := "CMPL AX,BX\nSETEQ AX"
					if byteRead {
						body = "TESTB AX,AX\nSETEQ AX"
					}
					ir, err := x86CustomRegisterBoolAPI(t, body, signature, api)
					if byteRead && (err != nil || ir == "") || !byteRead && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("narrow logical input initialized unspecified upper GP bytes", byteRead, err)
					}
				})
			}
		}
	}
	for _, typ := range []LLVMType{I1, I8} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("incoming-canonical-%s/%s", typ, api), func(t *testing.T) {
				signature := x86CustomRegisterBoolSignature()
				signature.Args[1] = typ
				ir, err := x86CustomRegisterBoolAPI(t, "MOVB AX,AX", signature, api)
				if typ == I1 && (err != nil || ir == "") || typ == I8 && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("initialized byte was confused with actual I1 input", typ, err)
				}
			})
		}
	}
}

func TestX86Mode32CustomRegisterBoolCompareExchangeEffects(t *testing.T) {
	for _, op := range []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHG8B"} {
		for _, locked := range []bool{false, true} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/locked=%t/%s", op, locked, api), func(t *testing.T) {
					body := op + " CX,(SI)"
					if op == "CMPXCHG8B" {
						body = op + " (SI)"
					}
					if locked {
						body = "LOCK\n" + body
					}
					ir, err := x86CustomRegisterBoolAPI(t, body+"\nSETEQ AX", x86CustomRegisterBoolSignature(), api)
					want := strings.ToLower(op)
					if locked {
						want = "lock; " + want
					}
					if err != nil || !strings.Contains(ir, "asm sideeffect \""+want) || !strings.Contains(ir, "=*m") || strings.Contains(ir, " cmpxchg ptr ") {
						t.Fatal("complete original native memory effect/faults not retained", err)
					}
				})
			}
		}
	}
}
