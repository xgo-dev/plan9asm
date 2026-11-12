package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// A zero-argument manual signature uses the existing logical AX return
// transport. It is not an assertion about Go ABI0, ABIInternal or native entry.
func TestX86Mode32LogicalScalarReturnMustBeInitialized(t *testing.T) {
	for _, row := range []struct {
		typ   LLVMType
		store string
	}{
		{I8, "MOVB"}, {I16, "MOVW"}, {I32, "MOVL"},
	} {
		for _, sample := range []struct {
			name, value string
			pass        bool
		}{
			{"initialized", row.store + " $7,AX\n", true},
			{"missing", "", false},
			{"wrong-register", row.store + " $7,BX\n", false},
			{"one-path-only", "MOVL $1,DX\nCMPL DX,$0\nJE done\n" + row.store + " $7,AX\ndone:\n", false},
		} {
			// A private bit-preserving FLAGS copy does not expose its unknown
			// bits. It also cannot manufacture missing AX result bytes.
			source := "TEXT ·logical(SB),4,$0-0\nPUSHFL\nPOPL CX\n" + sample.value + "RET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := FuncSig{Name: "logical", Ret: row.typ}
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				t.Run(fmt.Sprintf("%s/%s/%s", row.typ, sample.name, api), func(t *testing.T) {
					options := Options{
						Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
						Sigs:       map[string]FuncSig{"logical": sig},
						ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
					}
					ir, err := x86PackedFloatStorageAPI(api, file, options)
					if sample.pass && (err != nil || ir == "") ||
						!sample.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("logical AX result proof disagrees with actual reaching bytes", sample.pass, err)
					}
				})
			}
			if !errors.Is(CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "386"), ErrProbeNeedsContext) {
				t.Fatal("manual logical return invented a Go ABI0 declaration")
			}
		}
	}
}

func TestX86Mode32LogicalScalarReturnRoleBoundaries(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·logical(SB),4,$0-0\nMOVL $7,AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
		return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
	}
	for name, mutate := range map[string]func(*Func, *FuncSig){
		"wide-result":      func(_ *Func, sig *FuncSig) { sig.Ret = I64 },
		"pointer-result":   func(_ *Func, sig *FuncSig) { sig.Ret = Ptr },
		"bool-result":      func(_ *Func, sig *FuncSig) { sig.Ret = I1 },
		"incoming-value":   func(_ *Func, sig *FuncSig) { sig.Args = []LLVMType{I32} },
		"register-input":   func(_ *Func, sig *FuncSig) { sig.ArgRegs = []Reg{AX} },
		"FP-result":        func(_ *Func, sig *FuncSig) { sig.Frame.Results = []FrameSlot{{Type: I32}} },
		"FP-parameter":     func(_ *Func, sig *FuncSig) { sig.Frame.Params = []FrameSlot{{Type: I32}} },
		"frame":            func(fn *Func, _ *FuncSig) { fn.FrameSize = 4 },
		"argsize":          func(fn *Func, _ *FuncSig) { fn.ArgSize = 4 },
		"internal-entry":   func(fn *Func, _ *FuncSig) { fn.Sym += "<ABIInternal>" },
		"raw-source":       func(fn *Func, _ *FuncSig) { fn.Instrs[1].x86Encoded = true },
		"address-override": func(fn *Func, _ *FuncSig) { fn.Instrs[1].x86AddressBits = 16 },
		"segment":          func(fn *Func, _ *FuncSig) { fn.Instrs[1].x86SegmentPrefix = 0x64 },
		"wasm-entry":       func(_ *Func, sig *FuncSig) { sig.WASMNative = true },
	} {
		t.Run(name, func(t *testing.T) {
			fn := x86DirectTailSnapshot(file).Funcs[0]
			sig := FuncSig{Name: "logical", Ret: I32}
			mutate(&fn, &sig)
			before := x86DirectTailSnapshot(&File{Arch: ArchAMD64, Funcs: []Func{fn}}).Funcs[0]
			if err := checkX86LogicalRegisterResultInitialization(fn, sig, "386", transfer, false, false); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("logical return supplied an unrelated entry role", err)
			}
			if !reflect.DeepEqual(before, fn) {
				t.Fatal("logical return proof changed its original source")
			}
		})
	}
}

func TestX86Mode32LogicalScalarReturnLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("logical scalar result objects require LLVM22 llc")
	}
	for _, row := range []struct {
		typ LLVMType
		op  string
	}{{I8, "MOVB"}, {I16, "MOVW"}, {I32, "MOVL"}} {
		source := "TEXT ·logical(SB),4,$0-0\n" + row.op + " $7,AX\nRET\n"
		requireX86GoAssemblerResult(t, "386", source, true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				t.Run(fmt.Sprintf("%s/%s/%s", row.typ, triple, api), func(t *testing.T) {
					options := Options{
						Goarch: "386", TargetTriple: triple,
						Sigs:       map[string]FuncSig{"logical": {Name: "logical", Ret: row.typ}},
						ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
					}
					ir, err := x86PackedFloatStorageAPI(api, file, options)
					if err != nil || ir == "" {
						t.Fatal("initialized logical AX result", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
					}
				})
			}
		}
	}
}

func TestX86Mode32LogicalScalarReturnCannotBypassProof(t *testing.T) {
	for _, body := range []string{"", "MOVL $7,BX\n", "MOVB $7,AX\n", "MOVW $7,AX\n"} {
		file, err := Parse(ArchAMD64, "TEXT ·logical(SB),4,$0-0\n"+body+"RET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
			t.Run(fmt.Sprintf("%q/%s", body, api), func(t *testing.T) {
				options := Options{
					Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
					Sigs:       map[string]FuncSig{"logical": {Name: "logical", Ret: I32}},
					ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
				}
				ir, err := x86PackedFloatStorageAPI(api, file, options)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("missing AX bytes escaped through a cost-only proof selector", err)
				}
			})
		}
	}
}
