package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const arm64PrivateTailResultPointerSource = `TEXT ·ReadSlot(SB),516,$0-16
MOVD p+0(FP),R0
MOVD $ret+8(FP),R8
B slotbody<>(SB)
TEXT slotbody<>(SB),516,$0-0
MOVD (R0),R11
MOVD R11,(R8)
RET
`

func TestARM64PrivateTailCannotBorrowCallerFrame(t *testing.T) {
	for _, tail := range []string{"B", "JMP", "RET"} {
		t.Run(tail, func(t *testing.T) {
			arm64PrivateTailCannotBorrowCallerFrame(t, strings.Replace(arm64PrivateTailResultPointerSource, "B slotbody", tail+" slotbody", 1))
		})
	}
}

func arm64PrivateTailCannotBorrowCallerFrame(t *testing.T, source string) {
	t.Helper()
	requireARM64GoABIInternalObject(t, source)
	pkg := mustGoPackage(t, "test/privatetail", "package privatetail\nfunc ReadSlot(p *uint64) uint64\n")
	resolve := func(symbol string) string {
		return strings.TrimPrefix(goStripABISuffix(symbol), "·")
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	entry := *file
	entry.Funcs = file.Funcs[:1]
	// Derive the real entry only. The absent private helper must not acquire
	// another function's FP allocation or untransported R0/R8 input.
	entry.Funcs = append([]Func(nil), entry.Funcs...)
	entry.Funcs[0].Instrs = entry.Funcs[0].Instrs[:1]
	sigs, err := goSigsForAsmFile(pkg, &entry, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := fmt.Sprintf("%#v", file)
	for _, borrowed := range []bool{false, true} {
		for _, api := range []string{"text", "module", "GoModule"} {
			name := api
			if borrowed {
				name += "/explicit_Frame_only"
			}
			t.Run(name, func(t *testing.T) {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				options := Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: resolve, Sigs: map[string]FuncSig{"ReadSlot": sigs["ReadSlot"]}}
				callee := sigs["ReadSlot"]
				callee.Name = "slotbody"
				if borrowed {
					options.Sigs["slotbody"] = callee
				}
				var err error
				switch api {
				case "text":
					_, err = Translate(file, options)
				case "module":
					module, failure := TranslateModuleInContext(ctx, file, options)
					if !module.IsNil() {
						defer module.Dispose()
					}
					err = failure
				case "GoModule":
					opt := GoModuleOptions{GOARCH: "arm64", TargetTriple: options.TargetTriple, ResolveSym: resolve}
					if borrowed {
						opt.ManualSig = func(name string) (FuncSig, bool) { return callee, name == "slotbody" }
					}
					result, failure := translateGoModuleInContext(ctx, pkg, []byte(source), opt)
					if result != nil && !result.Module.IsNil() {
						defer result.Module.Dispose()
					}
					err = failure
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("private tail borrowed an unproved FP result-address/register transport: %v", err)
				}
				if fmt.Sprintf("%#v", file) != snapshot {
					t.Fatal("private-tail rejection mutated the original parsed file")
				}
			})
		}
	}
}

func TestARM64PrivateTailExplicitTransportValidation(t *testing.T) {
	valid := FuncSig{Args: []LLVMType{I64, Ptr}, Ret: I64, ArgRegs: []Reg{"R0", "R8"}}
	for _, test := range []struct {
		name        string
		symbol      string
		sig         FuncSig
		present     bool
		wantContext bool
	}{
		{"explicit", "helper<>(SB)", valid, true, false},
		{"external_unchanged", "external(SB)", FuncSig{}, false, false},
		{"missing", "helper<>(SB)", valid, false, true},
		{"no_registers", "helper<>(SB)", FuncSig{Args: valid.Args, Ret: I64}, true, true},
		{"partial", "helper<>(SB)", FuncSig{Args: valid.Args, ArgRegs: []Reg{"R0"}}, true, true},
		{"unknown_width", "helper<>(SB)", FuncSig{Args: []LLVMType{"[2 x i64]"}, ArgRegs: []Reg{"R0"}}, true, true},
		{"unknown_bank", "helper<>(SB)", FuncSig{Args: []LLVMType{I64}, ArgRegs: []Reg{"R99"}}, true, true},
		{"frame_bank", "helper<>(SB)", FuncSig{Args: []LLVMType{Ptr}, ArgRegs: []Reg{"FP"}}, true, true},
		{"offset", "helper<>+4(SB)", valid, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := arm64ValidatePrivateTailTransport(test.symbol, test.sig, test.present)
			if test.wantContext != errors.Is(err, ErrProbeNeedsContext) || !test.wantContext && err != nil {
				t.Fatalf("private tail transport classification changed: %v", err)
			}
		})
	}
}

func TestARM64PrivateTailExplicitTransportThreeAPIObjects(t *testing.T) {
	const source = `TEXT ·Pass<ABIInternal>(SB),516,$0-16
ADD $9,R0
B customTail<>(SB)
TEXT customTail<>(SB),516,$0-0
ADD $7,R0
RET
`
	requireARM64GoABIInternalObject(t, source)
	pkg := mustGoPackage(t, "test/privatetail", "package privatetail\nfunc Pass(uint64) uint64\n")
	resolve := func(symbol string) string {
		return strings.TrimSuffix(strings.TrimPrefix(goStripABISuffix(symbol), "·"), "<>")
	}
	manual := func(name string) (FuncSig, bool) {
		return FuncSig{Name: "customTail", Args: []LLVMType{I64}, Ret: I64, ArgRegs: []Reg{"R0"}}, name == "customTail"
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, manual)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-unknown-freebsd", "aarch64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(target+"/"+api, func(t *testing.T) {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
				var ir string
				var err error
				switch api {
				case "text":
					ir, err = Translate(file, options)
				case "module":
					module, failure := TranslateModuleInContext(ctx, file, options)
					if !module.IsNil() {
						defer module.Dispose()
						ir = module.String()
					}
					err = failure
				case "GoModule":
					result, failure := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve, ManualSig: manual})
					if result != nil && !result.Module.IsNil() {
						defer result.Module.Dispose()
						ir = result.Module.String()
					}
					err = failure
				}
				if err != nil {
					t.Fatalf("existing explicit private register contract was rejected: %v", err)
				}
				compileLLVMToObject(t, llc, target, "private-tail.ll", "private-tail.o", ir)
			})
		}
	}
}
