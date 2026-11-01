package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These internal linear consumers predate CFG lowering. Their native opcodes
// still need a real target architecture; a fabricated mixed-architecture
// fixture can pass LLVM's IR verifier but cannot produce a machine object.
func TestTranslateLinearNativeOpcodeArchitectureBoundaries(t *testing.T) {
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchARM64, ArchWASM} {
		for _, op := range []Op{OpCPUID, OpXGETBV, OpMRS} {
			for _, api := range []string{"text", "module"} {
				t.Run(fmt.Sprintf("%s/%s/%s", arch, op, api), func(t *testing.T) {
					ins := Instr{Op: op, Raw: string(op)}
					if op == OpMRS {
						ins.Args = []Operand{{Kind: OpIdent, Ident: "TPIDR_EL0"}, {Kind: OpReg, Reg: "R0"}}
						ins.Raw = "MRS TPIDR_EL0, R0"
					}
					fn := Func{Sym: "native", Instrs: []Instr{ins, {Op: OpRET, Raw: "RET"}}}
					sig := FuncSig{Name: "native", Ret: Void}
					var err error
					var ir string
					if api == "text" {
						var output strings.Builder
						err = translateFuncLinear(&output, arch, fn, sig, false)
						ir = output.String()
					} else {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						mod := ctx.NewModule("native-architecture")
						defer mod.Dispose()
						err = translateFuncLinearModule(mod, arch, fn, sig)
						ir = mod.String()
					}
					valid := op == OpMRS && arch == ArchARM64 || op != OpMRS && arch == ArchAMD64
					if (err == nil) != valid {
						t.Fatalf("native architecture acceptance = %v, valid=%t", err, valid)
					}
					if !valid && strings.Contains(ir, "asm sideeffect") {
						t.Fatal("foreign architecture emitted a native instruction before rejection")
					}
				})
			}
		}
	}
}

func TestTranslateLinearNativeOpcodesProduceTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct {
		arch   Arch
		triple string
	}{
		{ArchAMD64, "x86_64-apple-darwin"},
		{ArchAMD64, "x86_64-unknown-linux-gnu"},
		{ArchAMD64, "x86_64-pc-windows-msvc"},
		{ArchAMD64, "i386-unknown-linux-gnu"},
		{ArchAMD64, "i686-pc-windows-msvc"},
		{ArchARM64, "aarch64-apple-darwin"},
		{ArchARM64, "aarch64-unknown-linux-gnu"},
		{ArchARM64, "aarch64-pc-windows-msvc"},
	} {
		for _, api := range []string{"text", "module"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				instrs := []Instr{{Op: OpCPUID, Raw: "CPUID"}, {Op: OpXGETBV, Raw: "XGETBV"}}
				if target.arch == ArchARM64 {
					instrs = []Instr{{
						Op: OpMRS, Raw: "MRS TPIDR_EL0, R0",
						Args: []Operand{{Kind: OpIdent, Ident: "TPIDR_EL0"}, {Kind: OpReg, Reg: "R0"}},
					}}
				}
				instrs = append(instrs, Instr{Op: OpRET, Raw: "RET"})
				fn := Func{Sym: "native", Instrs: instrs}
				sig := FuncSig{Name: "native", Ret: Void}
				var ir string
				if api == "text" {
					var output strings.Builder
					if err := translateFuncLinear(&output, target.arch, fn, sig, false); err != nil {
						t.Fatal(err)
					}
					ir = output.String()
				} else {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					mod := ctx.NewModule("native-object")
					defer mod.Dispose()
					if err := translateFuncLinearModule(mod, target.arch, fn, sig); err != nil {
						t.Fatal(err)
					}
					ir = mod.String()
				}
				compileLLVMToObject(t, llc, target.triple, "native.ll", "native.o", ir)
				compileLLVMToObject(t, llc, target.triple, "native-opt.ll", "native-opt.o", x86UndefinedTrapOptimizedIR(t, ir))
			})
		}
	}
}
