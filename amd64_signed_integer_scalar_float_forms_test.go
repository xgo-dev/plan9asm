package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86SignedIntegerFloatRows(arch string) []string {
	var rows []string
	for _, bits := range []string{"L", "Q"} {
		for _, lane := range []string{"SS", "SD"} {
			if arch != "386" || bits == "L" {
				for _, source := range []string{"AX", "8(BX)", "(BX)(SI*4)"} {
					rows = append(rows, "CVTS"+bits+"2"+lane+" "+source+",X1")
				}
			}
			op := "VCVTSI2" + lane + bits
			for _, source := range []string{"AX", "8(BX)", "(BX)(SI*4)"} {
				rows = append(rows, op+" "+source+",X0,X1")
			}
			if lane != "SD" || bits != "L" {
				for _, suffix := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
					rows = append(rows, op+"."+suffix+" AX,X0,X1")
				}
			}
		}
	}
	return rows
}

func TestX86SignedIntegerScalarFloatCompleteGoTablesAndObjects(t *testing.T) {
	if len(x86SignedIntegerFloatSpecs) != 8 {
		t.Fatal("incomplete signed family")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + strings.Join(x86SignedIntegerFloatRows(target.arch), "\n") + "\nRET\n"
			if target.arch == "amd64" {
				source = strings.Replace(source, "\nRET", "\nVCVTSI2SSL R15,X29,X30\nVCVTSI2SDQ.RU_SAE R8,X31,X31\nCVTSL2SS AX,X15\nRET", 1)
			}
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"f": {Ret: Void}}}
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				var ir string
				var err error
				if api == "Translate" {
					ir, err = Translate(file, opt)
				} else {
					ir, err = func() (string, error) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						var module llvm.Module
						var moduleErr error
						if api == "TranslateModule" {
							module, moduleErr = TranslateModule(file, opt)
						} else {
							module, moduleErr = TranslateModuleInContext(ctx, file, opt)
						}
						if !module.IsNil() {
							defer module.Dispose()
						}
						if moduleErr != nil {
							return "", moduleErr
						}
						return module.String(), nil
					}()
				}
				if err != nil {
					t.Fatalf("%s: %v", api, err)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM22 llc required")
				}
				compileLLVMToObject(t, llc, target.triple, api+".ll", api+".o", ir)
			}
		})
	}
}

func TestX86SignedIntegerScalarFloatActualGoPerOpcodeAttributes(t *testing.T) {
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return // historical toolchain has its own actual assembler oracle below
	}
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range strings.Split(string(data), "{as: A") {
		op := strings.SplitN(row, ",", 2)[0]
		if !strings.HasPrefix(op, "VCVTSI2") {
			continue
		}
		body := strings.SplitN(row, "\n\t}},", 2)[0]
		spec, known := x86SignedIntegerFloatSpecs[Op(op)]
		if !known || !strings.Contains(body, "_yvcvtsi2sdl") || strings.Contains(body, "Masking") || strings.Contains(body, "Zeroing") || strings.Contains(body, "Bcst") || strings.Contains(body, "SaeEnabled") ||
			strings.Contains(body, "RoundingEnabled") != spec.rounding || !strings.Contains(body, fmt.Sprintf("evexN%d", spec.sourceBits/8)) {
			t.Fatalf("actual Go per-opcode flags changed: %s", body)
		}
		count++
	}
	if count != 4 {
		t.Fatalf("actual signed vector family contains %d opcodes", count)
	}
	data, err = os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{ACVTSL2SD, yxcvlf, Pf2, opBytes{0x2a}}", "{ACVTSL2SS, yxcvlf, Pf3, opBytes{0x2a}}",
		"{ACVTSQ2SD, yxcvqf, Pw, opBytes{Pf2, 0x2a}}", "{ACVTSQ2SS, yxcvqf, Pw, opBytes{Pf3, 0x2a}}",
	} {
		if !strings.Contains(string(data), row) {
			t.Fatalf("actual Go legacy row changed: %s", row)
		}
	}
}

func TestX86SignedIntegerScalarFloatMode32FeaturesFollowValidSource(t *testing.T) {
	for _, row := range []struct{ instruction, want string }{
		{"CVTSL2SS AX,X0", "+sse"},
		{"CVTSL2SD AX,X0", "+sse2"},
		{"VCVTSI2SSL AX,X0,X1", "+sse"},
		{"VCVTSI2SDL AX,X0,X1", "+sse2"},
		{"VCVTSI2SSQ AX,X0,X1", "+sse"},
		{"VCVTSI2SDQ AX,X0,X1", "+sse2"},
		{"VCVTSI2SSQ.RU_SAE AX,X0,X1", ""},
		{"VCVTSI2SDQ.RD_SAE AX,X0,X1", ""},
		{"CVTSQ2SS AX,X0", ""},
		{"VCVTSI2SSL AX,X8,X1", ""},
		{"VCVTSI2SSL.Z AX,X0,X1", ""},
	} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row.instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "386", file.Funcs[0]); got != row.want {
			t.Fatalf("%s mode32 features %q, want %q", row.instruction, got, row.want)
		}
		if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", file.Funcs[0]); got != "" {
			t.Fatalf("%s changed amd64 ISA baseline: %q", row.instruction, got)
		}
	}
}

func TestX86SignedIntegerScalarFloatGrammarAndHelperIdentity(t *testing.T) {
	for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
		args := "AX,X0"
		if strings.HasPrefix(op, "V") {
			args = "AX,X0,X1"
		}
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+op+" "+args+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		for _, declared := range []Op{"", Op(op), "CVTSL2SS", "VCVTSI2SDQ", "BOGUS"} {
			ins.Op = declared
			c, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			ok, _, err := c.lowerSignedIntegerScalarFloat(Op(op), ins)
			if declared != "" && declared != Op(op) {
				if !ok || err == nil || output.String() != before {
					t.Fatalf("%s/%s conflict emitted IR: %v", op, declared, err)
				}
			} else if !ok || err != nil {
				t.Fatalf("%s/%s valid identity failed: %v", op, declared, err)
			}
		}
	}
	for _, row := range []string{
		"CVTSL2SS.RN_SAE AX,X0", "CVTSQ2SD AX,Y0", "CVTSL2SS $1,X0", "CVTSL2SD X0,X1", "CVTSL2SS AX,X16",
		"VCVTSI2SSL AX,X0", "VCVTSI2SSL AX,Y0,X1", "VCVTSI2SSL AX,X0,K1,X1", "VCVTSI2SSL.Z AX,X0,X1",
		"VCVTSI2SSL.SAE AX,X0,X1", "VCVTSI2SSL.BCST (BX),X0,X1", "VCVTSI2SDL.RN_SAE AX,X0,X1",
		"VCVTSI2SSQ.RD_SAE (BX),X0,X1", "VCVTSI2SSL. AX,X0,X1", "VCVTSI2SSL X0,X1,X2",
	} {
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		assertX86ScalarIntegerFloatRejected(t, "amd64", "x86_64-unknown-linux-gnu", row)
	}
	for _, row := range []string{"CVTSQ2SS AX,X0", "CVTSQ2SD AX,X0", "VCVTSI2SSL R8,X0,X1"} {
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		assertX86ScalarIntegerFloatRejected(t, "386", "i386-unknown-linux-gnu", row)
	}
	for _, row := range []string{"VCVTSI2SSL AX,X8,X1", "VCVTSI2SDQ.RU_SAE AX,X1,X31"} {
		source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
		goAssemblerOracleOutput(t, "386", source, "", true)
		file, _ := Parse(ArchAMD64, source)
		if _, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("mode32 high named bank became physical success: %v", err)
		}
	}
}

func TestX86SignedIntegerScalarFloatFPSpanGrammarBeforeEmission(t *testing.T) {
	for _, row := range []string{"CVTSL2SS value+0(FP),X0", "CVTSQ2SD value+0(FP),X0", "VCVTSI2SSL value+0(FP),X0,X1", "VCVTSI2SDQ value+0(FP),X0,X1"} {
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		f, _, _ := x86SignedIntegerFloatProperties(ins, "amd64")
		for missing := -1; missing < f.sourceBits/8; missing++ {
			sig := FuncSig{Args: make([]LLVMType, f.sourceBits/8), Ret: Void}
			for i := range sig.Args {
				sig.Args[i] = I8
				if i != missing {
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(i), Type: I8, Index: i, Field: -1})
				}
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			before := output.String()
			known, _, err := ctx.lowerSignedIntegerScalarFloat(ins.Op, ins)
			if !known || (err != nil) != (missing >= 0) || missing >= 0 && output.String() != before {
				t.Fatalf("%s missing%d: %v", row, missing, err)
			}
		}
	}
	for _, row := range []string{"VCVTSI2SSL (AX)(SP*2),X0,X1", "CVTSL2SS 2147483648(BX),X0", "VCVTSI2SSQ $symbol(SB),X0,X1", "VCVTSI2SSL (AX)(SI*3),X0,X1"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			continue
		}
		ins := file.Funcs[0].Instrs[1]
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		known, _, err := ctx.lowerSignedIntegerScalarFloat(ins.Op, ins)
		if !known || err == nil || output.String() != before {
			t.Fatalf("invalid source emitted IR: %s %v", row, err)
		}
	}
}
