package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64DeclaredGoABIInternalNeedsRegisterContract(t *testing.T) {
	pkg := mustGoPackage(t, "test/internal", "package internal\nfunc Y(uint64) uint64\nfunc X(uint64) uint64\n")
	for _, branch := range []string{"CALL", "BL", "RET", "B", "JMP"} {
		source := "TEXT ·Y(SB),4,$0-16\n" + branch + " ·X<ABIInternal>(SB)\n"
		if branch == "CALL" || branch == "BL" {
			source += "RET\n"
		}
		requireARM64GoABIInternalObject(t, source)
		tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
			// A manual classic ABI0 frame has no standard register contract.
			// Actual declarations plus selectors now derive one independently;
			// overriding that evidence must not silently gain a register ABI.
			ManualSig: func(name string) (FuncSig, bool) {
				return sigWithClassicFrame("X", []LLVMType{I64}, I64), name == "X"
			},
		})
		if err == nil {
			tr.Module.Dispose()
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: a manual ABI0 frame cannot prove an explicit register entry: %v", branch, err)
		}
	}
}

func requireARM64GoABIInternalObject(t *testing.T, source string) {
	t.Helper()
	// Go reserves explicit selectors for package runtime. This validates the
	// actual selector grammar, not an ordinary-package rejection or execution.
	// The shared oracle observes the selected assembler's flags: Go 1.20 also
	// needs -compiling-runtime, while current Go derives permission from -p.
	requireARM64TypedCallGoSelectorObject(t, source)
}

func TestCrossLinuxRuntimeMatrixARM64ExplicitRegisterContract(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	pkg := mustGoPackage(t, "test/internal", "package internal\nfunc Y(uint64) uint64\nfunc X(uint64) uint64\n")
	for _, branch := range []string{"CALL", "BL", "RET", "B", "JMP"} {
		t.Run(branch, func(t *testing.T) {
			source := "TEXT ·Y(SB),4,$0-16\nMOVD a+0(FP),R9\n" + branch + " ·X<ABIInternal>(SB)\n"
			if branch == "CALL" || branch == "BL" {
				source += "MOVD R0,ret+8(FP)\nRET\n"
			}
			requireARM64GoABIInternalObject(t, source)
			translate := func(target string) string {
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
					ManualSig: func(name string) (FuncSig, bool) {
						return FuncSig{Name: "X", Args: []LLVMType{I64}, ArgRegs: []Reg{"R9"}, Ret: I64}, name == "X"
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Module.Dispose()
				return tr.Module.String()
			}
			for _, target := range []string{
				"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
				"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
			} {
				compileLLVMToObject(t, llc, target, "explicit-register.ll", "explicit-register.o", translate(target))
			}
			const main = `#include <stdint.h>
extern uint64_t Y(uint64_t);
uint64_t X(uint64_t a) { return a*7+9; }
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) { if (Y(inputs[i]) != inputs[i]*7+9) return 1; }
  return 0;
}
`
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "explicit_register", triple, translate(triple), main, runner)
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64DeclaredGoABI0Shapes(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range []struct {
		name, declarations, body, goCallee, goWant, cCallee, cWant, llvmCallee string
	}{
		{
			name:         "result_only",
			declarations: "func X() uint64",
			body:         "CALL ·X(SB)\nMOVD 8(RSP),R9",
			goCallee:     "func X() uint64 { return 0x123456789abcdef0 }",
			goWant:       "uint64(0x123456789abcdef0)",
			cCallee:      "uint64_t X(void) { return UINT64_C(0x123456789abcdef0); }",
			cWant:        "UINT64_C(0x123456789abcdef0)",
		},
		{
			name:         "narrow",
			declarations: "func X(uint8) uint8",
			body:         "MOVD a+0(FP),R9\nMOVB R9,8(RSP)\nCALL ·X(SB)\nMOVBU 16(RSP),R9",
			goCallee:     "func X(a uint8) uint8 { return a*7+9 }",
			goWant:       "uint64(uint8(a)*7+9)",
			cCallee:      "uint8_t X(uint8_t a) { return (uint8_t)(a*7+9); }",
			cWant:        "(uint8_t)(inputs[i]*7+9)",
		},
		{
			name:         "tuple_result",
			declarations: "func X(uint64) (uint64,uint64)",
			body:         "MOVD a+0(FP),R9\nMOVD R9,8(RSP)\nCALL ·X(SB)\nLDP 16(RSP),(R9,R10)\nEOR R10,R9,R9",
			goCallee:     "func X(a uint64) (uint64,uint64) { return a*7+9,a*11+3 }",
			goWant:       "(a*7+9)^(a*11+3)",
			cWant:        "(inputs[i]*7+9)^(inputs[i]*11+3)",
			llvmCallee: `define { i64, i64 } @X(i64 %a) {
  %x0 = mul i64 %a, 7
  %x = add i64 %x0, 9
  %y0 = mul i64 %a, 11
  %y = add i64 %y0, 3
  %r0 = insertvalue { i64, i64 } undef, i64 %x, 0
  %r = insertvalue { i64, i64 } %r0, i64 %y, 1
  ret { i64, i64 } %r
}
`,
		},
		{
			name:         "nested_aggregate",
			declarations: "type Pair struct { Lo,Hi uint64 }\ntype Nested struct { A uint64; B Pair }\nfunc X(Nested) uint64",
			body:         "MOVD a+0(FP),R9\nMOVD R9,8(RSP)\nADD $3,R9\nMOVD R9,16(RSP)\nADD $5,R9\nMOVD R9,24(RSP)\nCALL ·X(SB)\nMOVD 32(RSP),R9",
			goCallee:     "type Pair struct { Lo,Hi uint64 }; type Nested struct { A uint64; B Pair }; func X(a Nested) uint64 { return a.A*7+a.B.Lo*11+a.B.Hi*13 }",
			goWant:       "a*7+(a+3)*11+(a+8)*13",
			cWant:        "inputs[i]*7+(inputs[i]+3)*11+(inputs[i]+8)*13",
			llvmCallee: `define i64 @X({ i64, { i64, i64 } } %a) {
  %x = extractvalue { i64, { i64, i64 } } %a, 0
  %y = extractvalue { i64, { i64, i64 } } %a, 1, 0
  %z = extractvalue { i64, { i64, i64 } } %a, 1, 1
  %x1 = mul i64 %x, 7
  %y1 = mul i64 %y, 11
  %z1 = mul i64 %z, 13
  %xy = add i64 %x1, %y1
  %r = add i64 %xy, %z1
  ret i64 %r
}
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "TEXT ·Y(SB),4,$48-16\n" + tc.body + "\nMOVD R9,ret+8(FP)\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			goMain := "package main\nfunc Y(uint64) uint64\n" + tc.goCallee + "\nfunc main() { for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} { if Y(a) != " + tc.goWant + " { panic(\"ABI0 shape mismatch\") } } }\n"
			runARM64LocalRegisterGoOracle(t, source, goMain, len(runner) != 0)
			pkg := mustGoPackage(t, "test/shape", "package shape\nfunc Y(uint64) uint64\n"+tc.declarations+"\n")
			translate := func(target string) string {
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Module.Dispose()
				ir := tr.Module.String()
				if tc.llvmCallee != "" {
					for _, line := range strings.Split(ir, "\n") {
						if strings.HasPrefix(line, "declare ") && strings.Contains(line, " @X(") {
							return strings.Replace(ir, line, tc.llvmCallee, 1)
						}
					}
					t.Fatal("missing independent LLVM callee declaration")
				}
				return ir
			}
			for _, target := range []string{
				"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
				"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
			} {
				compileLLVMToObject(t, llc, target, "abi0-shape.ll", "abi0-shape.o", translate(target))
			}
			main := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern uint64_t Y(uint64_t);
%s
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) {
    if (Y(inputs[i]) != (%s)) { fprintf(stderr,"ABI0 shape mismatch\n"); return 1; }
  }
  return 0;
}
`, tc.cCallee, tc.cWant)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_shape", triple, translate(triple), main, runner)
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64DeclaredGoABI0(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·Y(SB),4,$32-16
MOVD a+0(FP),R9
MOVD R9,8(RSP)
MOVD $111,R0
MOVD $222,R1
CALL ·X(SB)
MOVD 16(RSP),R9
MOVD R9,ret+8(FP)
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	runARM64LocalRegisterGoOracle(t, source, `package main
func Y(a uint64) uint64
func X(a uint64) uint64 { return a*7+9 }
func main() {
	for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
		if Y(a) != a*7+9 { panic("declared Go ABI0 frame mismatch") }
	}
}
`, len(runner) != 0)
	pkg := mustGoPackage(t, "test/abi0", "package abi0\nfunc Y(uint64) uint64\nfunc X(uint64) uint64\n")
	translate := func(target string) string {
		tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target,
			ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer tr.Module.Dispose()
		return tr.Module.String()
	}
	for _, target := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		compileLLVMToObject(t, llc, target, "declared-go-abi0.ll", "declared-go-abi0.o", translate(target))
	}
	const main = `#include <stdint.h>
#include <stdio.h>
extern uint64_t Y(uint64_t);
uint64_t X(uint64_t a) { return a*7+9; }
int main(void) {
	uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
	for (unsigned i=0;i<5;i++) {
		if (Y(inputs[i]) != inputs[i]*7+9) {
			fprintf(stderr,"declared Go ABI0 frame mismatch\n");
			return 1;
		}
	}
	return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "declared_go_abi0", triple, translate(triple), main, runner)
}
