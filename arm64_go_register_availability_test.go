package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64GoInternalCallerSaveOracle(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·Pass<ABIInternal>(SB),4,$0-16
MOVD R0,R9
CALL ·Compute<ABIInternal>(SB)
EOR R9,R0,R0
RET
TEXT ·Compute<ABIInternal>(SB),4,$0-16
MOVD $99,R9
ADD $9,R0
RET
`
	const decl = "func Pass(uint64) uint64\nfunc Compute(uint64) uint64\n"
	runARM64GoInternalOracle(t, source, "package main\n"+decl+`func main() {
  for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    if Pass(a)!=99^(a+9) { panic("actual Go caller-save R9 mismatch") }
  }
}
`, len(runner) != 0)
	pkg := mustGoPackage(t, "test/callersave", "package callersave\n"+decl)
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple,
			ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
		})
		if tr != nil {
			tr.Module.Dispose()
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: out-of-band R9 result must require a machine-state call contract, got %v", triple, err)
		}
	}
}

func TestARM64GoInternalAvailabilityMissingContext(t *testing.T) {
	for _, tc := range []struct{ name, before, after, result string }{
		{"first_gp_read", "", "MOVD R9,R0", "uint64"},
		{"two_operand_update_is_read", "", "ADD $3,R9\nMOVD R9,R0", "uint64"},
		{"memory_base", "", "MOVD (R9),R0", "uint64"},
		{"memory_writeback_base", "", "MOVD.P R0,8(R9)", "uint64"},
		{"shift_source", "", "EOR R9<<3,R0,R0", "uint64"},
		{"register_extended_source", "", "ADD R9.UXTW,R0,R0", "uint64"},
		{"fp_register", "", "FMOVD F9,R0", "uint64"},
		{"flags_clobbered", "CMP $0,R0\n", "CSET NE,R0", "uint64"},
		{"carry_clobbered", "CMP $0,R0\n", "ADC ZR,R0", "uint64"},
		{"negate_carry_clobbered", "CMP $0,R0\n", "NGC R0,R0", "uint64"},
		{"merge_one_missing_write", "", "CBZ R0,left\nMOVD $99,R9\nB done\nleft:\nNOOP\ndone:\nEOR R9,R0,R0", "uint64"},
		{"scalar_vector_alias", "", "VMOV V0.D[1],R0", "(uint64,float64)"},
		{"scalar_result_width", "", "FMOVD F0,R0", "float32"},
		{"raw_native_effect", "", "WORD $0xd53bd040", "uint64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decl := "package availability\nfunc Pass(uint64) uint64\nfunc Compute(uint64) " + tc.result + "\n"
			pkg := mustGoPackage(t, "test/availability", decl)
			source := "TEXT ·Pass<ABIInternal>(SB),4,$0-16\n" + tc.before + "CALL ·Compute<ABIInternal>(SB)\n" + tc.after + "\nRET\n"
			requireARM64GoABIInternalObject(t, source)
			for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: triple,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
				})
				if tr != nil {
					tr.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: missing complete machine state must require context, got %v", triple, err)
				}
			}
		})
	}
	// The Go declaration initializes only R0, not the ambient native register
	// file. A register-only entry cannot manufacture a zero R9 input either.
	pkg := mustGoPackage(t, "test/availabilityentry", "package availabilityentry\nfunc Pass(uint64) uint64\n")
	tr, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\nMOVD R9,R0\nRET\n"), GoModuleOptions{GOARCH: "arm64"})
	if tr != nil {
		tr.Module.Dispose()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("undeclared register entry: %v", err)
	}
}

func TestCrossLinuxRuntimeMatrixARM64GoInternalExplicitCustomTail(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·Pass<ABIInternal>(SB),4,$0-16
ADD $9,R0
B customTail<>(SB)
TEXT customTail<>(SB),516,$0-0
ADD $7,R0
RET
`
	runARM64GoInternalOracle(t, source, `package main
func Pass(uint64) uint64
func main() {
  for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    if Pass(a)!=a+16 { panic("explicit custom tail register mismatch") }
  }
}
`, len(runner) != 0)
	pkg := mustGoPackage(t, "test/customtail", "package customtail\nfunc Pass(uint64) uint64\n")
	translate := func(target string) string {
		tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target,
			ResolveSym: func(sym string) string {
				return strings.TrimSuffix(strings.TrimPrefix(goStripABISuffix(sym), "·"), "<>")
			},
			ManualSig: func(name string) (FuncSig, bool) {
				return FuncSig{Name: "customTail", Args: []LLVMType{I64}, Ret: I64, ArgRegs: []Reg{"R0"}}, name == "customTail"
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer tr.Module.Dispose()
		return tr.Module.String()
	}
	for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		compileLLVMToObject(t, llc, target, "custom-tail.ll", "custom-tail.o", translate(target))
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "custom_tail", triple, translate(triple), `#include <stdint.h>
extern uint64_t Pass(uint64_t);
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) if (Pass(inputs[i])!=inputs[i]+16) return 1;
  return 0;
}
`, runner)
}
