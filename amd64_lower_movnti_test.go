package plan9asm

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func x86MOVNTICompleteFormsSource(goarch string) (string, map[string]FuncSig) {
	var source strings.Builder
	source.WriteString("DATA movntidata+0(SB)/8, $1\n")
	source.WriteString("GLOBL movntidata(SB), $8\n")
	source.WriteString("TEXT movntiforms(SB),$0-0\n")
	source.WriteString("\tMOVNTIL AX, 8(BX)\n")
	source.WriteString("\tMOVNTIL CX, movntidata(SB)\n")
	if goarch == "amd64" {
		source.WriteString("\tMOVNTIL R11, 16(R12)\n")
		source.WriteString("\tMOVNTIQ AX, 24(BX)\n")
		source.WriteString("\tMOVNTIQ CX, movntidata(SB)\n")
		source.WriteString("\tMOVNTIQ R13, 32(R14)\n")
	}
	source.WriteString("\tRET\n")

	source.WriteString("TEXT movntiframe(SB),$0-4\n")
	source.WriteString("\tMOVNTIL AX, ret+0(FP)\n")
	source.WriteString("\tRET\n")
	if goarch == "amd64" {
		source.WriteString("TEXT movntiframeq(SB),$0-8\n")
		source.WriteString("\tMOVNTIQ AX, ret+0(FP)\n")
		source.WriteString("\tRET\n")
	}

	// Yml's Go compatibility closure includes registers even though the ISA
	// defines only memory destinations for MOVNTI. Keep this Go-accepted source
	// form visible and require the translated function to trap explicitly.
	source.WriteString("TEXT movntiregtrap(SB),$0-0\n")
	source.WriteString("\tMOVNTIL AX, BX\n")
	source.WriteString("\tRET\n")

	sigs := map[string]FuncSig{
		"movntiforms":   {Name: "movntiforms", Ret: Void},
		"movntiframe":   {Name: "movntiframe", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}}},
		"movntiregtrap": {Name: "movntiregtrap", Ret: Void},
	}
	if goarch == "amd64" {
		sigs["movntiframeq"] = FuncSig{Name: "movntiframeq", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}
	}
	return source.String(), sigs
}

func TestTranslateX86MOVNTICompleteGo127FormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			source, sigs := x86MOVNTICompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`store i32`, `!nontemporal !0`, `!0 = !{i32 1}`, `"target-features"="+sse2"`, `asm sideeffect "ud2"`, "unreachable"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("MOVNTI lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "store i64") {
				t.Fatalf("MOVNTIQ lowering omitted i64 store:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "movnti-"+target.name+".ll", "movnti-"+target.name+".o", ir)
			command := exec.Command(llc, "-mtriple="+target.triple, "-filetype=asm", "-o=-", "-")
			command.Stdin = strings.NewReader(ir)
			assembly, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("llc MOVNTI assembly failed: %v\n%s", err, assembly)
			}
			if !strings.Contains(strings.ToLower(string(assembly)), "movnti") {
				t.Fatalf("LLVM 22 did not preserve the non-temporal integer store:\n%s", assembly)
			}
		})
	}
}

func TestTranslateX86MOVNTIRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "MOVNTIL 0(AX), BX"},
		{goarch: "amd64", instruction: "MOVNTIL 0(AX), 8(BX)"},
		{goarch: "amd64", instruction: "MOVNTIL $1, 8(BX)"},
		{goarch: "amd64", instruction: "MOVNTIL X0, 8(BX)"},
		{goarch: "amd64", instruction: "MOVNTIL AX"},
		{goarch: "amd64", instruction: "MOVNTIL AX, 0(BX), CX"},
		{goarch: "amd64", instruction: "MOVNTIL.Z AX, 8(BX)"},
		{goarch: "386", instruction: "MOVNTIQ AX, 8(BX)"},
		{goarch: "386", instruction: "MOVNTIL R8, 8(BX)"},
		{goarch: "386", instruction: "MOVNTIL AX, 8(R9)"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch:       test.goarch,
				TargetTriple: triple,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's MOVNTI yrl_ml table", test.instruction)
			}
		})
	}
}

func TestAMD64MOVNTIRuntimeSemanticsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT movntisemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVQ $0x1122334455667788, AX
	MOVQ $0x8877665544332211, BX
	MOVNTIL AX, 0(DI)
	MOVNTIQ BX, 8(DI)
	SFENCE
	SETCS 16(DI)
	SETOS 17(DI)
	SETEQ 18(DI)
	SETMI 19(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"movntisemantics": {
				Name: "movntisemantics", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void movntisemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[24] = {0};
  movntisemantics(out);
  if (load64(out) != UINT64_C(0x0000000055667788)) return 10;
  if (load64(out+8) != UINT64_C(0x8877665544332211)) return 11;
  if (out[16] != 1 || out[17] != 1 || out[18] != 0 || out[19] != 1) return 12;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "movnti_semantics", triple, ir, mainC, runPrefix)
}

func TestX86MOVNTIGoAssemblerCompatibilityClosure(t *testing.T) {
	for _, goarch := range []string{"amd64", "386"} {
		for _, instruction := range []string{"MOVNTIL AX, 8(BX)", "MOVNTIL AX, BX", "MOVNTIL AX, ret+0(FP)"} {
			t.Run(fmt.Sprintf("%s/%s", goarch, strings.NewReplacer(" ", "_", ",", "").Replace(instruction)), func(t *testing.T) {
				requireX86GoAssemblerResult(t, goarch, "TEXT compat(SB),$0-8\n\t"+instruction+"\n\tRET\n", true)
			})
		}
	}
}
