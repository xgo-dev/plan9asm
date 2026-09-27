package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86CMPSCompleteFormsSource(goarch string) string {
	widths := []string{"B", "W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	var source strings.Builder
	source.WriteString("TEXT cmpsforms(SB),$0-0\n")
	for _, width := range widths {
		op := "CMPS" + width
		fmt.Fprintf(&source, "\t%s\n", op)
		fmt.Fprintf(&source, "\tCLD; REP; %s\n", op)
		fmt.Fprintf(&source, "\tSTD; REPN; %s\n", op)
		source.WriteString("\tCLD\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86CMPSCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86CMPSCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"cmpsforms": {Name: "cmpsforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, width := range []string{"b", "w", "l"} {
				if want := "@__plan9asm_rep_cmps" + width; !strings.Contains(ir, want) {
					t.Fatalf("CMPS lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "@__plan9asm_rep_cmpsq") {
				t.Fatalf("CMPSQ lowering omitted qword helper:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "cmps-"+target.name+".ll", "cmps-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86CMPSRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "CMPSB AX"},
		{goarch: "amd64", instruction: "CMPSW AX, BX"},
		{goarch: "amd64", instruction: "CMPSL.Z"},
		{goarch: "386", instruction: "CMPSQ"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's CMPS ynone table", test.instruction)
			}
		})
	}
}

func TestAMD64CMPSRuntimeSemanticsPrefixesDirectionAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT cmpssemantics(SB),NOSPLIT,$0-24
	MOVQ out+0(FP), R8
	MOVQ left+8(FP), R9
	MOVQ right+16(FP), R10

	MOVQ R9, SI
	MOVQ R10, DI
	MOVQ $4, CX
	CLD
	REP; CMPSB
	MOVQ SI, 0(R8)
	MOVQ DI, 8(R8)
	MOVQ CX, 16(R8)
	SETCS 24(R8)
	SETEQ 25(R8)
	SETMI 26(R8)
	SETOS 27(R8)
	SETPS 28(R8)

	MOVQ R9, SI
	ADDQ $8, SI
	MOVQ R10, DI
	ADDQ $8, DI
	MOVQ $3, CX
	REPN; CMPSW
	MOVQ SI, 32(R8)
	MOVQ DI, 40(R8)
	MOVQ CX, 48(R8)
	SETCS 56(R8)
	SETEQ 57(R8)

	MOVQ R9, SI
	ADDQ $28, SI
	MOVQ R10, DI
	ADDQ $28, DI
	STD
	CMPSL
	CLD
	MOVQ SI, 64(R8)
	MOVQ DI, 72(R8)
	SETCS 80(R8)
	SETEQ 81(R8)
	SETMI 82(R8)
	SETOS 83(R8)

	MOVQ R9, SI
	ADDQ $40, SI
	MOVQ R10, DI
	ADDQ $40, DI
	CMPSQ
	MOVQ SI, 88(R8)
	MOVQ DI, 96(R8)
	SETEQ 104(R8)
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
			"cmpssemantics": {
				Name: "cmpssemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void cmpssemantics(uint8_t *, uint8_t *, uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t left[56] = {1,2,9,4};
  uint8_t right[56] = {1,2,3,4};
  const uint16_t leftw[3] = {5,7,8}, rightw[3] = {6,7,9};
  memcpy(left + 8, leftw, sizeof(leftw));
  memcpy(right + 8, rightw, sizeof(rightw));
  const uint32_t leftl[2] = {0,1}, rightl[2] = {0,2};
  memcpy(left + 24, leftl, sizeof(leftl));
  memcpy(right + 24, rightl, sizeof(rightl));
  const uint64_t q = UINT64_C(0x0123456789abcdef);
  memcpy(left + 40, &q, sizeof(q));
  memcpy(right + 40, &q, sizeof(q));
  uint8_t out[112] = {0};
  cmpssemantics(out, left, right);
	if (load64(out+0) != (uintptr_t)(left+3)) return 10;
	if (load64(out+8) != (uintptr_t)(right+3)) return 11;
	if (load64(out+16) != 1) return 12;
  if (out[24] != 0 || out[25] != 0 || out[26] != 0 || out[27] != 0 || out[28] != 1) return 11;
  if (load64(out+32) != (uintptr_t)(left+12) || load64(out+40) != (uintptr_t)(right+12) || load64(out+48) != 1) return 12;
  if (out[56] != 0 || out[57] != 1) return 13;
  if (load64(out+64) != (uintptr_t)(left+24) || load64(out+72) != (uintptr_t)(right+24)) return 14;
  if (out[80] != 1 || out[81] != 0 || out[82] != 1 || out[83] != 0) return 15;
  if (load64(out+88) != (uintptr_t)(left+48) || load64(out+96) != (uintptr_t)(right+48) || out[104] != 1) return 16;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "cmps_semantics", triple, ir, mainC, runPrefix)
}
