package plan9asm

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64LeaveGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64LeaveSpec{
		"LEAVEW": {bits: 16},
		"LEAVEL": {bits: 32},
		"LEAVEQ": {bits: 64},
	}
	if !reflect.DeepEqual(amd64LeaveSpecs, want) {
		t.Fatalf("LEAVE grammar = %+v, want %+v", amd64LeaveSpecs, want)
	}
}

func TestTranslateX86LeaveAndXLATCompleteGoAssemblerForms(t *testing.T) {
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
			secondLeave := "LEAVEQ"
			if target.goarch == "386" {
				secondLeave = "LEAVEL"
			}
			source := "TEXT implicitlegacyforms(SB),$0-0\n" +
				"\tLEAVEW\n" +
				"\t" + secondLeave + "\n" +
				"\tXLAT\n" +
				"\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"implicitlegacyforms": {Name: "implicitlegacyforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load i16", "load i8", "getelementptr i8", "-256"} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			if target.goarch == "386" {
				if !strings.Contains(ir, "load i32") {
					t.Errorf("386 IR is missing LEAVEL load:\n%s", ir)
				}
			} else if !strings.Contains(ir, "load i64") {
				t.Errorf("amd64 IR is missing LEAVEQ load:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "implicit-legacy-"+target.name+".ll", "implicit-legacy-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86LeaveAndXLATRejectFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LEAVEW AX"},
		{goarch: "amd64", instruction: "LEAVEL"},
		{goarch: "amd64", instruction: "LEAVEQ.P"},
		{goarch: "amd64", instruction: "XLAT AX"},
		{goarch: "amd64", instruction: "XLAT.P"},
		{goarch: "386", instruction: "LEAVEQ"},
		{goarch: "386", instruction: "LEAVEL AX"},
		{goarch: "386", instruction: "XLAT AX"},
	} {
		t.Run(test.goarch+"_"+strings.ReplaceAll(test.instruction, " ", "_"), func(t *testing.T) {
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
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's LEAVE/XLAT tables", test.instruction)
			}
		})
	}
}

func TestAMD64LeaveAndXLATRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT implicitlegacysemantics(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), R8
	MOVQ data+8(FP), BP
	LEAVEQ
	MOVQ BP, 0(R8)
	MOVQ SP, 8(R8)
	MOVQ data+8(FP), BX
	ADDQ $16, BX
	MOVQ $0x1122334455667703, AX
	XLAT
	MOVQ AX, 16(R8)
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
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"implicitlegacysemantics": {
				Name: "implicitlegacysemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
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
extern void implicitlegacysemantics(uint8_t *, uint8_t *);
static uint64_t load64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  uint8_t data[256] = {0}, out[24] = {0};
  const uint64_t saved = UINT64_C(0xa1b2c3d4e5f60718); memcpy(data,&saved,8);
  data[19] = 0xaa;
  implicitlegacysemantics(out,data);
  if (load64(out) != saved) return 10;
  if (load64(out+8) != (uintptr_t)(data+8)) return 11;
  if (load64(out+16) != UINT64_C(0x11223344556677aa)) return 12;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "implicit_legacy_semantics", triple, ir, mainC, runPrefix)
}
