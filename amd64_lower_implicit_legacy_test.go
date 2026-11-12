package plan9asm

import (
	"reflect"
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
			x86PhysicalSPRequirePublicContext(t, source, "func implicitlegacyforms()", target.goarch, target.triple)
			ir := x86ScalarFormatObjectUnit(t, file, map[string]FuncSig{
				"implicitlegacyforms": {Name: "implicitlegacyforms", Ret: Void},
			}, target.goarch, target.triple, 0)
			for _, want := range []string{"load i16", "load volatile i8", "-256"} {
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
	execution := x86ScalarCountHostExecution(t)
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
	// LEAVE changes physical SP and invalidates the later Go FP/RET transport.
	// Preserve this complete original body as Context and execute only its
	// explicitly private virtual-register mathematics, never a native Go ABI.
	x86PhysicalSPRequirePublicContext(t, source, "func implicitlegacysemantics(out,data *byte)", "amd64", execution.triple)
	ir := x86PhysicalSPPrivateEmitter(t, source,
		map[string]FuncSig{
			"implicitlegacysemantics": {
				Name: "implicitlegacysemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		}, "amd64", execution.triple)
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
	execution.compileAndRunLLVM(t, "implicit_legacy_private_math", ir,
		"#define implicitlegacysemantics InstructionFormat0\n"+mainC, "-O2")
	t.Log("private virtual-SP LEAVE/XLAT mathematics only; original public source remains Context, not native Go ABI")
}
