package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86LODSCompleteFormsSource(goarch string) string {
	widths := []string{"B", "W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	var source strings.Builder
	source.WriteString("TEXT lodsforms(SB),$0-0\n")
	for _, width := range widths {
		op := "LODS" + width
		fmt.Fprintf(&source, "\t%s\n", op)
		fmt.Fprintf(&source, "\tCLD; REP; %s\n", op)
		fmt.Fprintf(&source, "\tSTD; REPN; %s\n", op)
		source.WriteString("\tCLD\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86LODSCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86LODSCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"lodsforms": {Name: "lodsforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, width := range []string{"b", "w", "l"} {
				if want := "@__plan9asm_rep_lods" + width; !strings.Contains(ir, want) {
					t.Fatalf("LODS lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "@__plan9asm_rep_lodsq") {
				t.Fatalf("LODSQ lowering omitted qword helper:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "lods-"+target.name+".ll", "lods-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86LODSRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LODSB AX"},
		{goarch: "amd64", instruction: "LODSW AX, BX"},
		{goarch: "amd64", instruction: "LODSL.Z"},
		{goarch: "386", instruction: "LODSQ"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's LODS ynone table", test.instruction)
			}
		})
	}
}

func TestAMD64LODSRuntimeSemanticsWidthsPrefixesAndDirection(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT lodssemantics(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), R8
	MOVQ data+8(FP), R9
	CLD

	MOVQ R9, SI
	MOVQ $0x1122334455667788, AX
	LODSB
	MOVQ AX, 0(R8)
	MOVQ SI, 8(R8)

	MOVQ R9, SI
	ADDQ $8, SI
	MOVQ $0x1122334455667788, AX
	LODSW
	MOVQ AX, 16(R8)

	MOVQ R9, SI
	ADDQ $16, SI
	MOVQ $-1, AX
	LODSL
	MOVQ AX, 24(R8)

	MOVQ R9, SI
	ADDQ $24, SI
	LODSQ
	MOVQ AX, 32(R8)

	MOVQ R9, SI
	ADDQ $32, SI
	MOVQ $3, CX
	REP; LODSB
	MOVQ AX, 40(R8)
	MOVQ SI, 48(R8)
	MOVQ CX, 56(R8)

	MOVQ R9, SI
	ADDQ $40, SI
	MOVQ $3, CX
	REPN; LODSW
	MOVQ AX, 64(R8)
	MOVQ SI, 72(R8)
	MOVQ CX, 80(R8)

	MOVQ R9, SI
	ADDQ $52, SI
	MOVQ $2, CX
	STD
	REP; LODSL
	CLD
	MOVQ AX, 88(R8)
	MOVQ SI, 96(R8)
	MOVQ CX, 104(R8)
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
			"lodssemantics": {
				Name: "lodssemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void lodssemantics(uint8_t *, uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t data[64] = {0};
  data[0] = 0xaa;
  const uint16_t w = UINT16_C(0xbbcc); memcpy(data+8, &w, sizeof(w));
  const uint32_t l = UINT32_C(0x89abcdef); memcpy(data+16, &l, sizeof(l));
  const uint64_t q = UINT64_C(0x0123456789abcdef); memcpy(data+24, &q, sizeof(q));
  data[32] = 1; data[33] = 2; data[34] = 3;
  const uint16_t ws[3] = {0x1111,0x2222,0x3333}; memcpy(data+40, ws, sizeof(ws));
  const uint32_t ls[2] = {0x44444444,0x55555555}; memcpy(data+48, ls, sizeof(ls));
  uint8_t out[112] = {0};
  lodssemantics(out, data);
  if (load64(out+0) != UINT64_C(0x11223344556677aa) || load64(out+8) != (uintptr_t)(data+1)) return 10;
  if (load64(out+16) != UINT64_C(0x112233445566bbcc)) return 11;
  if (load64(out+24) != UINT64_C(0x89abcdef)) return 12;
  if (load64(out+32) != q) return 13;
  if ((load64(out+40) & 0xff) != 3 || load64(out+48) != (uintptr_t)(data+35) || load64(out+56) != 0) return 14;
  if ((load64(out+64) & 0xffff) != 0x3333 || load64(out+72) != (uintptr_t)(data+46) || load64(out+80) != 0) return 15;
  if (load64(out+88) != UINT64_C(0x44444444) || load64(out+96) != (uintptr_t)(data+44) || load64(out+104) != 0) return 16;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "lods_semantics", triple, ir, mainC, runPrefix)
}
