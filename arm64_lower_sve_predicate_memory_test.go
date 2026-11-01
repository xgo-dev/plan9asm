package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEPredicateMemoryCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svepredicatememoryforms(SB),$0-0\n")
	source.WriteString("\tPLDR (-VL*256)(R0), P0\n")
	source.WriteString("\tPLDR (VL*255)(RSP), P15\n")
	source.WriteString("\tPSTR P14, (-VL*256)(R1)\n")
	source.WriteString("\tPSTR P1, (VL*255)(RSP)\n")
	hints := []string{
		"PLDL1KEEP", "PLDL1STRM", "PLDL2KEEP", "PLDL2STRM", "PLDL3KEEP", "PLDL3STRM",
		"PSTL1KEEP", "PSTL1STRM", "PSTL2KEEP", "PSTL2STRM", "PSTL3KEEP", "PSTL3STRM",
	}
	for index, hint := range hints {
		fmt.Fprintf(&source, "\tPPRFB (VL*%d)(R2), P%d, %s\n", index%32, index%8, hint)
	}
	source.WriteString("\tPPRFB (R8)(RSP), P3, PSTL3KEEP\n")
	source.WriteString("\tPPRFH (R8<<1)(RSP), P3, PSTL3KEEP\n")
	source.WriteString("\tPPRFW (R8<<2)(RSP), P3, PSTL3KEEP\n")
	source.WriteString("\tPPRFD (R8<<3)(RSP), P3, PSTL3KEEP\n")
	source.WriteString("\tPPRFB (-VL*32)(R3), P0, PLDL1KEEP\n")
	source.WriteString("\tPPRFH (VL*31)(R4), P1, PLDL1STRM\n")
	source.WriteString("\tPPRFW (-VL*32)(R5), P2, PSTL1KEEP\n")
	source.WriteString("\tPPRFD (VL*31)(R6), P7, PSTL3STRM\n")
	source.WriteString("\tRET\n")
	return source.String()
}

func TestParseARM64SVEPredicateMemoryRetainsAddressSemantics(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT parsepredmem(SB),$0-0\n\tPLDR (-VL*2)(RSP), P5\n\tPPRFD (R8<<3)(RSP), P3, PSTL3KEEP\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	loadMemory := file.Funcs[0].Instrs[1].Args[0].Mem
	if loadMemory.Base != Reg("RSP") || loadMemory.OffRaw != "-VL*2" {
		t.Fatalf("PLDR address parsed as %+v, want RSP plus -VL*2", loadMemory)
	}
	prefetchMemory := file.Funcs[0].Instrs[2].Args[0].Mem
	if prefetchMemory.Base != Reg("RSP") || prefetchMemory.Index != Reg("R8") || prefetchMemory.Scale != 8 {
		t.Fatalf("PPRFD address parsed as %+v, want RSP plus R8<<3", prefetchMemory)
	}
}

func TestTranslateARM64SVEPredicateMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVEPredicateMemoryCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svepredicatememoryforms": {Name: "svepredicatememoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"load <vscale x 16 x i1>",
				"store <vscale x 16 x i1>",
				"@llvm.aarch64.sve.prf.nxv16i1",
				"@llvm.aarch64.sve.prf.nxv8i1",
				"@llvm.aarch64.sve.prf.nxv4i1",
				"@llvm.aarch64.sve.prf.nxv2i1",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicate memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-predicate-memory.ll", "arm64-sve-predicate-memory.o", ll)
		})
	}
}

func TestTranslateARM64SVEPredicateMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"PLDR (-VL*257)(R0), P1",
		"PSTR P1, (VL*256)(R0)",
		"PLDR (VL*1)(R0), P1.B",
		"PPRFB (-VL*33)(R0), P1, PLDL1KEEP",
		"PPRFD (VL*32)(R0), P1, PLDL1KEEP",
		"PPRFH (R8<<2)(RSP), P1, PLDL1KEEP",
		"PPRFW (R8)(RSP), P1, PLDL1KEEP",
		"PPRFD (R8<<3)(RSP), P8, PLDL1KEEP",
		"PPRFB (VL*1)(R0), P1, PLIL1KEEP",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvepredicatememory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvepredicatememory": {Name: "badsvepredicatememory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE predicate memory forms", instruction)
			}
		})
	}
}
