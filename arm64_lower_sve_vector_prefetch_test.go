package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEVectorPrefetchCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svevectorprefetchforms(SB),$0-0\n")
	for _, spec := range []struct {
		op      string
		shift   int
		maximum int
	}{
		{op: "ZPRFB", shift: 0, maximum: 31},
		{op: "ZPRFH", shift: 1, maximum: 62},
		{op: "ZPRFW", shift: 2, maximum: 124},
		{op: "ZPRFD", shift: 3, maximum: 248},
	} {
		shift := ""
		if spec.shift != 0 {
			shift = fmt.Sprintf("<<%d", spec.shift)
		}
		fmt.Fprintf(&source, "\t%s (Z8.D%s)(RSP), P0, PLDL1KEEP\n", spec.op, shift)
		for _, extension := range []string{"UXTW", "SXTW"} {
			fmt.Fprintf(&source, "\t%s (Z6.D.%s%s)(R14), P1, PLDL1STRM\n", spec.op, extension, shift)
			fmt.Fprintf(&source, "\t%s (Z7.S.%s%s)(R15), P2, PSTL1KEEP\n", spec.op, extension, shift)
		}
		fmt.Fprintf(&source, "\t%s (Z10.S), P3, PSTL2KEEP\n", spec.op)
		fmt.Fprintf(&source, "\t%s %d(Z10.S), P4, PSTL2STRM\n", spec.op, spec.maximum)
		fmt.Fprintf(&source, "\t%s (Z11.D), P5, PSTL3KEEP\n", spec.op)
		fmt.Fprintf(&source, "\t%s %d(Z11.D), P7, PSTL3STRM\n", spec.op, spec.maximum)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestParseARM64SVEVectorPrefetchRetainsAddressSemantics(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT parsezprf(SB),$0-0\n\tZPRFB (Z6.S.SXTW)(R14), P2, PLDL1STRM\n\tZPRFD (Z8.D<<3)(RSP), P3, PSTL3KEEP\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	first := file.Funcs[0].Instrs[1].Args[0].Mem
	if first.Base != Reg("R14") || first.Index != Reg("Z6.S") || first.IndexExt != ExtendSXTW || first.Scale != 1 {
		t.Fatalf("extended Z prefetch address parsed as %+v", first)
	}
	second := file.Funcs[0].Instrs[2].Args[0].Mem
	if second.Base != Reg("RSP") || second.Index != Reg("Z8.D") || second.IndexExt != "" || second.Scale != 8 {
		t.Fatalf("shifted Z prefetch address parsed as %+v", second)
	}
}

func TestTranslateARM64SVEVectorPrefetchCompleteGo127Family(t *testing.T) {
	source := arm64SVEVectorPrefetchCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svevectorprefetchforms": {Name: "svevectorprefetchforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.prfb.gather.index.nxv2i64",
				"@llvm.aarch64.sve.prfh.gather.uxtw.index.nxv4i32",
				"@llvm.aarch64.sve.prfw.gather.sxtw.index.nxv2i64",
				"@llvm.aarch64.sve.prfd.gather.scalar.offset.nxv2i64",
				"@llvm.aarch64.sve.prfd.gather.scalar.offset.nxv4i32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE vector prefetch lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-vector-prefetch.ll", "arm64-sve-vector-prefetch.o", ll)
		})
	}
}

func TestTranslateARM64SVEVectorPrefetchRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZPRFB (Z1.D<<1)(R0), P0, PLDL1KEEP",
		"ZPRFH (Z1.D)(R0), P0, PLDL1KEEP",
		"ZPRFW (Z1.S.SXTW<<1)(R0), P0, PLDL1KEEP",
		"ZPRFD (Z1.H.SXTW<<3)(R0), P0, PLDL1KEEP",
		"ZPRFB 32(Z1.S), P0, PLDL1KEEP",
		"ZPRFH 3(Z1.D), P0, PLDL1KEEP",
		"ZPRFW 128(Z1.S), P0, PLDL1KEEP",
		"ZPRFD 256(Z1.D), P0, PLDL1KEEP",
		"ZPRFD 8(Z1.D), P8, PLDL1KEEP",
		"ZPRFD 8(Z1.D), P0, PLIL1KEEP",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvevectorprefetch(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvevectorprefetch": {Name: "badsvevectorprefetch", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE vector prefetch forms", instruction)
			}
		})
	}
}
