package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const armOfficialVFPTriple = "armv7-unknown-linux-gnueabihf"

const armOfficialVFPDeclaration = "func officialvfp(selector uint32, memory *[8]uint64, out *[14]uint64)"

func armOfficialVFPSource() string {
	var source strings.Builder
	source.WriteString("TEXT officialvfp(SB),4,$0-12\nMOVW selector+0(FP),R0\nMOVW memory+4(FP),R4\nMOVW out+8(FP),R6\n")
	row := 0
	appendCase := func(before, instruction, result string) {
		source.WriteString(before + "CMP $1,R0\n" + instruction + "\n")
		fmt.Fprintf(&source, "%s%d(R6)\n", result, row*8)
		row++
	}
	const flags = "MOVW CPSR,R1\nAND $0xf0000000,R1\nMOVW R1,"
	appendCase("MOVD $3.0,F4\nMOVD $12.0,F5\n", "CMPD.CS F4, F5", flags)
	appendCase("MOVF $-3.0,F7\n", "CMPF.VS F7", flags)
	for _, stem := range []string{"ADD", "SUB", "DIV", "MUL"} {
		appendCase("MOVD $3.0,F3\nMOVD $12.0,F4\nMOVD F4,F5\n", stem+"D.EQ F3, F4, F5", "MOVD F5,")
		appendCase("MOVF $3.0,F0\nMOVF $12.0,F2\n", stem+"F.NE F0, F2", "MOVF F2,")
	}
	for _, address := range []string{"(R4)", "0x20(R4)"} {
		before := "MOVD $7.0,F8\nMOVD F8," + address + "\nMOVD $3.0,F9\n"
		appendCase(before, "MOVD.EQ F9, "+address, "MOVD "+address+",F9\nMOVD F9,")
		appendCase(before, "MOVD.EQ "+address+", F9", "MOVD F9,")
	}
	source.WriteString("RET\n")
	return source.String()
}

func armOfficialVFPIR(t *testing.T, source string) string {
	t.Helper()
	pkg := mustGoPackage(t, "predicatedarm", "package predicatedarm\n"+armOfficialVFPDeclaration+"\n")
	translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm", TargetTriple: armOfficialVFPTriple,
		ResolveSym: func(symbol string) string {
			return strings.TrimPrefix(goStripABISuffix(symbol), "·")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translated.Module.Dispose()
	return translated.Module.String()
}

func TestARMOfficialPredicatedVFPObjects(t *testing.T) {
	source := armOfficialVFPSource()
	requireARMGoAssemblerResult(t, source, true)
	ir := armOfficialVFPIR(t, source)
	if !strings.Contains(ir, "define void @officialvfp(") {
		t.Fatal("original predicated VFP fixture is missing from the module")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	compileLLVMToObject(t, llc, armOfficialVFPTriple, "official-vfp.ll", "official-vfp.o", ir)
	compileLLVMToObject(t, llc, armOfficialVFPTriple, "official-vfp-opt.ll", "official-vfp-opt.o", armFloatEffectOptimizedIR(t, ir))
}
