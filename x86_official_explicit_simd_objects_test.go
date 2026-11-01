package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func explicitSIMD27InitializedFunction(name, operation, arch string) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if word == 4 {
		move = "MOVL"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DX\n%s a+%d(FP),SI\n%s b+%d(FP),DI\n%s input+%d(FP),CX\nMOVOU (SI),X0\nMOVOU (DI),X1\nCMPL CX,CX\n", name, 4*word, move, move, word, move, 2*word, move, 3*word)
	// AX has exactly one role in each original form. An address used by a
	// memory form is never also used as the numerical insert source.
	if strings.Contains(operation, "(AX)") {
		source += move + " SI,AX\n"
	} else {
		source += move + " CX,AX\n"
	}
	mmx := strings.Contains(operation, "M0")
	if mmx {
		source += "MOVQ (SI),M0\n"
	}
	source += operation + "\n"
	if mmx {
		source += "EMMS\n"
	}
	source += "MOVOU X1,0(DX)\nMOVOU (SI),X2\nMOVOU X2,16(DX)\n"
	if strings.HasSuffix(operation, ",AX") {
		store := "MOVL"
		if strings.HasPrefix(operation, "PEXTRQ ") {
			store = "MOVQ"
		}
		source += store + " AX,32(DX)\n"
	}
	source += "SETCS CL\nMOVB CL,40(DX)\nSETEQ CL\nMOVB CL,41(DX)\nRET\n"
	return source, fmt.Sprintf("func %s(out *[64]byte,a,b *[16]byte,input uintptr)\n", name)
}

// Original source and byte identity precede LLVM objects. The scalar mask,
// lane memory access, old vector bytes and MMX state retain separate owners.
func TestX86LegacyExplicitSIMDInitializedThreeAPIObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := explicitSIMD27OriginalCases(t, catalog)
	for _, arch := range []string{"amd64", "386"} {
		var cases []x86OfficialPackedCase
		for _, fixture := range originals {
			op := strings.Fields(fixture.witness.Instruction)[0]
			if arch == "386" && (op == "PEXTRQ" || op == "PINSRQ") {
				continue
			}
			cases = append(cases, fixture)
		}
		x86Legacy127Objects(t, arch, cases, explicitSIMD27InitializedFunction)
	}
}
