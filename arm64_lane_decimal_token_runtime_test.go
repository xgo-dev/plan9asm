package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64LaneDecimalTokens(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	decl, original, source := arm64LaneTokenProgram()
	pkg := mustGoPackage(t, "test/lanetokenruntime", "package tokenruntime\n"+decl)
	result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Module.Dispose()

	var goChecks, cDecl, cChecks strings.Builder
	number := 0
	for _, tc := range arm64LaneTokenCases() {
		if !tc.accepted {
			continue
		}
		for form := 0; form < 3; form++ {
			fmt.Fprintf(&cDecl, "extern uint64_t Token%d(uint64_t);\n", number)
			goWant, cWant := "a & 255", "a & UINT64_C(255)"
			if form == 2 {
				goWant = "repeated"
				cWant = "(a & UINT64_C(255)) * UINT64_C(0x0101010101010101)"
			}
			fmt.Fprintf(&goChecks, "    if got := Token%d(a); got != %s { panic(\"Go lane-token case %d\") }\n", number, goWant, number)
			fmt.Fprintf(&cChecks, "        if (Token%d(a) != (%s)) { fprintf(stderr, \"LLVM lane-token case %d input %%u\\n\",i); return 1; }\n", number, cWant, number)
			number++
		}
	}
	if number != 27 {
		t.Fatalf("accepted-function denominator changed: %d", number)
	}
	goMain := "package main\n" + decl + `
func main() {
    for _, a := range []uint64{0, 1, 0x123456789abcdef0, 0x8000000000000000, ^uint64(0)} {
        var repeated uint64
        for shift := uint(0); shift < 64; shift += 8 {
            repeated |= (a & 255) << shift
        }
` + goChecks.String() + `
    }
}
`
	// Same lane instructions, explicitly distinct ordinary-Go and translated
	// register transports. This does not certify any external native caller.
	runARM64LocalRegisterGoOracle(t, original, goMain, len(runner) != 0, "1.20")
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + `
int main(void) {
    const uint64_t inputs[] = {0, 1, UINT64_C(0x123456789abcdef0),
        UINT64_C(0x8000000000000000), UINT64_MAX};
    const volatile uint64_t canary = UINT64_C(0x8718369423719654);
    for (unsigned i = 0; i < 5; i++) {
        uint64_t a = inputs[i];
` + cChecks.String() + `
    }
    if (canary != UINT64_C(0x8718369423719654)) return 2;
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "lane_decimal_token", triple, result.Module.String(), cMain, runner)
}
