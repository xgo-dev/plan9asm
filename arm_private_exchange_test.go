package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const armPrivateExchangeDecl = "func invoke(value int32) int32\n"

const armPrivateExchangeFixture = `TEXT ·invoke(SB),516,$0-8
MOVW value+0(FP),R0
MOVW R14,R8
MOVW $worker<>(SB),R7
MOVW $9,R6
CMP $0,R0
BX.NE (R7)
ADD.EQ $2,R0
ADD R6,R0
MOVW R0,ret+4(FP)
MOVW R8,R14
RET

TEXT worker<>(SB),516,$0-0
ADD $3,R0
ADD $4,R6
CMP $13,R6
RET
`

func armPrivateExchangeIR(t *testing.T, api string) string {
	t.Helper()
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	if api == "Go" {
		pkg := mustGoPackage(t, "exchange", "package exchange\n"+armPrivateExchangeDecl)
		result, err := TranslateGoModule(pkg, []byte(armPrivateExchangeFixture), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm", TargetTriple: armOfficialVFPTriple, ResolveSym: resolve,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Module.Dispose()
		return result.Module.String()
	}
	file, err := Parse(ArchARM, armPrivateExchangeFixture)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm", TargetTriple: armOfficialVFPTriple, ResolveSym: resolve,
		Sigs: map[string]FuncSig{"invoke": armLocalCallSignature("invoke")}}
	if api == "module" {
		module, err := TranslateModule(file, options)
		if err != nil {
			t.Fatal(err)
		}
		defer module.Dispose()
		return module.String()
	}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARMPrivateExchangeSharesSourceState(t *testing.T) {
	requireARMGoAssemblerResult(t, armPrivateExchangeFixture, true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir := armPrivateExchangeIR(t, api)
			if strings.Contains(ir, "worker") || strings.Contains(ir, "blx ") {
				t.Fatalf("closed private exchange emitted a separate machine/C ABI call:\n%s", ir)
			}
		})
	}
}

func TestARMPrivateExchangeNeedsClosedAddressAndLeaf(t *testing.T) {
	for _, test := range []struct{ name, from, to, want string }{
		{"caller observes address", "ADD R6,R0", "CMP R7,R0\nADD R6,R0", "observable target"},
		{"caller observes scratch", "ADD R6,R0", "CMP R11,R0\nADD R6,R0", "observable target"},
		{"overwritten target", "MOVW $9,R6", "MOVW $9,R7\nMOVW $9,R6", "observable target"},
		{"alternate entry", "CMP $0,R0", "callsite:\nCMP $0,R0", "straight-line"},
		{"leaf observes address", "ADD $4,R6", "ADD R7,R6", "incoming code address"},
		{"leaf observes stack", "ADD $4,R6", "MOVW 4(R13),R6", "zero-frame scalar leaf"},
		{"address in data", "TEXT worker", "DATA entry<>(SB)/4,$worker<>(SB)\nGLOBL entry<>(SB),8,$4\nTEXT worker", "escapes through DATA"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.Replace(armPrivateExchangeFixture, test.from, test.to, 1)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = PrepareARMPrivateExchanges(file, nil)
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("private exchange result = %v, want context containing %q", err, test.want)
			}
		})
	}
}

const armPrivateExchangeGoMain = `
package main
import "fmt"
` + armPrivateExchangeDecl + `
func main() {
	for _, value := range []int32{-17, -2, 0, 1, 1024} {
		want := value + 18
		if value == 0 { want = 11 }
		if got := invoke(value); got != want { panic(got) }
	}
	fmt.Println("private exchange preserved caller state")
}
`

const armPrivateExchangeCMain = `
extern int invoke(int);
int main(void) {
	int inputs[] = {-17, -2, 0, 1, 1024};
	for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
		int value = inputs[i];
		if (invoke(value) != (value == 0 ? 11 : value + 18)) return 1;
	}
	return 0;
}
`

func TestCrossLinuxRuntimeMatrixARMPrivateExchange(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	runARMGoSourceOracle(t, armPrivateExchangeFixture, armPrivateExchangeGoMain)
	for _, api := range []string{"text", "module", "Go"} {
		ir := armPrivateExchangeIR(t, api)
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", api, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
					"arm_private_exchange", armOfficialVFPTriple, ir, armPrivateExchangeCMain,
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
			})
		}
	}
}
