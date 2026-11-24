package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const armLocalCallOracle = `TEXT oracle(SB),516,$0-8
	MOVW value+0(FP),R0
	MOVW R14,R8
	CMP $0,R0
	BL.EQ helper
	ADD.NE $3,R0
	MOVW.NE R0,ret+4(FP)
	RET.NE
	CALL helper
	MOVW R8,R14
	MOVW R0,ret+4(FP)
	RET
helper:
	MOVW R14,R9
	BL inner
	MOVW R9,R7
	MOVW R9,R14
	B (R7)
inner:
	ADD $3,R0
	ADD.EQ $5,R0
	RET
`

func armLocalCallSignature(name string) FuncSig {
	return FuncSig{
		Name: name, Args: []LLVMType{I32}, Ret: I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Index: 0, Type: I32, Field: -1}},
			Results: []FrameSlot{{Offset: 4, Index: 0, Type: I32, Field: -1}},
		},
	}
}

func TestARMNamedLocalCallContinuationObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	sigs := map[string]FuncSig{"oracle": armLocalCallSignature("oracle")}
	for index, source := range []string{armLocalCallOracle, `TEXT oracle(SB),4,$0-8
	MOVW value+0(FP),R0
	BL 3(PC)
	MOVW R0,ret+4(FP)
	RET
	ADD $3,R0
	B (R14)
`, `TEXT oracle(SB),516,$0-8
	B setup
	ADD $3,R0
	B (R14)
setup:
	MOVW value+0(FP),R0
	MOVW R14,R8
	CALL -4(PC)
	MOVW R8,R14
	MOVW R0,ret+4(FP)
	RET
`, `TEXT oracle(SB),4,$0-8
	MOVW value+0(FP),R0
	B 0(PC)
	MOVW R0,ret+4(FP)
	RET
`, `TEXT oracle(SB),4,$0-8
	MOVW value+0(FP),R0
	BL 0(PC)
	MOVW R0,ret+4(FP)
	RET
`, `TEXT oracle(SB),4,$0-8
	MOVW value+0(FP),R0
	CMP $0,R0
	BL.LE 1(PC)
	ADD $7,R0
	MOVW R0,ret+4(FP)
	RET
`} {
		t.Run(fmt.Sprintf("case%d", index), func(t *testing.T) {
			requireARMGoAssemblerResult(t, source, true)
			ir := translateARMCompleteForms(t, source, sigs)
			compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "local-call.ll", "local-call.o", ir)
		})
	}
}

func TestARMNamedLocalCallConditionForms(t *testing.T) {
	var assembly strings.Builder
	sigs := make(map[string]FuncSig)
	for index, condition := range []string{"", "AL", "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE"} {
		op := "BL"
		if condition != "" {
			op += "." + condition
		}
		name := fmt.Sprintf("condition%d", index)
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-8\nMOVW value+0(FP),R0\nCMP $0,R0\n%s 3(PC)\n", name, op)
		assembly.WriteString("MOVW R0,ret+4(FP)\nRET\nADD $3,R0\nB (R14)\n")
		sigs[name] = armLocalCallSignature(name)
	}
	requireARMGoAssemblerResult(t, assembly.String(), true)
	translateARMCompleteForms(t, assembly.String(), sigs)
}

func TestARMOfficialLocalControlObjects(t *testing.T) {
	corpus := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata", "arm.s")
	data, err := os.ReadFile(corpus)
	if err != nil {
		t.Fatal(err)
	}
	branch := regexp.MustCompile(`^B(?:L(?:\.[A-Z]{2})?|\.[A-Z]{2}|[A-Z]{2})?\s+(?:[+-]?\d+\(PC\)|jmp_label_\d+)$`)
	var source strings.Builder
	var names []string
	sigs := make(map[string]FuncSig)
	for _, line := range strings.Split(string(data), "\n") {
		code, _, _ := strings.Cut(line, "//")
		instruction := strings.TrimSpace(code)
		if !branch.MatchString(instruction) {
			continue
		}
		name := fmt.Sprintf("official%d", len(names))
		names = append(names, name)
		sigs[name] = armLocalCallSignature(name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVW value+0(FP),R0\nCMP $0,R0\n", name)
		source.WriteString(armOfficialLocalControlBody(t, instruction))
	}
	if len(names) != 85 {
		t.Fatalf("found %d original local ARM branches, want 85", len(names))
	}
	requireARMGoAssemblerResult(t, source.String(), true)
	ir := translateARMCompleteForms(t, source.String(), sigs)
	for _, name := range names {
		if !strings.Contains(ir, "define i32 @"+name+"(") {
			t.Fatalf("missing original local ARM control function %s", name)
		}
	}
}

func armOfficialLocalControlBody(t *testing.T, instruction string) string {
	t.Helper()
	const result = "MOVW R0,ret+4(FP)\nRET\n"
	const helper = "ADD $3,R0\nB (R14)\n"
	const pad = "ADD $1,R0\n"
	fields := strings.Fields(instruction)
	opcode, _, _ := strings.Cut(fields[0], ".")
	target := fields[1]
	instruction += "\n"
	link := opcode == "BL"

	number, relative := strings.CutSuffix(target, "(PC)")
	if !relative {
		if link {
			return instruction + result + target + ":\n" + helper
		}
		return instruction + pad + target + ":\n" + result
	}
	offset, err := strconv.Atoi(number)
	if err != nil || offset < -16 || offset > 16 {
		t.Fatalf("unexpected original ARM PC offset %q", target)
	}
	switch {
	case offset < 0:
		return strings.Repeat(pad, -offset) + instruction + result
	case link && offset >= 3:
		return instruction + result + strings.Repeat(pad, offset-3) + helper
	case link:
		return instruction + pad + result
	case offset > 1:
		return instruction + strings.Repeat(pad, offset-1) + result
	default:
		return instruction + result
	}
}

func TestARMNamedLocalCallRejectsUnprovedLinkUse(t *testing.T) {
	for _, body := range []string{
		"MOVW R14, ret+4(FP)\nB (R14)", // Observed code address.
		"ADD $4, R14\nB (R14)",         // Changed continuation.
		"MOVW $1,R14\nB (R14)",         // Native register branch.
		"MOVW R14,R11\nB (R11)",        // Go can use R11 for instruction expansion.
	} {
		source := "TEXT oracle(SB),4,$0-8\nBL helper\nRET\nhelper:\n" + body + "\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"oracle": armLocalCallSignature("oracle")}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%q: expected a link context error, got %v", body, err)
		}
	}
}

type armCallerLinkReturnCase struct {
	op, condition, frame string
	copied               bool
}

func armCallerLinkReturnCases() []armCallerLinkReturnCase {
	cases := []armCallerLinkReturnCase{
		{"B", "", "516,$0", false}, {"B", "", "4,$0", true},
		{"B", "AL", "4,$-4", true}, {"JMP", "", "4,$0", false},
		{"JMP", "AL", "516,$0", true}, {"BX", "", "516,$0", false},
	}
	for _, condition := range []string{
		"AL", "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE",
	} {
		cases = append(cases, armCallerLinkReturnCase{"BX", condition, "516,$0", true})
	}
	return cases
}

func (row armCallerLinkReturnCase) source(name string) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),%s-8\nMOVW value+0(FP),R0\n", name, row.frame)
	link := "R14"
	if row.copied {
		source.WriteString("MOVW R14,R7\nMOVW R7,R8\n")
		link = "R8"
	}
	op := row.op
	if row.condition != "" {
		op += "." + row.condition
	}
	fmt.Fprintf(&source, "CMP $1,R0\nADD $3,R0\nMOVW R0,ret+4(FP)\n%s (%s)\n", op, link)
	if row.condition != "" && row.condition != "AL" {
		source.WriteString("ADD $5,R0\nMOVW R0,ret+4(FP)\nRET\n")
	}
	return source.String()
}

func TestARMCallerLinkReturnObjects(t *testing.T) {
	source, _ := armCallerLinkReturnFixture()
	requireARMGoAssemblerResult(t, source, true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir := armCallerLinkReturnIR(t, api, source)
			if strings.Contains(ir, `asm sideeffect "bx $0"`) {
				t.Fatal("ordinary caller return branched through a synthesized register")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc is required")
			}
			compileLLVMToObject(t, llc, armOfficialVFPTriple, api+".ll", api+".o", ir)
		})
	}
}

func TestARMCallerLinkReturnRejectsMissingProof(t *testing.T) {
	const name = "bad"
	base := (armCallerLinkReturnCase{"B", "", "516,$0", true}).source(name)
	for _, row := range []struct{ name, source, diagnostic string }{
		{"overwritten", strings.Replace(base, "B (R8)", "MOVW $4,R8\nB (R8)", 1), "has no proven register link"},
		{"stack-frame", strings.Replace(base, "516,$0-8", "4,$4-8", 1), "cannot exit through this caller link"},
		{"address-as-data", strings.Replace(base, "MOVW R0,ret+4(FP)", "MOVW R14,ret+4(FP)", 1), "observes a code address"},
		{"address-offset", strings.Replace(base, "B (R8)", "B 4(R8)", 1), "requires a zero-offset link register"},
		{"local-exchange", strings.ReplaceAll(armLocalCallOracle, "B (R7)", "BX (R7)"), "BX rewrites LR"},
	} {
		t.Run(row.name, func(t *testing.T) {
			requireARMGoAssemblerResult(t, row.source, true)
			file, err := Parse(ArchARM, row.source)
			if err != nil {
				t.Fatal(err)
			}
			sigs := make(map[string]FuncSig)
			for _, fn := range file.Funcs {
				sigs[fn.Sym] = armLocalCallSignature(fn.Sym)
			}
			_, err = Translate(file, Options{Goarch: "arm", TargetTriple: armOfficialVFPTriple, Sigs: sigs})
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), row.diagnostic) {
				t.Fatalf("want caller-link diagnostic %q, got %v", row.diagnostic, err)
			}
		})
	}
}

func TestARMCallerLinkReturnIgnoresUnrelatedBranches(t *testing.T) {
	source := `TEXT tail(SB),516,$0-0
MOVW R14,R7
MOVW R7,R8
B (R6)
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	if call, ret := armLinkControlCandidates(file.Funcs[0]); call || ret {
		t.Fatal("a separate return-link copy captured an unrelated register branch")
	}
}

func armCallerLinkReturnFixture() (string, string) {
	var source, declarations strings.Builder
	for index, row := range armCallerLinkReturnCases() {
		name := fmt.Sprintf("callerlink%d", index)
		source.WriteString(row.source(name))
		fmt.Fprintf(&declarations, "func %s(value int32) int32\n", name)
	}
	return source.String(), declarations.String()
}

func armCallerLinkReturnIR(t *testing.T, api, source string) string {
	t.Helper()
	_, declarations := armCallerLinkReturnFixture()
	pkg := mustGoPackage(t, "callerlinks", "package callerlinks\n"+declarations)
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	if api == "Go" {
		translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm", TargetTriple: armOfficialVFPTriple, ResolveSym: resolve,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer translated.Module.Dispose()
		return translated.Module.String()
	}
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm", TargetTriple: armOfficialVFPTriple, ResolveSym: resolve, Sigs: sigs}
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

func TestCrossLinuxRuntimeMatrixARMNamedLocalCall(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	runARMGoSourceOracle(t, armLocalCallOracle, `package main
import "fmt"
func oracle(value int32) int32
func main() {
	for _, value := range []int32{0, 1, -1, 42, -42} {
		want := value + 3
		if value == 0 { want = 16 }
		if got := oracle(value); got != want { panic(fmt.Sprintf("oracle(%d) = %d, want %d", value, got, want)) }
	}
	fmt.Println("original Go local calls matched")
}
`)
	ir := translateARMCompleteForms(t, armLocalCallOracle, map[string]FuncSig{"oracle": armLocalCallSignature("oracle")})
	const mainC = `
#include <stdint.h>
#include <stdio.h>
extern int32_t oracle(int32_t);
int main(void) {
	int32_t inputs[] = {0, 1, -1, 42, -42};
	for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
		const int32_t value = inputs[i];
		const int32_t want = value == 0 ? 16 : value + 3;
		const int32_t got = oracle(value);
		if (got == want) continue;
		fprintf(stderr, "oracle(%d) = %d, want %d\n", value, got, want);
		return 1;
	}
	return 0;
}
`
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
				"arm_named_local_call", "armv7-unknown-linux-gnueabihf", ir, mainC,
				[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
		})
	}
	t.Run("CallerLinkReturns", func(t *testing.T) {
		source, declarations := armCallerLinkReturnFixture()
		goMain, cMain := armCallerLinkReturnDrivers(declarations)
		runARMGoSourceOracle(t, source, goMain)
		for _, api := range []string{"text", "module", "Go"} {
			ir := armCallerLinkReturnIR(t, api, source)
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/O%d", api, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
						"arm_caller_links", armOfficialVFPTriple, ir, cMain,
						[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
				})
			}
		}
	})
}

func armCallerLinkReturnDrivers(declarations string) (string, string) {
	var goMain, cDeclarations, cMain strings.Builder
	goMain.WriteString("package main\nimport \"fmt\"\n" + declarations + "func main() {\n")
	cMain.WriteString("int main(void) {\n")
	for index, row := range armCallerLinkReturnCases() {
		name := fmt.Sprintf("callerlink%d", index)
		fmt.Fprintf(&cDeclarations, "extern int32_t %s(int32_t);\n", name)
		for _, value := range []int32{0, 1, 2, -1, -2147483648, 2147483647} {
			want := armCallerLinkReturnExpected(row.condition, value)
			fmt.Fprintf(&goMain, "if got := %s(%d); got != %d { panic(fmt.Sprintf(%q, got)) }\n",
				name, value, want, fmt.Sprintf("%s(%d) = %%d, want %d", name, value, want))
			fmt.Fprintf(&cMain, "if (%s((int32_t)%#x) != (int32_t)%#x) { fputs(%q, stderr); return 1; }\n",
				name, uint32(value), uint32(want), fmt.Sprintf("%s(%d) want %d\n", name, value, want))
		}
	}
	goMain.WriteString("fmt.Println(\"ARM caller links matched\")\n}\n")
	cMain.WriteString("return 0;\n}\n")
	return goMain.String(), "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() + cMain.String()
}

// The fixture compares value with 1 before the branch. The expected signed
// and unsigned relations are independent of the translator's condition code.
func armCallerLinkReturnExpected(condition string, value int32) int32 {
	taken := true
	switch condition {
	case "EQ":
		taken = value == 1
	case "NE":
		taken = value != 1
	case "CS", "HS":
		taken = uint32(value) >= 1
	case "CC", "LO":
		taken = uint32(value) < 1
	case "MI":
		taken = value-1 < 0
	case "PL":
		taken = value-1 >= 0
	case "VS":
		taken = value == -2147483648
	case "VC":
		taken = value != -2147483648
	case "HI":
		taken = uint32(value) > 1
	case "LS":
		taken = uint32(value) <= 1
	case "GE":
		taken = value >= 1
	case "LT":
		taken = value < 1
	case "GT":
		taken = value > 1
	case "LE":
		taken = value <= 1
	}
	if taken {
		return value + 3
	}
	return value + 8
}
