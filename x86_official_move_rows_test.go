package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialMoveRowsThreeAPIsObjectsAndTerminalFaults(t *testing.T) {
	cases := x86OfficialPackedRowsObjectsInspect(t, goasmrules.X86PackedMoveRows, 144, 306, 0,
		x86OfficialMoveAssembly, x86OfficialMoveInspectFaults)
	faults, copies := 0, 0
	for _, fixture := range cases {
		if fixture.witness.Zeroing && fixture.witness.Destination == "(AX)" {
			faults++
		}
		if !fixture.witness.Memory && fixture.witness.Destination != "(AX)" {
			copies++
		}
	}
	if faults != 30 || len(cases)-faults != 276 || copies != 102 {
		t.Fatal("ordinary moves, terminal #UD and actual selected register rows were conflated", len(cases), faults, copies)
	}
	t.Log("AVX-only: 144 rows / 276 ordinary initialized witnesses + 30 terminal #UD controls; legacy remains separate")
}

func x86OfficialMoveAssembly(cases []x86OfficialPackedCase) (string, string) {
	var source, declarations strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprint("MoveRow", index)
		w := fixture.witness
		var body, declaration string
		if w.Zeroing && w.Destination == "(AX)" {
			body = x86PackedZeroStoreInstruction("·"+fixture.symbol, w.Instruction)
			declaration = fmt.Sprintf("func %s()\n", fixture.symbol)
		} else {
			result := w.Destination
			if result == "(AX)" {
				result = w.First
			}
			initialization := fmt.Sprintf("VMOVUPS (AX),Z%s\n", result[1:])
			if !w.Memory && w.Destination != "(AX)" {
				initialization = fmt.Sprintf("VMOVUPS (AX),Z%s\n", w.First[1:]) + initialization
			}
			body, declaration = x86PackedMoveInitializedInstruction(fixture.symbol, "amd64", initialization, w.Instruction, "VMOVD X"+result[1:]+",CX")
		}
		for offset, instruction := range strings.Split(body, "\n") {
			if instruction == w.Instruction {
				fixture.line = line + offset
			}
		}
		source.WriteString(body)
		declarations.WriteString(declaration)
		line += strings.Count(body, "\n")
	}
	return source.String(), declarations.String()
}

func x86OfficialMoveInspectFaults(t *testing.T, ir string, cases []x86OfficialPackedCase) {
	t.Helper()
	for _, fixture := range cases {
		w := fixture.witness
		if !w.Zeroing || w.Destination != "(AX)" {
			continue
		}
		body, err := x86OfficialMoveFaultBody(ir, fixture.symbol)
		if err != nil {
			t.Fatal("terminal move lost its owned no-input #UD before object compilation", fixture.row, err)
		}
		t.Logf("terminal row=%s symbol=%s bodySHA=%x; one UD2, unreachable, zero input loads", fixture.row, fixture.symbol, sha256.Sum256([]byte(body)))
	}
}

func x86OfficialMoveFaultBody(ir, symbol string) (string, error) {
	definition := regexp.MustCompile(`(?m)^define [^\n]*@` + regexp.QuoteMeta(symbol) + `\(\)[^\n]*\{\n`).FindStringIndex(ir)
	if definition == nil {
		return "", fmt.Errorf("fault definition %s has inputs or is absent", symbol)
	}
	body, _, closed := strings.Cut(ir[definition[1]:], "\n}")
	trap := `call void asm sideeffect "ud2", "~{memory}"()`
	if !closed || strings.Count(body, trap) != 1 || !strings.HasSuffix(strings.TrimSpace(body), "unreachable") ||
		strings.Contains(body, "load ") || strings.Contains(body, "@llvm.masked.") {
		return "", fmt.Errorf("fault body %s lost its terminal no-input UD2: %s", symbol, body)
	}
	return body, nil
}

func TestX86OfficialMoveFaultInspectionRejectsAnotherFunctionsTrap(t *testing.T) {
	const trap = "  call void asm sideeffect \"ud2\", \"~{memory}\"()\n  unreachable"
	const valid = "define void @Fault() {\nentry:\n" + trap + "\n}\n"
	if _, err := x86OfficialMoveFaultBody(valid, "Fault"); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, "@Fault", "@Other", 1) + "define void @Fault() {\n  ret void\n}\n",
		strings.Replace(valid, "@Fault()", "@Fault(i64 %mask)", 1),
		strings.Replace(valid, trap, "  %x = load i64, ptr null\n"+trap, 1),
		strings.Replace(valid, "unreachable", "ret void", 1),
		strings.Replace(valid, trap, trap+"\n"+trap, 1),
	} {
		if _, err := x86OfficialMoveFaultBody(invalid, "Fault"); err == nil {
			t.Fatal("module-wide trap or input read substituted for the original terminal function", invalid)
		}
	}
}
