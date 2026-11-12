package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This inventory is independent of x86StringSpecs. It describes architectural
// memory accesses, not initialized pointee bytes or permission to perform them.
type x86StringMemoryRow struct {
	op, kind      string
	width         int
	reads, writes int
}

func x86StringMemoryRows() []x86StringMemoryRow {
	var rows []x86StringMemoryRow
	for _, family := range []struct {
		name, kind    string
		reads, writes int
	}{
		{"MOVS", "movs", 1, 1},
		{"STOS", "stos", 0, 1},
		{"SCAS", "scas", 1, 0},
		{"CMPS", "cmps", 2, 0},
		{"LODS", "lods", 1, 0},
	} {
		for _, width := range []struct {
			suffix string
			bytes  int
		}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
			rows = append(rows, x86StringMemoryRow{
				family.name + width.suffix, family.kind, width.bytes,
				family.reads, family.writes,
			})
		}
	}
	return rows
}

func x86StringMemoryModeRows(arch string) []x86StringMemoryRow {
	var rows []x86StringMemoryRow
	for _, row := range x86StringMemoryRows() {
		if arch != "386" || row.width != 8 {
			rows = append(rows, row)
		}
	}
	return rows
}

func x86StringMemoryHelper(row x86StringMemoryRow) string {
	prefix := "__plan9asm_rep_"
	if row.kind == "movs" {
		prefix = "__plan9asm_"
	}
	return prefix + strings.ToLower(row.op)
}

// These generated identifiers contain only ASCII letters, digits and '_'.
// Accept either of LLVM's equivalent quoted/unquoted identifier renderings.
func x86StringMemoryFunction(t testing.TB, ir, name string) string {
	t.Helper()
	head := regexp.MustCompile(`(?m)^define [^\n]* @(?:"` + regexp.QuoteMeta(name) + `"|` + regexp.QuoteMeta(name) + `)\(`)
	locations := head.FindAllStringIndex(ir, -1)
	if len(locations) != 1 {
		t.Fatalf("complete function %q appears %d times", name, len(locations))
	}
	rest := ir[locations[0][0]:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatal("unterminated complete function", name)
	}
	return rest[:end+2]
}

// The returned bodies are local test observations, never reusable source,
// frame, caller-memory or native-entry permissions.
func x86StringMemoryFunctions(t testing.TB, ir string, names []string) map[string]string {
	t.Helper()
	// Parse once and use LLVM's own symbol index rather than scanning the
	// whole module with a fresh matcher for every requested definition.
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal("complete function index requires valid LLVM IR", err)
	}
	bodies := make(map[string]string, len(names))
	for _, name := range names {
		if _, duplicate := bodies[name]; duplicate {
			t.Fatal("duplicate expected complete function", name)
		}
		function := module.NamedFunction(name)
		if function.IsNil() || function.IsDeclaration() || function.BasicBlocksCount() == 0 {
			t.Fatal("missing complete indexed function", name)
		}
		bodies[name] = function.String()
	}
	return bodies
}

func x86StringMemoryHelperIR(t *testing.T, row x86StringMemoryRow) string {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT helper(SB),4,$0-0\n"+row.op+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	var ir strings.Builder
	emitX86StringHelpers(&ir, file)
	return x86StringMemoryFunction(t, ir.String(), x86StringMemoryHelper(row))
}

func TestX86StringImplicitMemoryIndependentFamilyEffects(t *testing.T) {
	rows := x86StringMemoryRows()
	if len(rows) != 20 {
		t.Fatal("all five families and four widths must remain independently covered")
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		if seen[row.op] {
			t.Fatal("duplicate original spelling", row.op)
		}
		seen[row.op] = true
		for _, arch := range []string{"386", "amd64"} {
			form, known, err := x86StringInstructionProperties(Instr{Op: Op(row.op), Raw: row.op}, arch)
			invalid := arch == "386" && row.width == 8
			if !known || (err != nil) != invalid || form.kind != row.kind ||
				form.width != row.width || form.typ != LLVMType(fmt.Sprintf("i%d", 8*row.width)) {
				t.Fatal("typed grammar disagrees with independent mode/width inventory", arch, row, form, err)
			}
		}
	}
	if len(x86StringMemoryModeRows("386")) != 15 || len(x86StringMemoryModeRows("amd64")) != 20 {
		t.Fatal("mode filtering lost a complete family")
	}
}

func TestX86StringImplicitHelpersKeepObservableNativeAccesses(t *testing.T) {
	for _, row := range x86StringMemoryRows() {
		t.Run(row.op, func(t *testing.T) {
			ir := x86StringMemoryHelperIR(t, row)
			typ := fmt.Sprintf("i%d", 8*row.width)
			reads := strings.Count(ir, " = load volatile "+typ+", ptr ")
			writes := regexp.MustCompile(`(?m)^  store volatile `+typ+` [^\n]+, ptr [^\n]+, align 1$`).FindAllString(ir, -1)
			if reads != row.reads || len(writes) != row.writes {
				t.Fatalf("dead outputs must retain every original exact-width native access: got read/write %d/%d, want %d/%d\n%s",
					reads, len(writes), row.reads, row.writes, ir)
			}
			if regexp.MustCompile(`(?m)^  (?:%[^ ]+ = load|store) i\d+ `).MatchString(ir) {
				t.Fatal("ordinary nonvolatile native access remains in the string helper", ir)
			}
		})
	}
}

func TestX86StringImplicitHelpersGuardZeroCountBeforeMemory(t *testing.T) {
	for _, row := range x86StringMemoryRows() {
		t.Run(row.op, func(t *testing.T) {
			ir := x86StringMemoryHelperIR(t, row)
			condition, empty, body := "empty", "empty_exit", "scan"
			if row.kind == "movs" || row.kind == "stos" {
				condition, empty, body = "done", "exit", "body"
			} else if row.kind == "lods" {
				body = "load"
			}
			gate := fmt.Sprintf("%%%s = icmp eq i64 %%left, 0\n  br i1 %%%s, label %%%s, label %%%s",
				condition, condition, empty, body)
			gateAt, bodyAt := strings.Index(ir, gate), strings.Index(ir, "\n"+body+":\n")
			if !strings.Contains(ir, "[ %count, %entry ]") || gateAt < 0 || bodyAt <= gateAt {
				t.Fatal("zero count must branch around every memory access", ir)
			}
			emptyAt := strings.Index(ir, "\n"+empty+":\n")
			if emptyAt <= bodyAt || strings.Contains(ir[emptyAt:], " load ") || strings.Contains(ir[emptyAt:], " store ") {
				t.Fatal("empty path performed a memory access", ir)
			}
			if row.kind == "scas" || row.kind == "cmps" || row.kind == "lods" {
				if !strings.Contains(ir[emptyAt:], "i1 false") {
					t.Fatal("zero iterations must not claim an executed comparison/load", ir)
				}
			}
		})
	}
}

func x86StringMemoryFixture(rows []x86StringMemoryRow, arch, prefix string, count int, backward bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	for _, row := range rows {
		name := "stringmem_" + strings.ToLower(row.op)
		fmt.Fprintf(&declarations, "func %s(dst, src *byte, mode uint32)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s dst+0(FP),DI\n%s src+%d(FP),SI\n",
			name, 2*word+4, move, move, word)
		fmt.Fprintf(&source, "MOVL mode+%d(FP),BX\nMOVL $19,AX\nMOVL $%d,CX\nCLD\n", 2*word, count)
		if backward {
			source.WriteString("STD\n")
		}
		if prefix != "" {
			source.WriteString(prefix + "\n")
		}
		source.WriteString(row.op + "\n")
		// Every implicit result is genuinely dead. The source has a real void
		// declaration; this is not an uninitialized nonvoid result fixture.
		source.WriteString("MOVL $0,AX\nMOVL $0,CX\nMOVL $0,SI\nMOVL $0,DI\nCLD\nRET\n")
	}
	return source.String(), declarations.String()
}

func TestX86StringImplicitMemoryDoesNotGrantResultOrPointerAuthority(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86StringMemoryModeRows(arch) {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				body := fmt.Sprintf("%s dst+0(FP),DI\n%s src+%d(FP),SI\nMOVL $1,CX\nMOVL $19,AX\nCLD\nREP\n%s\nMOVL $7,ret+%d(FP)\nRET",
					move, move, word, row.op, 2*word)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(dst,src *byte) uint32", body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("syntax and paired lowering cannot create public pointee/caller-write/string-loop authority", err)
				}
			})
		}
	}
}
