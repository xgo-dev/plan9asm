package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// ABI0 starts the result area at a word boundary, even for a uint32 parameter.
// Actual Go asmdecl independently checks both target modes below. This helper
// changes only the original-Go fixture's layout, not any translated program.
func x86OriginalNativeMXCSRSource(arch string) string {
	result := goWordSize(arch)
	return fmt.Sprintf("TEXT ·MXCSR(SB),4,$0-%d\nSTMXCSR ret+%d(FP)\nLDMXCSR value+0(FP)\nRET\n", result+4, result)
}

func x86NativeFixtureASMDecl(t *testing.T, arch, declarations, source string, diagnostic string) {
	t.Helper()
	driver, _ := x86LEAActualSDKDriver(t)
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":               "module oracle\n\ngo 1.20\n",
		"value.go":             "package oracle\n" + declarations,
		"value_" + arch + ".s": source,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "vet", "-asmdecl", "-p=1", ".")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0",
		"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOMAXPROCS=2")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if diagnostic == "" {
		if err != nil {
			t.Fatalf("actual Go %s asmdecl rejected the callable original fixture: %v\n%s", arch, err, output)
		}
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || ctx.Err() != nil ||
		!strings.Contains(string(output), diagnostic) || !strings.Contains(string(output), "value_"+arch+".s:") {
		t.Fatalf("source-bound actual asmdecl rejection missing (not infrastructure): %v\n%s", err, output)
	}
	t.Logf("actual Go asmdecl arch=%s source-sha256=%x expected-diagnostic=%q", arch, sha256.Sum256([]byte(source)), diagnostic)
}

func x86NativeIndependentReturnLayout(arch string, bytes int) (string, string, int) {
	word := 8
	if arch == "386" {
		word = 4
	}
	offset := (bytes + word - 1) / word * word
	declaration := fmt.Sprintf("func Copy(bits uint%d) (ret uint%d)\n", bytes*8, bytes*8)
	body := fmt.Sprintf("TEXT ·Copy(SB),4,$0-%d\n", offset+bytes)
	if bytes == 8 && arch == "386" {
		body += fmt.Sprintf("MOVL bits_lo+0(FP),AX\nMOVL AX,ret_lo+%d(FP)\nMOVL bits_hi+4(FP),AX\nMOVL AX,ret_hi+%d(FP)\n", offset, offset+4)
	} else {
		move := map[int]string{1: "MOVB", 2: "MOVW", 4: "MOVL", 8: "MOVQ"}[bytes]
		body += fmt.Sprintf("%s bits+0(FP),AX\n%s AX,ret+%d(FP)\n", move, move, offset)
	}
	return body + "RET\n", declaration, offset
}

func TestX86OriginalNativeABI0ReturnLayoutActualGoPrior(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, bytes := range []int{1, 2, 4, 8} {
			t.Run(fmt.Sprintf("%s/uint%d", arch, bytes*8), func(t *testing.T) {
				source, declaration, offset := x86NativeIndependentReturnLayout(arch, bytes)
				goAssemblerOracleOutput(t, arch, source, "", true)
				x86NativeFixtureASMDecl(t, arch, declaration, source, "")
				result := "ret"
				if arch == "386" && bytes == 8 {
					result = "ret_lo"
				}
				wrong := strings.Replace(source, fmt.Sprintf("%s+%d(FP)", result, offset), fmt.Sprintf("%s+%d(FP)", result, offset-1), 1)
				x86NativeFixtureASMDecl(t, arch, declaration, wrong, fmt.Sprintf("invalid offset %s+%d(FP)", result, offset-1))
				wrong = strings.Replace(source, fmt.Sprintf("$0-%d", offset+bytes), fmt.Sprintf("$0-%d", offset+bytes+1), 1)
				x86NativeFixtureASMDecl(t, arch, declaration, wrong, "wrong argument size")
			})
		}
	}
}

func TestX86OriginalNativeUint32HelpersMatchActualGoABI0(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		// This prior must complete before asking anything about fixture output.
		prior, declaration, _ := x86NativeIndependentReturnLayout(arch, 4)
		x86NativeFixtureASMDecl(t, arch, declaration, prior, "")
		references, declarations := x86ScalarReciprocalOriginalReferences(arch)
		for _, family := range []struct{ name, source, declaration string }{
			{"duplicate-MXCSR", x86OriginalNativeMXCSRSource(arch), "func MXCSR(value uint32) uint32\n"},
			{"reciprocal-all-four-and-MXCSR", references, declarations},
		} {
			t.Run(arch+"/"+family.name, func(t *testing.T) {
				t.Logf("actual original fixture arch=%s family=%s source-sha256=%x", arch, family.name, sha256.Sum256([]byte(family.source)))
				goAssemblerOracleOutput(t, arch, family.source, "", true)
				x86NativeFixtureASMDecl(t, arch, family.declaration, family.source, "")
			})
		}
	}
}

func x86NativeSegmentQuerySourceFormat(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "x86_segment_query_runtime_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var literal func(ast.Expr) string
	literal = func(expression ast.Expr) string {
		switch value := expression.(type) {
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				text, err := strconv.Unquote(value.Value)
				if err != nil {
					t.Fatal(err)
				}
				return text
			}
		case *ast.BinaryExpr:
			if value.Op == token.ADD {
				return literal(value.X) + literal(value.Y)
			}
		}
		return ""
	}
	var formats []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		format := literal(call.Args[1])
		if strings.Contains(format, "MOVQ selector+8(FP),AX") && strings.Contains(format, "LAHF\nMOVB AH,8(DI)") {
			formats = append(formats, format)
		}
		return true
	})
	if len(formats) != 1 {
		t.Fatal("actual segment-query source producer lost its unambiguous original format", len(formats))
	}
	return formats[0]
}

func TestX86OriginalNativeSegmentQueryUsesCompleteGoSETccSpelling(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{ASET([A-Z]+), yscond, Pb, opBytes\{0x0f, (0x[0-9a-f]+), 00\}\}`).FindAllStringSubmatch(string(data), -1)
	conditions := []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"}
	opcodes := []string{"0x93", "0x92", "0x94", "0x9d", "0x9f", "0x97", "0x9e", "0x96", "0x9c", "0x98", "0x95", "0x91", "0x90", "0x9b", "0x99", "0x9a"}
	if len(rows) != len(conditions) {
		t.Fatal("complete official yscond directory changed", len(rows))
	}
	var prior strings.Builder
	for index, row := range rows {
		if row[1] != conditions[index] || row[2] != opcodes[index] {
			t.Fatal("official SETcc opcode or complete spelling changed", row)
		}
		fmt.Fprintf(&prior, "TEXT ·Condition%d(SB),4,$0-0\nSET%s AL\nRET\n", index, row[1])
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil || regexp.MustCompile(`instructions\["SET`).Match(aliases) {
		t.Fatal("Go SETcc alias namespace changed; inspect the complete official map", err)
	}
	for _, arch := range []string{"386", "amd64"} {
		goAssemblerOracleOutput(t, arch, prior.String(), "", true)
		for _, illegal := range []string{"SETO", "SETNO"} {
			goAssemblerOracleOutput(t, arch, "TEXT ·Invalid(SB),4,$0-0\n"+illegal+" AL\nRET\n", "", false)
		}
	}
	format := x86NativeSegmentQuerySourceFormat(t)
	var source, declarations strings.Builder
	for index, row := range x86SegmentQueryOracle {
		for role, operand := range []string{"AX", "(SI)", "CX"} {
			for seed := 0; seed < 2; seed++ {
				name := fmt.Sprintf("Query%d_%d_%d", index, role, seed)
				operation := row.op + " " + operand
				prepare, _ := x86SegmentQueryNativeFlagSeed(seed == 1)
				if row.bytes != 0 {
					operation += ",CX"
				}
				source.WriteString(fmt.Sprintf(format, name, prepare, operation))
				fmt.Fprintf(&declarations, "func %s(out *[18]byte,selector,old uint64,p *uint16)\n", name)
			}
		}
	}
	// The real complete producer must have a valid original Go object before
	// any translator result can count. No invalid spelling is relabelled Context.
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	seed, _ := x86SegmentQueryNativeFlagSeed(false)
	if strings.Count(source.String(), seed) != 24 {
		t.Fatal("complete original zero-overflow seed denominator changed")
	}
	legacy := strings.ReplaceAll(source.String(), seed, "XORL DX,DX\nSTC\n")
	goAssemblerOracleOutput(t, "amd64", legacy, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api+"/all-six-status-inputs", func(t *testing.T) {
			if ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
				t.Fatal("original Go-compatible complete segment-query observer rejected", err)
			}
		})
		t.Run(api+"/original-XOR-undefined-AF", func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, legacy, declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "LAHF") {
				t.Fatal("original XOR's undefined AF became an initialized complete LAHF byte", err)
			}
		})
	}
}
