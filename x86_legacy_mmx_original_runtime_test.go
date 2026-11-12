package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func x86LegacyMMXActualRuntimeLiterals(t *testing.T) (string, string) {
	t.Helper()
	const filename = "amd64_lower_legacy_mmx_test.go"
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	literals := make(map[string]string)
	owners := 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64LegacyMMXRuntimeSemantics" {
			continue
		}
		owners++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			value, ok := node.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				return true
			}
			name := value.Names[0].Name
			if name != "source" && name != "mainC" {
				return true
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || literals[name] != "" {
				t.Fatal("original MMX runtime lost its actual unique literal", name)
			}
			literals[name], err = strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			return true
		})
	}
	if owners != 1 || literals["source"] == "" || literals["mainC"] == "" {
		t.Fatal("missing or duplicate complete original MMX runtime owner")
	}
	return literals["source"], literals["mainC"]
}

func TestX86LegacyMMXOriginalRuntimeHasClosedPhysicalRegion(t *testing.T) {
	source, reference := x86LegacyMMXActualRuntimeLiterals(t)
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(reference))); got != "486d3a793dca517202c6b20d6ea6a0d0e6b040d3b08a185f74a9a82fdcecba28" {
		t.Fatal("original complete MMX C reference changed", got)
	}
	// The only permitted fixture correction moves this independent incoming
	// address before MMX and closes MMX with EMMS. Reconstruct the old source
	// to bind every other byte, not a smaller substitute numerical program.
	const outSeed = "\tMOVQ out+8(FP), DI\n"
	const begin = "\tMOVQ AX, M1\n"
	if strings.Count(source, outSeed) != 1 || strings.Count(source, begin) != 1 || strings.Count(source, "\tEMMS\n") > 1 {
		t.Fatal("original MMX source changed an input or physical boundary")
	}
	original := strings.Replace(source, "\tEMMS\n", "", 1)
	original = strings.Replace(original, outSeed, "", 1)
	original = strings.Replace(original, begin, begin+outSeed, 1)
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(original))); got != "7783cda56681fb4d7b2eb5906ada0906dc29ac06609eff12b228b7824e8bc911" {
		t.Fatal("MMX fixture changed more than the independent seed/EMMS repair", got)
	}
	var instructions, effects []string
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "TEXT ") || line == "RET" {
			continue
		}
		instructions = append(instructions, line)
		if !strings.HasPrefix(line, "MOVQ value+") && !strings.HasPrefix(line, "MOVQ out+") && line != "EMMS" {
			effects = append(effects, line)
		}
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(effects, "\n")))); got != "485db67989f91f63ee99acffa3d80c576f775453a337791a9da8b94700f1c61c" {
		t.Fatal("original full MMX/SSE store and fence sequence changed", got)
	}
	mmx := regexp.MustCompile(`\bM[0-7]\b`)
	first, last, count, emms := -1, -1, 0, 0
	for index, instruction := range instructions {
		if instruction == "EMMS" {
			emms++
		}
		if mmx.MatchString(instruction) {
			if first < 0 {
				first = index
			}
			last, count = index, count+1
		}
	}
	if count != 6 || first < 0 || last+1 >= len(instructions) {
		t.Fatal("incomplete physical MMX operation inventory", count)
	}
	for index := first; index <= last; index++ {
		if !mmx.MatchString(instructions[index]) {
			t.Fatal("original runtime interrupts physical MMX with an unrelated source operation", instructions[index])
		}
	}
	if emms != 1 || instructions[last+1] != "EMMS" || strings.Index(source, outSeed) > strings.Index(source, begin) {
		t.Fatal("original MMX runtime lacks prepared inputs and its real immediately following EMMS")
	}
}

func TestX86LegacyMMXOriginalRuntimeThreeAPIsAndTargetsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("original MMX runtime objects require LLVM22 llc")
	}
	source, _ := x86LegacyMMXActualRuntimeLiterals(t)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source,
						"func legacymmxsemantics(value uint64, out *byte)", "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("actual initialized original MMX runtime lost its public physical-region owner", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						if !strings.Contains(pipeline.ir, "asm sideeffect") || !strings.Contains(pipeline.ir, "emms") {
							t.Fatal("original MMX region or its physical cleanup disappeared")
						}
						x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}
