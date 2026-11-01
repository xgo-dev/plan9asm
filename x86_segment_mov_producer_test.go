package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This is a test-only observation of the selected assembler's source schema.
// It never selects translator semantics or grants a source/native capability.
type x86SegmentMOVEncoderSchema struct {
	indexPrefix386  bool
	namedDiagnostic bool
	registers       map[string]int64
}

var x86SegmentMOVProducerSources = []string{
	"src/cmd/internal/obj/x86/asm6.go",
	"src/cmd/asm/internal/asm/parse.go",
	"src/cmd/internal/obj/x86/a.out.go",
	"src/cmd/internal/obj/util.go",
}

func x86SegmentMOVSourceFunction(source []byte, name string) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "selected.go", source, 0)
	if err != nil {
		return nil, err
	}
	var found *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == name {
			if found != nil {
				return nil, fmt.Errorf("duplicate selected function %s", name)
			}
			found = function
		}
	}
	if found == nil || found.Body == nil {
		return nil, fmt.Errorf("missing selected function %s", name)
	}
	return source[fset.Position(found.Pos()).Offset:fset.Position(found.End()).Offset], nil
}

func x86SegmentMOVInspectProducer(sources map[string][]byte) (x86SegmentMOVEncoderSchema, error) {
	var result x86SegmentMOVEncoderSchema
	// Complete AST-bounded functions pin the two independently inspected
	// producer schemas. An unfamiliar producer fails observation, not skips.
	profiles := []struct {
		prefix, index, address, parse string
		indexPrefix, named            bool
	}{
		// Observed Go1.20.14: I386 early return dominates the Index switch;
		// asmidx writes the selected enum's numeric register identities.
		{
			"4b1d710df7230ccfb9abb463fa692b57a492fa44ddef3feda094eb963822dff1",
			"3c08a9be657cff57a08638f4366576bdc6c7a951711855d417a70f36fe7db17d",
			"2c2e8d87991ead9b37a043704619d0f862f0039644c9feb711e9cf22e5cb8f9d",
			"e973c5bb650e3cecba96f4ac6934b17388cf4c64907d0006340be23e3e2e30f5",
			false, false,
		},
		// Observed Go1.21.13/1.22.12/1.23.12: the I386 early return
		// is gone, but asmidx retains numeric identities. asmandsz has
		// the changed Windows TLS relocation condition.
		{
			"7359b12c59641f0ca2b3179bdd5c631dd91b721cf3b68d2a05ffd837992bb881",
			"3c08a9be657cff57a08638f4366576bdc6c7a951711855d417a70f36fe7db17d",
			"db9c3b90208841426493ed3e3f475000462e8a53a5e0d4e67a68e11f8c3c44c9",
			"e973c5bb650e3cecba96f4ac6934b17388cf4c64907d0006340be23e3e2e30f5",
			true, false,
		},
		// Observed Go1.24.13/1.25.14/1.26.9: named diagnostics and
		// the current relocation writer, with the earlier parser body.
		{
			"7359b12c59641f0ca2b3179bdd5c631dd91b721cf3b68d2a05ffd837992bb881",
			"aecd67962a374b23f9f57ed1dbfe281bd91e801118d9c3478fa54d150dd90f06",
			"dca5b846b2f8e47be6c360076cbddc4d3a95a879a3e7cc90a581d34a10287a46",
			"e973c5bb650e3cecba96f4ac6934b17388cf4c64907d0006340be23e3e2e30f5",
			true, true,
		},
		// Observed Go1.27.2: explicit Index FS/GS reaches the prefix switch;
		// asmidx writes register names. These hashes are not a build-version gate.
		{
			"7359b12c59641f0ca2b3179bdd5c631dd91b721cf3b68d2a05ffd837992bb881",
			"aecd67962a374b23f9f57ed1dbfe281bd91e801118d9c3478fa54d150dd90f06",
			"dca5b846b2f8e47be6c360076cbddc4d3a95a879a3e7cc90a581d34a10287a46",
			"c15ef57b88cb006f21dd98b0b15b52a9082d899d9afdb075f454a02fdd8b516a",
			true, true,
		},
	}
	var hashes []string
	for index, name := range []string{"prefixof", "asmidx", "asmandsz", "registerIndirect"} {
		filename := x86SegmentMOVProducerSources[0]
		if index == 3 {
			filename = x86SegmentMOVProducerSources[1]
		}
		function, err := x86SegmentMOVSourceFunction(sources[filename], name)
		if err != nil {
			return result, err
		}
		hashes = append(hashes, fmt.Sprintf("%x", sha256.Sum256(function)))
	}
	matched := false
	for _, profile := range profiles {
		if strings.Join(hashes, "/") == strings.Join([]string{profile.prefix, profile.index, profile.address, profile.parse}, "/") {
			result.indexPrefix386, result.namedDiagnostic, matched = profile.indexPrefix, profile.named, true
		}
	}
	if !matched {
		return result, fmt.Errorf("unobserved selected prefix/index/address/parser schema: %v", hashes)
	}
	registers, err := x86SegmentMOVProducerRegisters(sources[x86SegmentMOVProducerSources[2]], sources[x86SegmentMOVProducerSources[3]])
	if err != nil {
		return result, err
	}
	result.registers = registers
	return result, nil
}

func x86SegmentMOVProducerRegisters(registerSource, objectSource []byte) (map[string]int64, error) {
	objects, err := parser.ParseFile(token.NewFileSet(), "util.go", objectSource, 0)
	if err != nil {
		return nil, err
	}
	var base int64
	found := false
	for _, declaration := range objects.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, specification := range group.Specs {
			value := specification.(*ast.ValueSpec)
			if len(value.Names) != 1 || value.Names[0].Name != "RBaseAMD64" || len(value.Values) != 1 {
				continue
			}
			expression, ok := value.Values[0].(*ast.BinaryExpr)
			if !ok || expression.Op != token.MUL || found {
				return nil, fmt.Errorf("unknown register base declaration")
			}
			left, leftOK := expression.X.(*ast.BasicLit)
			right, rightOK := expression.Y.(*ast.BasicLit)
			if !leftOK || !rightOK || left.Kind != token.INT || right.Kind != token.INT {
				return nil, fmt.Errorf("unknown register base expression")
			}
			base, found = constant.Int64Val(constant.BinaryOp(constant.MakeFromLiteral(left.Value, token.INT, 0), token.MUL, constant.MakeFromLiteral(right.Value, token.INT, 0)))
		}
	}
	if !found || base <= 0 || base > 1<<30 {
		return nil, fmt.Errorf("missing bounded actual register base")
	}
	registers, err := parser.ParseFile(token.NewFileSet(), "a.out.go", registerSource, 0)
	if err != nil {
		return nil, err
	}
	for _, declaration := range registers.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST || len(group.Specs) == 0 {
			continue
		}
		first := group.Specs[0].(*ast.ValueSpec)
		if len(first.Names) != 1 || first.Names[0].Name != "REG_AL" || len(first.Values) != 1 {
			continue
		}
		expression, ok := first.Values[0].(*ast.BinaryExpr)
		if !ok || expression.Op != token.ADD {
			return nil, fmt.Errorf("unknown register iota expression")
		}
		selector, leftOK := expression.X.(*ast.SelectorExpr)
		iota, rightOK := expression.Y.(*ast.Ident)
		if !leftOK || !rightOK || iota.Name != "iota" || selector.Sel.Name != "RBaseAMD64" {
			return nil, fmt.Errorf("unknown actual register iota base")
		}
		object, ok := selector.X.(*ast.Ident)
		if !ok || object.Name != "obj" {
			return nil, fmt.Errorf("unknown actual register namespace")
		}
		result := make(map[string]int64)
		for index, specification := range group.Specs {
			value := specification.(*ast.ValueSpec)
			if len(value.Names) != 1 || value.Type != nil || index != 0 && len(value.Values) != 0 {
				return nil, fmt.Errorf("unknown register enum shape")
			}
			name := value.Names[0].Name
			if _, duplicate := result[name]; duplicate {
				return nil, fmt.Errorf("duplicate register constant")
			}
			result[name] = base + int64(index)
			if name == "REG_GS" {
				if result["REG_CX"] == 0 || result["REG_FS"] == 0 {
					return nil, fmt.Errorf("incomplete actual register tuple")
				}
				return result, nil
			}
		}
	}
	return nil, fmt.Errorf("missing complete actual register enum")
}

type x86SegmentMOVSelectedEncoder struct {
	schema  x86SegmentMOVEncoderSchema
	sources map[string][]byte
}

func x86SegmentMOVObserveSelectedEncoder(t *testing.T) x86SegmentMOVSelectedEncoder {
	t.Helper()
	driver, _ := x86LEAActualSDKDriver(t)
	tool := "asm"
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	paths := []string{driver, filepath.Join(runtime.GOROOT(), "pkg/tool", runtime.GOOS+"_"+runtime.GOARCH, tool)}
	for _, filename := range x86SegmentMOVProducerSources {
		paths = append(paths, filepath.Join(runtime.GOROOT(), filepath.FromSlash(filename)))
	}
	sources := make(map[string][]byte)
	for index, filename := range paths {
		data, err := os.ReadFile(filename)
		real, realErr := filepath.EvalSymlinks(filename)
		if err != nil || realErr != nil {
			t.Fatalf("selected producer observation missing %s: %v %v", filename, err, realErr)
		}
		if index >= 2 {
			sources[x86SegmentMOVProducerSources[index-2]] = data
		}
		filename, real, want := filename, real, sha256.Sum256(data)
		t.Cleanup(func() {
			current, err := os.ReadFile(filename)
			currentReal, realErr := filepath.EvalSymlinks(filename)
			if err != nil || realErr != nil || currentReal != real || sha256.Sum256(current) != want {
				t.Errorf("selected producer source/tool changed: %s", filename)
			}
		})
		t.Logf("selected producer observation path=%s sha256=%x", filename, sha256.Sum256(data))
	}
	schema, err := x86SegmentMOVInspectProducer(sources)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual selected encoder schema: 386 Index segment prefix=%v, named asmidx diagnostic=%v; observation only, no source/native authority", schema.indexPrefix386, schema.namedDiagnostic)
	return x86SegmentMOVSelectedEncoder{schema, sources}
}

func (schema x86SegmentMOVEncoderSchema) dynamicPrefix(arch, segment string) []byte {
	if arch == "386" && !schema.indexPrefix386 {
		return nil
	}
	if segment == "FS" {
		return []byte{0x64}
	}
	return []byte{0x65}
}

func (schema x86SegmentMOVEncoderSchema) acceptsScaledDiagnostic(filename, wantFilename string, source, wantSource []byte, segment, diagnostic string) bool {
	if filename != wantFilename || !bytes.Equal(source, wantSource) || segment != "FS" && segment != "GS" {
		return false
	}
	index, hasIndex := schema.registers["REG_CX"]
	base, hasBase := schema.registers["REG_"+segment]
	if !hasIndex || !hasBase {
		return false
	}
	want := fmt.Sprintf("asm: asmidx: bad address 4/%d/%d\nasm: assembly failed", index, base)
	if schema.namedDiagnostic {
		want = "asm: asmidx: bad address 4/CX/" + segment + "\nasm: assembly failed"
	}
	return strings.TrimSpace(strings.ReplaceAll(diagnostic, "\r\n", "\n")) == want
}

func TestX86SegmentMOVSelectedProducerSchemaRejectsUnknownAST(t *testing.T) {
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	t.Run("actual-complete-schema", func(t *testing.T) {
		if _, err := x86SegmentMOVInspectProducer(producer.sources); err != nil {
			t.Fatal(err)
		}
	})
	for _, mutation := range []struct{ name, function, old, replacement string }{
		{"prefix-effect", "prefixof", "return 0x64", "return 0x66"},
		{"prefix-declaration", "prefixof", "func prefixof", "func otherPrefix"},
		{"diagnostic-writer", "asmidx", "asmidx: bad address", "asmidx: unknown address"},
		{"address-role", "asmandsz", "a.Index != REG_TLS", "a.Index != REG_FS"},
		{"parser-identity", "registerIndirect", "a.Index = r1", "a.Index = r2"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			filename := x86SegmentMOVProducerSources[0]
			if mutation.function == "registerIndirect" {
				filename = x86SegmentMOVProducerSources[1]
			}
			original, err := x86SegmentMOVSourceFunction(producer.sources[filename], mutation.function)
			if err != nil || !bytes.Contains(original, []byte(mutation.old)) {
				t.Fatal("mutation lost its exact actual function anchor", err)
			}
			changed := bytes.Replace(original, []byte(mutation.old), []byte(mutation.replacement), 1)
			sources := make(map[string][]byte)
			for name, source := range producer.sources {
				sources[name] = append([]byte(nil), source...)
			}
			sources[filename] = bytes.Replace(sources[filename], original, changed, 1)
			if _, err := x86SegmentMOVInspectProducer(sources); err == nil {
				t.Fatal("unobserved actual producer AST borrowed a calibrated encoding/diagnostic")
			}
		})
	}
	for _, filename := range x86SegmentMOVProducerSources {
		t.Run("missing-"+filepath.Base(filename), func(t *testing.T) {
			sources := make(map[string][]byte)
			for name, source := range producer.sources {
				if name != filename {
					sources[name] = source
				}
			}
			if _, err := x86SegmentMOVInspectProducer(sources); err == nil {
				t.Fatal("incomplete selected source inventory accepted")
			}
		})
	}
}

func TestX86SegmentMOVSelectedProducerDiagnosticReaderExactIdentity(t *testing.T) {
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	for _, segment := range []string{"FS", "GS"} {
		source := []byte("TEXT invalid(SB),4,$0-0\nMOVL -8(" + segment + ")(CX*4),DX\nRET\n")
		good := fmt.Sprintf("asm: asmidx: bad address 4/%d/%d\nasm: assembly failed", producer.schema.registers["REG_CX"], producer.schema.registers["REG_"+segment])
		if producer.schema.namedDiagnostic {
			good = "asm: asmidx: bad address 4/CX/" + segment + "\nasm: assembly failed"
		}
		for _, row := range []struct {
			name, filename, text, diagnostic string
			accepted                         bool
		}{
			{"exact", "bound.s", string(source), good, true},
			{"CRLF", "bound.s", string(source), strings.ReplaceAll(good, "\n", "\r\n"), true},
			{"foreign-file", "foreign.s", string(source), good, false},
			{"changed-source", "bound.s", string(source) + "NOP\n", good, false},
			{"arbitrary-numbers", "bound.s", string(source), "asm: asmidx: bad address 4/12345/67890\nasm: assembly failed", false},
			{"swapped-registers", "bound.s", string(source), fmt.Sprintf("asm: asmidx: bad address 4/%d/%d\nasm: assembly failed", producer.schema.registers["REG_"+segment], producer.schema.registers["REG_CX"]), false},
			{"wrong-scale", "bound.s", string(source), strings.Replace(good, "address 4/", "address 8/", 1), false},
			{"extra-diagnostic", "bound.s", string(source), good + "\nother source failed", false},
			{"missing-terminal", "bound.s", string(source), strings.Split(good, "\n")[0], false},
		} {
			t.Run(segment+"/"+row.name, func(t *testing.T) {
				if got := producer.schema.acceptsScaledDiagnostic(row.filename, "bound.s", []byte(row.text), source, segment, row.diagnostic); got != row.accepted {
					t.Fatal("diagnostic lost exact selected-source/writer/register identity", got, row.accepted)
				}
			})
		}
	}
}
