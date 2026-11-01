//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Independent obj6.progedit directory, not an implementation permission map.
var asmGeneratedFloatPoolNames = [][]string{
	{
		"MOVSS", "VMOVSS", "FMOVF", "FADDF", "FSUBF", "FSUBRF", "FMULF", "FDIVF", "FDIVRF",
		"FCOMF", "FCOMFP", "ADDSS", "SUBSS", "MULSS", "DIVSS", "COMISS", "UCOMISS",
	},
	{
		"MOVSD", "VMOVSD", "FMOVD", "FADDD", "FSUBD", "FSUBRD", "FMULD", "FDIVD", "FDIVRD",
		"FCOMD", "FCOMDP", "ADDSD", "SUBSD", "MULSD", "DIVSD", "COMISD", "UCOMISD",
	},
}

var asmGeneratedFloatPoolValues = []struct {
	text     string
	bits32   uint32
	bits64   uint64
	positive bool
}{
	{"0.0", 0, 0, true},
	{"-0.0", 0x80000000, 0x8000000000000000, false},
	{"1.25", 0x3fa00000, 0x3ff4000000000000, false},
	{"-2.5", 0xc0200000, 0xc004000000000000, false},
	{"1.000000059604644775390625", 0x3f800000, 0x3ff0000010000000, false},
	{"1e-50", 0, 0x358dee7a4ad4b81f, false},
	{"1e40", 0x7f800000, 0x483d6329f1c35ca5, false},
	{"(+(-2.5))", 0xc0200000, 0xc004000000000000, false},
	{"0x1.4p+0", 0x3fa00000, 0x3ff4000000000000, false},
	{"1.2_5", 0x3fa00000, 0x3ff4000000000000, false},
	{"-(-0.0)", 0, 0, true},
}

type asmGeneratedFloatPoolCase struct {
	name, instruction, pool string
	width                   uint32
	bits, sourceBits        uint64
}

func asmGeneratedFloatPoolSource(arch, pkg string) ([]byte, []byte, []asmGeneratedFloatPoolCase) {
	var source, declarations strings.Builder
	declarations.WriteString("package poolfixture\n")
	var cases []asmGeneratedFloatPoolCase
	appendCase := func(op string, size int, value int, register int) {
		literal := asmGeneratedFloatPoolValues[value]
		index := len(cases)
		name, objectName := fmt.Sprintf("·Case%d", index), fmt.Sprintf("%s.Case%d", pkg, index)
		if index%11 == 0 {
			name, objectName = fmt.Sprintf("private%d<>", index), fmt.Sprintf("private%d", index)
		} else {
			fmt.Fprintf(&declarations, "func Case%d()\n", index)
		}
		destination := fmt.Sprintf("X%d", register)
		if strings.HasPrefix(op, "F") {
			destination = "F0"
		}
		instruction := fmt.Sprintf("%s $%s,%s", op, literal.text, destination)
		bits := literal.bits64
		if size == 4 {
			bits = uint64(literal.bits32)
		}
		pool := fmt.Sprintf("$f%d.%0*x", size*8, size*2, bits)
		if strings.Contains(op, "MOVS") && literal.positive && register < 16 {
			pool = "" // The original float64 +0 bits select legacy XORPS.
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, instruction)
		cases = append(cases, asmGeneratedFloatPoolCase{objectName, instruction, pool, uint32(size), bits, literal.bits64})
	}
	for precision, names := range asmGeneratedFloatPoolNames {
		for _, op := range names {
			for value := range asmGeneratedFloatPoolValues {
				appendCase(op, 4+4*precision, value, 0)
			}
		}
		for _, op := range names[:2] {
			for _, register := range []int{7, 15, 16, 31} {
				if arch == "386" && register == 15 || !strings.HasPrefix(op, "V") && register >= 16 {
					continue // Independent actual Go mode/register restrictions.
				}
				for _, value := range []int{0, 1} {
					appendCase(op, 4+4*precision, value, register)
				}
			}
		}
	}
	// This ordinary explicit DATA remains the only actual source layout.
	source.WriteString("DATA ordinary<>(SB)/8,$0x1122334455667788\nGLOBL ordinary<>(SB),8,$8\n")
	return []byte(source.String()), []byte(declarations.String()), cases
}

func asmGeneratedFloatPoolOfficialDirectory(t *testing.T, root string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "src/cmd/internal/obj/x86/obj6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actual []string
	ast.Inspect(file, func(node ast.Node) bool {
		clause, ok := node.(*ast.CaseClause)
		if !ok || len(clause.List) == 0 {
			return true
		}
		first, ok := clause.List[0].(*ast.Ident)
		if !ok || first.Name != "AMOVSS" && first.Name != "AFMOVF" && first.Name != "AMOVSD" && first.Name != "AFMOVD" {
			return true
		}
		for _, expression := range clause.List {
			identifier, ok := expression.(*ast.Ident)
			if !ok {
				t.Fatal("actual scalar pool rewrite has an unknown opcode selector")
			}
			actual = append(actual, strings.TrimPrefix(identifier.Name, "A"))
		}
		return true
	})
	expected := append(append([]string(nil), asmGeneratedFloatPoolNames[0]...), asmGeneratedFloatPoolNames[1]...)
	if !reflect.DeepEqual(actual, expected) || len(actual) != 34 {
		t.Fatal("the independent complete Go FCONST rewrite directory changed", actual)
	}
}

func asmGeneratedFloatPoolOriginal(t *testing.T, data, text []byte) []ASMDataMember {
	t.Helper()
	var members []ASMDataMember
	var texts []TextMember
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal("stock Go complete DATA reader", err)
	}
	if err := json.Unmarshal(text, &texts); err != nil || len(texts) != len(members) {
		t.Fatal("stock Go complete TEXT reader", err)
	}
	for index := range members {
		members[index].Texts = texts[index].Texts
	}
	return members
}

func asmGeneratedFloatPoolStockControls(t *testing.T, member ASMDataMember, cases []asmGeneratedFloatPoolCase, arch string) {
	t.Helper()
	wanted := map[string]bool{"ordinary": true}
	for _, row := range cases {
		if row.pool != "" {
			wanted[row.pool] = true
		}
	}
	definitions := make(map[string]ASMDataDefinition)
	for _, definition := range member.Definitions {
		if !wanted[definition.Name] {
			continue // Whole anonymous/AUX records remain in the independent object comparisons.
		}
		if definition.Name != "ordinary" {
			t.Logf("actual generated definition name=%q ns=%d relative=%d index=%d ABI=%d kind=%d flags=%d/%d size=%d align=%d data=%x hash=%x relocs=%v",
				definition.Name, definition.Namespace, definition.Relative, definition.Index, definition.ABI, definition.Kind,
				definition.Flags, definition.Flags2, definition.Size, definition.Align, definition.Data, definition.Hash, definition.Relocations)
		}
		if _, exists := definitions[definition.Name]; exists {
			t.Fatal("the stock assembler repeated an object-local definition name")
		}
		definitions[definition.Name] = definition
	}
	texts := make(map[string]TextRecord)
	for _, text := range member.Texts {
		texts[text.Name] = text
	}
	if len(texts) != len(cases) || len(definitions) != 14 || len(wanted) != 14 {
		t.Fatal("actual complete TEXT or deduplicated DATA inventory differs", len(texts), len(cases), len(definitions))
	}
	for _, row := range cases {
		text, present := texts[row.name]
		if !present {
			t.Fatal("stock reader lost an actual source owner", row.name)
		}
		if row.pool == "" {
			if len(text.Relocations) != 0 || !bytes.Contains(text.Code, []byte{0x0f, 0x57}) {
				t.Fatal("original positive-zero MOV did not become relocation-free legacy XORPS", row.instruction)
			}
			continue
		}
		definition, present := definitions[row.pool]
		align := row.width
		if arch == "386" && align == 8 {
			align = 4
		}
		var expected [8]byte
		binary.LittleEndian.PutUint64(expected[:], row.bits)
		if !present || definition.Namespace != TextSymbolHashed64 || definition.ABI != 0 || definition.Kind != 3 ||
			definition.Flags != 2 || definition.Flags2 != 0 || definition.Size != row.width || definition.Align != align ||
			!bytes.Equal(definition.Data, expected[:row.width]) || !bytes.Equal(definition.Hash, expected[:]) || len(definition.Relocations) != 0 {
			t.Fatal("actual float pool differs from the independent Go writer/IEEE directory", row.instruction, definition)
		}
		if len(text.Relocations) != 1 {
			t.Fatal("original scalar FCONST lost its unique actual pool relocation", row.instruction, text.Relocations)
		}
		relocation := text.Relocations[0]
		kind := uint16(14) // Actual amd64 R_PCREL; mode32 retains R_ADDR.
		if arch == "386" {
			kind = 1
		}
		if relocation.Type != kind || relocation.Size != 4 || relocation.Add != 0 ||
			relocation.Target.PackageIndex != 2147483646 || relocation.Target.SymbolIndex != definition.Relative ||
			relocation.Target.Name != definition.Name || !relocation.Target.ABIKnown || relocation.Target.ABI != 0 {
			t.Fatal("actual source owner and object-local pool reference differ", row.instruction, relocation)
		}
	}
}

func asmGeneratedFloatPoolMetadataControls(t *testing.T, source ASMDataSourceObservation, cases []asmGeneratedFloatPoolCase) {
	t.Helper()
	if len(source.GeneratedFloatPools) != 13 || len(source.TextOrder) != len(cases) {
		t.Fatal("the complete deduplicated metadata or source TEXT directory differs")
	}
	byOwner := make(map[int]ASMGeneratedFloatPoolOwner)
	for _, pool := range source.GeneratedFloatPools {
		for _, owner := range pool.Owners {
			if owner.TextSourceOrdinal < 0 || owner.TextSourceOrdinal >= len(cases) {
				t.Fatal("generated pool owner escaped the complete source", owner)
			}
			row := cases[owner.TextSourceOrdinal]
			text := source.TextOrder[owner.TextSourceOrdinal]
			actual := source.Original.Texts[text.ObjectOrdinal]
			if _, duplicate := byOwner[owner.TextSourceOrdinal]; duplicate || pool.Definition.Name != row.pool ||
				owner.StatementOrdinal != 3*owner.TextSourceOrdinal+1 || owner.TextObjectOrdinal != text.ObjectOrdinal ||
				owner.TextNamespace != text.Namespace || owner.TextRelative != text.Relative || owner.TextIndex != text.Index ||
				actual.Name != row.name || owner.Opcode != strings.Fields(row.instruction)[0] || owner.SourceFloat64Bits != row.sourceBits ||
				owner.RelocationOrdinal != 0 || len(actual.Relocations) != 1 || !reflect.DeepEqual(owner.Relocation, actual.Relocations[0]) {
				t.Fatal("the FCONST/TEXT/physical-relocation metadata association differs", row, owner)
			}
			byOwner[owner.TextSourceOrdinal] = owner
		}
	}
	for ordinal, row := range cases {
		_, associated := byOwner[ordinal]
		if associated != (row.pool != "") {
			t.Fatal("source pool and original positive-zero XOR roles were confused", row)
		}
	}
}

func TestGoSDKASMGeneratedFloatPoolWholeFamilyObservation(t *testing.T) {
	directory, driver, _ := fixture(t)
	root := filepath.Dir(filepath.Dir(driver))
	asmGeneratedFloatPoolOfficialDirectory(t, root)
	if err := GeneratedFloatPoolSources(runtime.Version(), func(role string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(role)))
	}); err != nil {
		t.Fatal("the independent actual SDK producer sources differ", err)
	}
	dataOracle := officialReaderForSource(t, driver, sdkASMDataReaderSource)
	textOracle := officialReaderForSource(t, driver, sdkTextReaderSource)
	builtin, err := os.ReadFile(filepath.Join(root, builtinSourceRole))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "darwin/amd64", "windows/386", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			_, arch, _ := strings.Cut(target, "/")
			env := fixtureEnv(t, target)
			consumer := filepath.Join(directory, strings.ReplaceAll(target, "/", "-"))
			if err := os.Mkdir(consumer, 0700); err != nil {
				t.Fatal(err)
			}
			pkg := fixtureModule + "/" + filepath.Base(consumer)
			source, declarations, cases := asmGeneratedFloatPoolSource(arch, pkg)
			for name, data := range map[string][]byte{"pool.go": declarations, "pool.s": source} {
				if err := os.WriteFile(filepath.Join(consumer, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			selection := run(t, driver, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly", "-gcflags=-std", "-asmflags=-std", ".")
			var selected struct {
				ImportPath, Export string
				SFiles             []string
			}
			if json.Unmarshal(selection, &selected) != nil || selected.ImportPath != pkg || !reflect.DeepEqual(selected.SFiles, []string{"pool.s"}) {
				t.Fatal("actual complete first-party assembly selection differs")
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			data := run(t, dataOracle, consumer, env, selected.Export)
			text := run(t, textOracle, consumer, env, selected.Export)
			actual := asmGeneratedFloatPoolOriginal(t, data, text)
			if len(actual) != 3 {
				t.Fatal("actual original archive lost its complete member inventory", len(actual))
			}
			request := SDKASMDataObservationRequest{PackagePath: pkg, Target: target, Archive: archive, BuiltinSource: builtin}
			expanded := bytes.ReplaceAll(source, []byte(","), []byte(", "))
			if err := os.WriteFile(filepath.Join(consumer, "expanded.asm"), expanded, 0600); err != nil {
				t.Fatal(err)
			}
			input := SDKASMDataSource{Name: "pool.s", Original: source, Expanded: expanded}
			artifacts := map[string][]byte{"source-pool.s": source, "source-pool.go": declarations,
				"expanded.asm": expanded, "original.a": archive, "selection.json": selection, "data-sdk.json": data, "text-sdk.json": text}
			for _, role := range []string{"original", "expanded"} {
				name := "pool.s"
				if role == "expanded" {
					name = "expanded.asm"
				}
				arguments := []string{"tool", "asm", "-std"}
				if target == "darwin/amd64" {
					arguments = append(arguments, "-shared")
				}
				arguments = append(arguments, "-p", pkg, "-o", role+".o", name)
				run(t, driver, consumer, env, arguments...)
				object, err := os.ReadFile(filepath.Join(consumer, role+".o"))
				if err != nil {
					t.Fatal(err)
				}
				if role == "original" {
					input.OriginalObject = object
				} else {
					input.ExpandedObject = object
				}
				artifacts[role+".o"] = object
				artifacts[role+"-data-sdk.json"] = run(t, dataOracle, consumer, env, role+".o")
				artifacts[role+"-text-sdk.json"] = run(t, textOracle, consumer, env, role+".o")
			}
			request.Sources = []SDKASMDataSource{input}
			retainTextArtifact(t, target, "generated-float-pool", artifacts)
			t.Run("stock-reader-complete-family", func(t *testing.T) {
				asmGeneratedFloatPoolStockControls(t, actual[2], cases, arch)
				for _, role := range []string{"original", "expanded"} {
					member := asmGeneratedFloatPoolOriginal(t, artifacts[role+"-data-sdk.json"], artifacts[role+"-text-sdk.json"])
					if len(member) != 1 || !sameASMDataObjects(member[0], actual[2]) {
						t.Fatal("independent original/expanded/archive DATA/TEXT inventory differs", role)
					}
				}
			})
			t.Run("complete-source-join-without-literal-authority", func(t *testing.T) {
				observation, err := ObserveX86SDKASMData(request)
				if err != nil || observation == nil {
					t.Fatal("actual assembler-created float pool is absent from the complete source/object observation", err)
				}
				if !reflect.DeepEqual(observation.Members, actual) || len(observation.Sources) != 1 ||
					len(observation.Sources[0].Layouts) != 1 || len(observation.Sources[0].ExpandedLayouts) != 1 ||
					observation.Sources[0].Layouts[0].Name != "ordinary" || len(observation.Sources[0].GeneratedFuncdata) != 0 {
					t.Fatal("generated float pools replaced whole objects, explicit DATA or FUNCDATA roles")
				}
				asmGeneratedFloatPoolMetadataControls(t, observation.Sources[0], cases)
				images, err := ReadonlyLiteralDataInitializers(observation)
				if err != nil || len(images) != 1 || images[0].Definition.Name != "ordinary" ||
					!bytes.Equal(images[0].Initial, []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}) {
					t.Fatal("generated pools entered the image plan or blocked ordinary private RODATA", images, err)
				}
			})
			t.Run("complete-source-and-binary-guards", func(t *testing.T) {
				asmGeneratedFloatPoolGuards(t, request)
			})
		})
	}
}
