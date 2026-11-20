package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func x86PhysicalFixtureSyntax(t *testing.T, path, name string) ([]byte, *token.FileSet, *ast.FuncDecl) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == name {
			return data, positions, function
		}
	}
	t.Fatal("original physical-SP fixture disappeared", name)
	return nil, nil, nil
}

func x86PhysicalFixtureHash(t *testing.T, text, want string) {
	t.Helper()
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(text))); got != want {
		t.Fatal("original physical-SP source, C observations or construction changed", got, want)
	}
}

func x86LeaveOriginalFixture(t *testing.T) (string, string) {
	t.Helper()
	_, _, function := x86PhysicalFixtureSyntax(t, "amd64_lower_implicit_legacy_test.go", "TestAMD64LeaveAndXLATRuntimeSemantics")
	values := make(map[string]string)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || len(declaration.Values) != 1 {
			return true
		}
		name := declaration.Names[0].Name
		if name != "source" && name != "mainC" {
			return true
		}
		literal, ok := declaration.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING || values[name] != "" {
			t.Fatal("original LEAVE source/C is no longer an independent complete literal", name)
		}
		var err error
		values[name], err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return true
	})
	x86PhysicalFixtureHash(t, values["source"], "7446bb6a394be848c20c77729a90b392adc96fb10a8ff632f58a09753d6e77fe")
	x86PhysicalFixtureHash(t, values["mainC"], "2cb4195e45e6bf440923af28528d9f4700df9c6b4e85edcfe0ac6ae32ea1b480")
	return values["source"], values["mainC"]
}

type x86UnaryPhysicalAlias struct {
	op, spelling, effective string
	bits, number            int
}

// Independent raw ModRM numbering, including wide AH/CH/DH/BH spellings.
// Reading the production alias function would fail to detect a shared bug.
func x86UnaryOriginalAliases() []x86UnaryPhysicalAlias {
	var rows []x86UnaryPhysicalAlias
	for _, family := range []string{"NEG", "NOT"} {
		for index, bits := range []int{16, 32, 64} {
			for _, reg := range []struct {
				spelling, effective string
				number              int
			}{
				{"AL", "AX", 0}, {"CL", "CX", 1}, {"DL", "DX", 2}, {"BL", "BX", 3},
				{"AH", "SP", 4}, {"CH", "BP", 5}, {"DH", "SI", 6}, {"BH", "DI", 7},
				{"BPB", "BP", 5}, {"SIB", "SI", 6}, {"DIB", "DI", 7}, {"R8B", "R8", 8}, {"R15B", "R15", 15},
			} {
				rows = append(rows, x86UnaryPhysicalAlias{family + []string{"W", "L", "Q"}[index], reg.spelling, reg.effective, bits, reg.number})
			}
		}
	}
	return rows
}

func x86UnaryOriginalFixture(t *testing.T) (string, string) {
	t.Helper()
	data, positions, function := x86PhysicalFixtureSyntax(t, "amd64_lower_neg_test.go", "TestAMD64UnaryYmbAliasesRuntime")
	start, end, cBuilder := -1, -1, ""
	for _, statement := range function.Body.List {
		text := string(data[positions.Position(statement.Pos()).Offset:positions.Position(statement.End()).Offset])
		if strings.HasPrefix(text, "var source, checks strings.Builder") {
			start = positions.Position(statement.Pos()).Offset
		}
		if text == "source.WriteString(\"\\tRET\\n\")" {
			end = positions.Position(statement.End()).Offset
		}
		if strings.HasPrefix(text, "mainC := fmt.Sprintf(") {
			cBuilder = text
		}
	}
	if start < 0 || end < start {
		t.Fatal("original complete unary source builder disappeared")
	}
	x86PhysicalFixtureHash(t, string(data[start:end]), "795cb722ff6fdbb95e2801dac85c4e608f4bb01db6b2f1f43588a6c81468365a")
	x86PhysicalFixtureHash(t, cBuilder, "78a78f3e15b40a852b63b5701035a6e97db6528e2d39f3d0068b1fa77e782aee")
	var source, checks strings.Builder
	source.WriteString("TEXT unaryaliases(SB),$0-8\n\tMOVQ out+0(FP), R14\n")
	rows := x86UnaryOriginalAliases()
	if len(rows) != 78 {
		t.Fatal("original complete unary alias directory changed", len(rows))
	}
	for index, row := range rows {
		const input uint64 = 0x1122334455667701
		want := ^input
		if strings.HasPrefix(row.op, "NEG") {
			want++
		}
		if row.bits == 16 {
			want = input&^0xffff | want&0xffff
		} else if row.bits == 32 {
			want &= 0xffffffff
		}
		fmt.Fprintf(&source, "\tMOVQ $%#x, %s\n\t%s %s\n\tMOVQ %s, %d(R14)\n", input, row.effective, row.op, row.spelling, row.effective, index*8)
		fmt.Fprintf(&checks, "  if (out[%d] != UINT64_C(%#x)) return %d;\n", index, want, index+1)
	}
	source.WriteString("\tRET\n")
	driver := fmt.Sprintf("#include <stdint.h>\nextern void unaryaliases(uint64_t *);\nint main(void) {\n  uint64_t out[%d] = {0};\n  unaryaliases(out);\n%s  return 0;\n}\n", len(rows), checks.String())
	return source.String(), driver
}

func TestX86PhysicalSPOriginalProgramsRetainContextAndActualGoBytes(t *testing.T) {
	leave, _ := x86LeaveOriginalFixture(t)
	unary, _ := x86UnaryOriginalFixture(t)
	for _, fixture := range []struct{ source, declaration string }{
		{leave, "func implicitlegacysemantics(out,data *byte)"},
		{unary, "func unaryaliases(out *uint64)"},
	} {
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", "#include \"textflag.h\"\n"+fixture.source)
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("invalid physical SP/FP/RET source acquired public logical ABI authority", api, err)
			}
		}
	}
	// The actual frameless Go byte stream does not repair the changed SP.
	// Its later logical data+8(FP) still encodes 16(RSP), now based in data,
	// not the original caller stack. Do not run this invalid body as a C ABI.
	// This standalone byte helper has no -I option. Resolve the selected SDK's
	// real header explicitly, rather than treating its missing include as an
	// assembler rejection of the original body.
	header := fmt.Sprintf("#include %q\n", filepath.Join(runtime.GOROOT(), "pkg", "include", "textflag.h"))
	leaveCode := amd64RegisterBoolOriginalBytes(t, header+leave)
	left, lateFP, restoresSP := false, false, false
	var last x86asm.Op
	for len(leaveCode) != 0 {
		instruction, err := x86asm.Decode(leaveCode, 64)
		if err != nil || instruction.Len <= 0 || instruction.Len > len(leaveCode) {
			t.Fatal("actual complete LEAVE source bytes stopped decoding", err)
		}
		leaveCode, last = leaveCode[instruction.Len:], instruction.Op
		if instruction.Op == x86asm.LEAVE {
			left = true
			continue
		}
		if left {
			restoresSP = restoresSP || instruction.Args[0] == x86asm.RSP
			if memory, ok := instruction.Args[1].(x86asm.Mem); ok {
				lateFP = lateFP || instruction.Op == x86asm.MOV && instruction.Args[0] == x86asm.RBX &&
					memory.Base == x86asm.RSP && memory.Disp == 16
			}
		}
	}
	if !left || !lateFP || restoresSP || last != x86asm.RET {
		t.Fatal("original Go physical SP/late-FP/RET evidence changed", left, lateFP, restoresSP, last)
	}
	code, count := amd64RegisterBoolOriginalBytes(t, unary), 0
	for len(code) != 0 {
		instruction, err := x86asm.Decode(code, 64)
		if err != nil || instruction.Len <= 0 || instruction.Len > len(code) {
			t.Fatal("actual full unary Go bytes stopped decoding", err)
		}
		code = code[instruction.Len:]
		if instruction.Op != x86asm.NEG && instruction.Op != x86asm.NOT {
			continue
		}
		rows := x86UnaryOriginalAliases()
		if count >= len(rows) {
			t.Fatal("actual original byte stream gained a unary row")
		}
		row := rows[count]
		base := map[int]x86asm.Reg{16: x86asm.AX, 32: x86asm.EAX, 64: x86asm.RAX}[row.bits]
		if instruction.Args[0] != base+x86asm.Reg(row.number) || instruction.DataSize != row.bits ||
			instruction.Op.String() != row.op[:3] {
			t.Fatal("actual Go byte alias no longer matches its independent physical register/width", count, row, instruction)
		}
		count++
	}
	if count != 78 {
		t.Fatal("actual original unary bytes lost an alias row", count)
	}
}

func TestX86PhysicalFrameFamiliesCompleteGoRowsAndNumericalBoundary(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{ALEAVEW, ynone, Pe, opBytes{0xc9}}",
		"{ALEAVEL, ynone, P32, opBytes{0xc9}}",
		"{ALEAVEQ, ynone, Py, opBytes{0xc9}}",
		"{AXLAT, ynone, Px, opBytes{0xd7}}",
	} {
		if !strings.Contains(string(data), row) {
			t.Fatal("independent complete implicit Go opcode attributes changed", row)
		}
	}
	for family, extension := range map[string]string{"NEG": "03", "NOT": "02"} {
		for _, width := range []struct{ suffix, prefix, opcode string }{
			{"B", "Pb", "0xf6"}, {"W", "Pe", "0xf7"}, {"L", "Px", "0xf7"}, {"Q", "Pw", "0xf7"},
		} {
			row := fmt.Sprintf("{A%s%s, yscond, %s, opBytes{%s, %s}}", family, width.suffix, width.prefix, width.opcode, extension)
			if !strings.Contains(string(data), row) {
				t.Fatal("complete unary Go prefix, opcode or /r extension changed", row)
			}
			if width.suffix == "B" {
				continue // AH is actual AX high8 here, not the wide raw ModRM SP alias.
			}
			for _, arch := range []string{"amd64", "386"} {
				if arch == "386" && width.suffix == "Q" {
					continue // The independent legacy form/rejection roots retain this illegal mode.
				}
				for _, spelling := range []string{"AH", "CH", "DH"} {
					instruction := x86ScalarLaneInstruction(t, family+width.suffix+" "+spelling)
					state := x86ResultState{flags: x86ByteFlagCF, direction: x86ResultDirectionBackward}
					for index := range state.gp {
						state.gp[index] = 0xff
					}
					before := state.clone()
					want := spelling == "DH" || arch == "386" && spelling == "CH"
					if accepted := x86ResultTransfer(instruction, &state, nil, 0, arch); accepted != want ||
						!want && !reflect.DeepEqual(state, before) {
						t.Fatal("wide Ymb alias imported physical SP/BP as ordinary NUM or lost ordinary SI/mode32BP", arch, instruction.Raw, accepted, want)
					}
				}
			}
		}
	}
}
