package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var x86AddSubLiteralValues = []x86ScalarLiteralValue{
	{name: "one", text: "1.0", bits32: 0x3f800000, bits64: 0x3ff0000000000000},
	{name: "plus", text: "+1.0", bits32: 0x3f800000, bits64: 0x3ff0000000000000},
	{name: "minus", text: "-1.0", bits32: 0xbf800000, bits64: 0xbff0000000000000},
	{name: "zero", text: "0.0"},
	{name: "negativeZero", text: "-0.0", bits32: 0x80000000, bits64: 0x8000000000000000},
	{name: "hex", text: "0x1.4p+0", bits32: 0x3fa00000, bits64: 0x3ff4000000000000},
	{name: "scientific", text: "6.25e-1", bits32: 0x3f200000, bits64: 0x3fe4000000000000},
	{name: "parentheses", text: "(1.25)", bits32: 0x3fa00000, bits64: 0x3ff4000000000000},
	{name: "signedParentheses", text: "(-2.5)", bits32: 0xc0200000, bits64: 0xc004000000000000},
	{name: "roundEven", text: "1.000000059604644775390625", bits32: 0x3f800000, bits64: 0x3ff0000010000000},
	{name: "underflow32", text: "1e-50", bits64: 0x358dee7a4ad4b81f},
	{name: "overflow32", text: "1e40", bits32: 0x7f800000, bits64: 0x483d6329f1c35ca5},
	{name: "underscore", text: "1_000.0", bits32: 0x447a0000, bits64: 0x408f400000000000},
	{name: "nestedSign", text: "+(-(+1.25))", bits32: 0xbfa00000, bits64: 0xbff4000000000000},
}

func x86AddSubLiteralPackage(t *testing.T, arch, declarations string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "literal.go", "package literal\n"+declarations, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check("literal", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: "literal", Types: pkg, Syntax: []*ast.File{file}}
}

func TestX86FloatAddSubLiteralActualGoObjects(t *testing.T) {
	// This shared oracle authenticates the invoked SDK/assembler and hashes
	// obj6/asm6/AVX tables before and after these original-source objects.
	x86ScalarLiteralActualGoRewriteSet(t)
	for _, name := range []string{"obj6.go", "asm6.go"} {
		path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if name == "obj6.go" {
			if err := x86AddSubLiteralRewriteSource(data); err != nil {
				t.Fatal(err)
			}
		} else {
			for _, op := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
				if !bytes.Contains(data, []byte("{A"+op+", yxm,")) {
					t.Fatalf("actual Go no longer uses yxm for %s", op)
				}
			}
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		for _, op := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
			for _, value := range x86AddSubLiteralValues {
				for _, register := range []int{0, 7, 8, 15} {
					row := fmt.Sprintf("%s $%s,X%d", op, value.text, register)
					entry := fmt.Sprintf("TEXT literal%d(SB),4,$0-0\n%s\nRET\n", source.Len(), row)
					if arch == "386" && register >= 8 {
						x86ScalarLiteralExpectedGoListing(t, arch, entry, false)
						continue
					}
					source.WriteString(entry)
				}
			}
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range x86AddSubLiteralValues {
			for _, pool := range []string{fmt.Sprintf("$f32.%08x", value.bits32), fmt.Sprintf("$f64.%016x", value.bits64)} {
				if !strings.Contains(listing, pool) {
					t.Fatalf("actual Go pool rounding/sign missing %s", pool)
				}
			}
		}
		if strings.Contains(listing, "XORPS") {
			t.Fatal("arithmetic zero literal incorrectly acquired MOV zero rewrite")
		}
	}
}

// Independently bind the actual encoder's complete scalar pool-rewrite body,
// not just the presence of an opcode name somewhere in the source file.
func x86AddSubLiteralRewriteSource(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "obj6.go", source, 0)
	if err != nil {
		return err
	}
	seen := make(map[string]int)
	var progedit *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "progedit" {
			if progedit != nil || function.Body == nil {
				return fmt.Errorf("missing or duplicate progedit body")
			}
			progedit = function
		}
	}
	if progedit == nil {
		return fmt.Errorf("actual Go progedit missing")
	}
	allowed := make(map[*ast.CaseClause]bool)
	for _, statement := range progedit.Body.List {
		switchStatement, ok := statement.(*ast.SwitchStmt)
		if !ok || switchStatement.Init != nil {
			continue
		}
		selector, ok := switchStatement.Tag.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "As" {
			continue
		}
		base, ok := selector.X.(*ast.Ident)
		if !ok || base.Name != "p" {
			continue
		}
		for _, entry := range switchStatement.Body.List {
			if clause, ok := entry.(*ast.CaseClause); ok {
				allowed[clause] = true
			}
		}
	}
	var failure error
	ast.Inspect(progedit.Body, func(node ast.Node) bool {
		clause, ok := node.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expression := range clause.List {
			name, ok := expression.(*ast.Ident)
			if !ok || name.Name != "AADDSS" && name.Name != "AADDSD" && name.Name != "ASUBSS" && name.Name != "ASUBSD" {
				continue
			}
			seen[name.Name]++
			if !allowed[clause] {
				failure = fmt.Errorf("nested or conditional literal rewrite %s", name.Name)
			}
			bits := 64
			if strings.HasSuffix(name.Name, "SS") {
				bits = 32
			}
			expected := fmt.Sprintf(`package p
func f() {
if p.From.Type == obj.TYPE_FCONST {
	f%d := %s
	p.From.Type = obj.TYPE_MEM
	p.From.Name = obj.NAME_EXTERN
	p.From.Sym = ctxt.Float%dSym(f%d)
	p.From.Offset = 0
}
}`, bits, map[int]string{32: "float32(p.From.Val.(float64))", 64: "p.From.Val.(float64)"}[bits], bits, bits)
			fixture, err := parser.ParseFile(token.NewFileSet(), "expected.go", expected, 0)
			if err != nil {
				failure = err
				continue
			}
			body, err := x86ScalarLiteralBodySyntax(clause.Body)
			want, wantErr := x86ScalarLiteralBodySyntax(fixture.Decls[0].(*ast.FuncDecl).Body.List)
			if err != nil || wantErr != nil || body != want {
				failure = fmt.Errorf("unrecognized actual Go %s literal rewrite body", name.Name)
			}
		}
		return true
	})
	for _, name := range []string{"AADDSS", "AADDSD", "ASUBSS", "ASUBSD"} {
		if seen[name] != 1 {
			return fmt.Errorf("actual Go literal rewrite registration %s count=%d", name, seen[name])
		}
	}
	return failure
}

func TestX86FloatAddSubLiteralRewriteSourceRejectsMutation(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/obj6.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86AddSubLiteralRewriteSource(source); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(source)
	for _, replacement := range [][2]string{
		{"func progedit(", "func unrelated("},
		{"AADDSS,", "AADDPS,"}, {"ASUBSD,", "ASUBPD,"},
		{"ctxt.Float32Sym(f32)", "ctxt.Float64Sym(f32)"}, {"p.From.Offset = 0", "p.From.Offset = 4"},
	} {
		mutated := bytes.ReplaceAll(source, []byte(replacement[0]), []byte(replacement[1]))
		if bytes.Equal(mutated, source) || x86AddSubLiteralRewriteSource(mutated) == nil {
			t.Fatalf("unknown source rewrite accepted: %q", replacement)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != before {
		t.Fatalf("source mutation oracle changed the real SDK: %v", err)
	}
}

func TestX86FloatAddSubLiteralOriginalInstructionBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			opcode             string
			prefix, opcodeByte byte
		}{
			{"ADDSS", 0xf3, 0x58}, {"ADDSD", 0xf2, 0x58},
			{"SUBSS", 0xf3, 0x5c}, {"SUBSD", 0xf2, 0x5c},
		} {
			for _, literal := range []string{"0.0", "-0.0", "1.0", "0x1.4p0"} {
				code := x86PackedFirstGoInstructionBytes(t, arch, row.opcode+" $"+literal+",X0")
				if !bytes.Equal(code[:4], []byte{row.prefix, 0x0f, row.opcodeByte, 0x05}) {
					t.Fatalf("%s %s literal %s original bytes=%x", arch, row.opcode, literal, code)
				}
			}
		}
	}
}

func TestX86FloatAddSubLiteralCallerKeepsDefinedBytes(t *testing.T) {
	for _, opcode := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
		file, err := Parse(ArchAMD64, "TEXT literal(SB),4,$0-0\n"+opcode+" $-0.0,X0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86FloatAddSubProperties(ins, "amd64")
		if !recognized || err != nil || !form.literal || form.memory != -1 || form.memoryBytes != 0 {
			t.Fatalf("literal confused with caller memory: %+v / %v", form, err)
		}
		low := x86CallerVectorByteMask(int64(form.bits / 8))
		for _, old := range []uint64{0, low &^ 1, low, low | 0xf0000000, ^uint64(0)} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": old}, masks: map[Reg]bool{}}
			before, _ := x86CloneCallerVectorState(state.vectors, state.masks)
			accepted := x86CallerFloatAddSubStep(&ins, form, &state, nil)
			if accepted != (old&low == low) || !accepted && !reflect.DeepEqual(before, state.vectors) || accepted && state.vectors["Z0"] != old {
				t.Fatalf("%s invented destination/upper knowledge: old=%x state=%x accepted=%t", opcode, old, state.vectors["Z0"], accepted)
			}
		}
		// Source spelling is not permission to use a different typed value.
		ins.Args[0].Imm++
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		_, _, err = ctx.lowerFloatAddSub(ins.Op, ins)
		if err == nil || output.String() != before {
			t.Fatal("mismatched literal/source bits emitted IR")
		}
	}
}

func TestX86FloatAddSubLiteralThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var declarations, source strings.Builder
			for _, op := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
				for _, value := range x86AddSubLiteralValues {
					name := strings.ToLower(op) + value.name
					fmt.Fprintf(&declarations, "func %s()\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\nPXOR X0,X0\n%s $%s,X0\nRET\n", name, op, value.text)
				}
			}
			pkg := x86AddSubLiteralPackage(t, target.arch, declarations.String())
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(sym string) string { return strings.Replace(sym, "·", "literal.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					var ir string
					var err error
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						var module llvm.Module
						module, err = TranslateModuleInContext(ctx, file, options)
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
					case "GoModule":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(ctx, pkg, []byte(source.String()), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "add-sub-literal.ll", "add-sub-literal.o", ir)
				})
			}
		})
	}
}

func TestX86FloatAddSubLiteralRejectsNonGoFormats(t *testing.T) {
	for _, row := range []string{
		"ADDSD $1,X0", "ADDSS $0,X0", "SUBSD $0x3ff0000000000000,X0",
		"ADDSD $(1.0+2.0),X0", "SUBSS $(1.0/2.0),X0", "ADDSS $1e999,X0",
		"ADDPS $1.0,X0", "ADDPD $1.0,X0", "SUBPS $1.0,X0", "SUBPD $1.0,X0",
		"VADDSS $1.0,X0,X1", "VADDSD $1.0,X0,X1", "VSUBSS $1.0,X0,X1", "VSUBSD $1.0,X0,X1",
		"ADDSD.Z $1.0,X0", "ADDSS $1.0,Y0", "SUBSD $1.0,X16", "ADDSD X0,$1.0",
	} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT literal(SB),4,$0-0\n" + row + "\nRET\n"
			x86ScalarLiteralExpectedGoListing(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			ins := file.Funcs[0].Instrs[1]
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerFloatAddSub(ins.Op, ins)
			if !known || term || err == nil || before != output.String() {
				t.Fatalf("non-Go literal emitted IR: %t/%t/%v", known, term, err)
			}
		})
	}
}
