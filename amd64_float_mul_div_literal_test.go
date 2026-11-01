package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
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

var x86MulDivLiteralValues = []x86ScalarLiteralValue{
	{name: "reduce", text: "0.0625", bits32: 0x3d800000, bits64: 0x3fb0000000000000},
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
	{name: "leadingDot", text: ".5", bits32: 0x3f000000, bits64: 0x3fe0000000000000},
	{name: "trailingDot", text: "1.", bits32: 0x3f800000, bits64: 0x3ff0000000000000},
	{name: "exponent", text: "1E+2", bits32: 0x42c80000, bits64: 0x4059000000000000},
	{name: "hexExponent", text: "0x1p-4", bits32: 0x3d800000, bits64: 0x3fb0000000000000},
	{name: "doubleNegativeZero", text: "--0.0"},
	{name: "unaryNegativeZero", text: "-(0.0)", bits32: 0x80000000, bits64: 0x8000000000000000},
	{name: "negativeUnderflow32", text: "-1e-50", bits32: 0x80000000, bits64: 0xb58dee7a4ad4b81f},
	{name: "negativeOverflow32", text: "-1e40", bits32: 0xff800000, bits64: 0xc83d6329f1c35ca5},
}

func TestX86FloatMulDivLiteralMathArchExp(t *testing.T) {
	x86ScalarLiteralActualGoRewriteSet(t)
	path := filepath.Join(runtime.GOROOT(), "src/math/exp_amd64.s")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(original)
	row := "MULSD   $0.0625, X0"
	if bytes.Count(original, []byte(row)) != 2 {
		t.Fatal("original math.archExp no longer contains both literal reductions")
	}
	// The source row is original. The surrounding first-party function has
	// an explicit initialized scalar parameter/result, not guessed math ABI.
	source := "TEXT ·Reduce(SB),4,$0-16\nMOVSD input+0(FP),X0\n" + row + "\nMOVSD X0,ret+8(FP)\nRET\n"
	x86ScalarLiteralGoListing(t, "amd64", source)
	pkg := x86MulDivLiteralPackage(t, "amd64", "func Reduce(input float64) float64\n")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != before {
		t.Fatalf("actual original math source changed: %v", err)
	}
	t.Logf("original math.archExp source SHA256=%x; both reduction rows retain initialized scalar semantics", before)
}

func x86MulDivLiteralPackage(t *testing.T, arch, declarations string) GoPackage {
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

func TestX86FloatMulDivLiteralActualGoObjects(t *testing.T) {
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
			if err := x86MulDivLiteralRewriteSource(data); err != nil {
				t.Fatal(err)
			}
		} else {
			for _, op := range []string{"MULSS", "MULSD", "DIVSS", "DIVSD"} {
				if !bytes.Contains(data, []byte("{A"+op+", yxm,")) {
					t.Fatalf("actual Go no longer uses yxm for %s", op)
				}
			}
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		for _, op := range []string{"MULSS", "MULSD", "DIVSS", "DIVSD"} {
			for _, value := range x86MulDivLiteralValues {
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
		for _, value := range x86MulDivLiteralValues {
			for _, pool := range []struct {
				name  string
				bits  uint64
				width int
			}{
				{fmt.Sprintf("$f32.%08x", value.bits32), uint64(value.bits32), 4},
				{fmt.Sprintf("$f64.%016x", value.bits64), value.bits64, 8},
			} {
				if !strings.Contains(listing, pool.name) {
					t.Fatalf("actual Go pool rounding/sign missing %s", pool.name)
				}
				start := strings.Index(listing, pool.name+" SRODATA")
				if start < 0 {
					t.Fatalf("actual Go pool has no original DATA payload: %s", pool.name)
				}
				var payload []byte
				for _, line := range strings.Split(listing[start:], "\n")[1:] {
					data := x86InsertExtractListedBytes(line)
					if len(data) == 0 {
						break
					}
					payload = append(payload, data...)
				}
				var want [8]byte
				binary.LittleEndian.PutUint64(want[:], pool.bits)
				if !bytes.Equal(payload, want[:pool.width]) {
					t.Fatalf("actual original pool %s bytes=%x want=%x", pool.name, payload, want[:pool.width])
				}
			}
		}
		if strings.Contains(listing, "XORPS") {
			t.Fatal("arithmetic zero literal incorrectly acquired MOV zero rewrite")
		}
	}
}

func TestX86FloatMulDivLiteralCallerSourceContracts(t *testing.T) {
	for _, opcode := range []string{"MULSS", "MULSD", "DIVSS", "DIVSD"} {
		move, result := "MOVSS", "float32"
		if strings.HasSuffix(opcode, "SD") {
			move, result = "MOVSD", "float64"
		}
		body := fmt.Sprintf("%s (DI),X15\n%s $0.0625,X15\n%s X15,(DX)", move, opcode, move)
		for _, target := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			t.Run(opcode+"/"+target, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, strings.ReplaceAll(x86CallerFixtureSource, "float32", result), assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, target); err != nil {
					t.Fatal(err)
				}
			})
		}
		for name, unsafe := range map[string]string{
			"undefined low bytes":      fmt.Sprintf("%s $1.0,X0\n%s X0,(DX)", opcode, move),
			"pointer input":            fmt.Sprintf("MOVQ DI,X0\n%s $1.0,X0\n%s X0,(DX)", opcode, move),
			"private stack bits":       fmt.Sprintf("MOVQ SP,X0\n%s $1.0,X0\n%s X0,(DX)", opcode, move),
			"read-only input store":    strings.Replace(body, "(DX)", "(DI)", 1),
			"one-byte result overflow": strings.Replace(body, "(DX)", "1(DX)", 1),
			"unproved source memory":   strings.Replace(body, "(DI)", "(BX)", 1),
			"FP pointer contents":      fmt.Sprintf("%s a+0(FP),X0\n%s $1.0,X0\n%s X0,(DX)", move, opcode, move),
			"join lacks input":         fmt.Sprintf("CMPQ AX,$0\nJE joined\n%s (DI),X15\njoined:\n%s $1.0,X15\n%s X15,(DX)", move, opcode, move),
		} {
			t.Run(opcode+"/"+name, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", unsafe, 1)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, strings.ReplaceAll(x86CallerFixtureSource, "float32", result), assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("literal invented source/extent/escape evidence: %v", err)
				}
			})
		}
	}
}

// Independently bind the actual encoder's complete scalar pool-rewrite body,
// not just the presence of an opcode name somewhere in the source file.
func x86MulDivLiteralRewriteSource(source []byte) error {
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
			if !ok || name.Name != "AMULSS" && name.Name != "AMULSD" && name.Name != "ADIVSS" && name.Name != "ADIVSD" {
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
	for _, name := range []string{"AMULSS", "AMULSD", "ADIVSS", "ADIVSD"} {
		if seen[name] != 1 {
			return fmt.Errorf("actual Go literal rewrite registration %s count=%d", name, seen[name])
		}
	}
	return failure
}

func TestX86FloatMulDivLiteralRewriteSourceRejectsMutation(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/obj6.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86MulDivLiteralRewriteSource(source); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(source)
	for _, replacement := range [][2]string{
		{"func progedit(", "func unrelated("},
		{"AMULSS,", "AMULPS,"}, {"ADIVSD,", "ADIVPD,"},
		{"ctxt.Float32Sym(f32)", "ctxt.Float64Sym(f32)"}, {"p.From.Offset = 0", "p.From.Offset = 4"},
	} {
		mutated := bytes.ReplaceAll(source, []byte(replacement[0]), []byte(replacement[1]))
		if bytes.Equal(mutated, source) || x86MulDivLiteralRewriteSource(mutated) == nil {
			t.Fatalf("unknown source rewrite accepted: %q", replacement)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != before {
		t.Fatalf("source mutation oracle changed the real SDK: %v", err)
	}
}

func TestX86FloatMulDivLiteralOriginalInstructionBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			opcode             string
			prefix, opcodeByte byte
		}{
			{"MULSS", 0xf3, 0x59}, {"MULSD", 0xf2, 0x59},
			{"DIVSS", 0xf3, 0x5e}, {"DIVSD", 0xf2, 0x5e},
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

func TestX86FloatMulDivLiteralCallerKeepsDefinedBytes(t *testing.T) {
	for _, opcode := range []string{"MULSS", "MULSD", "DIVSS", "DIVSD"} {
		file, err := Parse(ArchAMD64, "TEXT literal(SB),4,$0-0\n"+opcode+" $-0.0,X0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86FloatMulDivProperties(ins, "amd64")
		if !recognized || err != nil || !form.literal || form.memory != -1 || form.memoryBytes != 0 {
			t.Fatalf("literal confused with caller memory: %+v / %v", form, err)
		}
		low := x86CallerVectorByteMask(int64(form.bits / 8))
		for _, old := range []uint64{0, low &^ 1, low, low | 0xf0000000, ^uint64(0)} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": old}, masks: map[Reg]bool{}}
			before, _ := x86CloneCallerVectorState(state.vectors, state.masks)
			accepted := x86CallerFloatBinaryStep(&ins, form.x86FloatBinaryForm, &state, nil)
			if accepted != (old&low == low) || !accepted && !reflect.DeepEqual(before, state.vectors) || accepted && state.vectors["Z0"] != old {
				t.Fatalf("%s invented destination/upper knowledge: old=%x state=%x accepted=%t", opcode, old, state.vectors["Z0"], accepted)
			}
		}
		// Source spelling is not permission to use a different typed value.
		ins.Args[0].Imm++
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		_, _, err = ctx.lowerFloatMulDiv(ins.Op, ins)
		if err == nil || output.String() != before {
			t.Fatal("mismatched literal/source bits emitted IR")
		}
	}
}

func TestX86FloatMulDivLiteralThreeAPIsFiveTargets(t *testing.T) {
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
			for _, op := range []string{"MULSS", "MULSD", "DIVSS", "DIVSD"} {
				for _, value := range x86MulDivLiteralValues {
					name := strings.ToLower(op) + value.name
					fmt.Fprintf(&declarations, "func %s()\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\nPXOR X0,X0\n%s $%s,X0\nRET\n", name, op, value.text)
				}
			}
			pkg := x86MulDivLiteralPackage(t, target.arch, declarations.String())
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
					compileLLVMToObject(t, llc, target.triple, "mul-div-literal.ll", "mul-div-literal.o", ir)
					x86MulDivLiteralOptimizedObject(t, llc, target.triple, ir)
				})
			}
		})
	}
}

func TestX86FloatMulDivLiteralRejectsNonGoFormats(t *testing.T) {
	for _, row := range []string{
		"MULSD $1,X0", "MULSS $0,X0", "DIVSD $0x3ff0000000000000,X0",
		"MULSD $(1.0+2.0),X0", "DIVSS $(1.0/2.0),X0", "MULSS $1e999,X0",
		"MULPS $1.0,X0", "MULPD $1.0,X0", "DIVPS $1.0,X0", "DIVPD $1.0,X0",
		"VMULSS $1.0,X0,X1", "VMULSD $1.0,X0,X1", "VDIVSS $1.0,X0,X1", "VDIVSD $1.0,X0,X1",
		"MULSD.Z $1.0,X0", "MULSS $1.0,Y0", "DIVSD $1.0,X16", "MULSD X0,$1.0",
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
			known, term, err := ctx.lowerFloatMulDiv(ins.Op, ins)
			if !known || term || err == nil || before != output.String() {
				t.Fatalf("non-Go literal emitted IR: %t/%t/%v", known, term, err)
			}
		})
	}
}

// Keep this consumer's lifecycle inventory independent of the shared file,
// which has another writer. The actual original-Go test still uses the same
// bounded owned command helper as all other native numerical oracles.
func TestX86FloatMulDivLiteralCommandLifecycle(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_float_mul_div_literal_runtime_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	commands, consumers := 0, 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if function, ok := call.Fun.(*ast.Ident); ok && function.Name == "runtimeOracleCombinedOutput" {
			consumers++
		}
		if method, ok := call.Fun.(*ast.SelectorExpr); ok {
			if owner, ok := method.X.(*ast.Ident); ok && owner.Name == "exec" && method.Sel.Name == "CommandContext" {
				commands++
			}
			switch method.Sel.Name {
			case "CombinedOutput", "Output", "Start", "Run":
				if owner, ok := method.X.(*ast.Ident); !ok || owner.Name != "t" {
					t.Errorf("literal oracle bypasses owned lifecycle: %s", method.Sel.Name)
				}
			}
		}
		return true
	})
	if commands != 2 || consumers != 2 {
		t.Fatalf("original-Go literal command lifecycle missing: commands=%d consumers=%d", commands, consumers)
	}
}
