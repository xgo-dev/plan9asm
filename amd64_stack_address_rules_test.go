package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86StackAddressEncoderCarrier(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "asm6.go", source, 0)
	if err != nil {
		return err
	}
	canonical := func(node ast.Node) string {
		var output bytes.Buffer
		if err := format.Node(&output, token.NewFileSet(), node); err != nil {
			return ""
		}
		return output.String()
	}
	variables := make(map[string]*ast.CompositeLit)
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for index, name := range value.Names {
				if index < len(value.Values) {
					if literal, ok := value.Values[index].(*ast.CompositeLit); ok {
						variables[name.Name] = literal
					}
				}
			}
		}
	}
	const table = `[]ytab{
		{Zrp_, 1, argList{Yrl}},
		{Zm_o, 2, argList{Ym}},
		{Zib_, 1, argList{Yi8}},
		{Zil_, 1, argList{Yi32}},
	}`
	wantTable, err := parser.ParseExpr(table)
	if err != nil || variables["ypushl"] == nil || canonical(variables["ypushl"]) != canonical(wantTable) {
		return fmt.Errorf("complete ordered PUSH operand/encoder rows changed")
	}
	registrations := map[string]string{
		"APUSHL": `{APUSHL, ypushl, P32, opBytes{0x50, 0xff, 06, 0x6a, 0x68}}`,
		"APUSHQ": `{APUSHQ, ypushl, Py, opBytes{0x50, 0xff, 06, 0x6a, 0x68}}`,
		"APUSHW": `{APUSHW, ypushl, Pe, opBytes{0x50, 0xff, 06, 0x6a, 0x68}}`,
	}
	optab := variables["optab"]
	if optab == nil {
		return fmt.Errorf("missing complete Go opcode table")
	}
	seen := make(map[string]bool)
	for _, entry := range optab.Elts {
		row, ok := entry.(*ast.CompositeLit)
		if !ok || len(row.Elts) == 0 {
			continue
		}
		name := canonical(row.Elts[0])
		text, relevant := registrations[name]
		if !relevant {
			continue
		}
		want, err := parser.ParseExpr("[]Optab{" + text + "}")
		if err != nil || seen[name] || canonical(row) != canonical(want.(*ast.CompositeLit).Elts[0]) {
			return fmt.Errorf("complete PUSH registration changed: %s", name)
		}
		seen[name] = true
	}
	if len(seen) != len(registrations) {
		return fmt.Errorf("incomplete PUSH opcode inventory")
	}
	const absolute = `package reference
func useAbs(ctxt *obj.Link, s *obj.LSym) bool {
	if ctxt.Headtype == objabi.Hsolaris {
		return strings.HasPrefix(s.Name, "libc_")
	}
	return ctxt.Arch.Family == sys.I386 && !ctxt.Flag_shared
}`
	wantAbsolute, err := parser.ParseFile(token.NewFileSet(), "reference.go", absolute, 0)
	if err != nil || functions["useAbs"] == nil ||
		canonical(functions["useAbs"]) != canonical(wantAbsolute.Decls[0]) {
		return fmt.Errorf("absolute-relocation source mode changed")
	}
	const address = `package reference
func oclass() { switch kind {
case obj.TYPE_ADDR:
	switch a.Name {
	case obj.NAME_GOTREF:
		ctxt.Diag("unexpected TYPE_ADDR with NAME_GOTREF")
		return Yxxx
	case obj.NAME_EXTERN, obj.NAME_STATIC:
		if a.Sym != nil && useAbs(ctxt, a.Sym) { return Yi32 }
		return Yiauto
	case obj.NAME_AUTO, obj.NAME_PARAM:
		return Yiauto
	}
	if a.Sym != nil && strings.HasPrefix(a.Sym.Name, "runtime.duff") { return Yi32 }
	if a.Sym != nil || a.Name != obj.NAME_NONE { ctxt.Diag("unexpected addr: %v", obj.Dconv(p, a)) }
	fallthrough
} }`
	wantAddress, err := parser.ParseFile(token.NewFileSet(), "reference.go", address, 0)
	if err != nil || functions["oclass"] == nil {
		return fmt.Errorf("missing complete address classifier")
	}
	findAddress := func(function *ast.FuncDecl) *ast.CaseClause {
		var result *ast.CaseClause
		ast.Inspect(function.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expression := range clause.List {
				if canonical(expression) == "obj.TYPE_ADDR" {
					result = clause
				}
			}
			return true
		})
		return result
	}
	actualAddress := findAddress(functions["oclass"])
	if actualAddress == nil || canonical(actualAddress) != canonical(findAddress(wantAddress.Decls[0].(*ast.FuncDecl))) {
		return fmt.Errorf("complete named address classification changed")
	}
	const emitter = `package reference
func doasm() { switch encoding {
case Z_il, Zil_:
	var a *obj.Addr
	if yt.zcase == Zil_ { a = &p.From } else { a = &p.To }
	ab.Put1(byte(op))
	if o.prefix == Pe {
		v := vaddr(ctxt, p, a, nil)
		ab.PutInt16(int16(v))
	} else { ab.relput4(ctxt, cursym, p, a) }
} }`
	findEmitter := func(function *ast.FuncDecl) *ast.CaseClause {
		if function == nil {
			return nil
		}
		var result *ast.CaseClause
		ast.Inspect(function.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if ok && len(clause.List) == 2 && canonical(clause.List[0]) == "Z_il" && canonical(clause.List[1]) == "Zil_" {
				result = clause
			}
			return true
		})
		return result
	}
	actualEmitter := findEmitter(functions["doasm"])
	emitterMatched := false
	oldEmitter := strings.Replace(emitter, "\tvar a *obj.Addr\n", "", 1)
	oldEmitter = strings.Replace(oldEmitter, "v := vaddr", "v = vaddr", 1)
	for _, reference := range []string{emitter, oldEmitter} {
		want, err := parser.ParseFile(token.NewFileSet(), "reference.go", reference, 0)
		if err == nil && actualEmitter != nil && canonical(actualEmitter) == canonical(findEmitter(want.Decls[0].(*ast.FuncDecl))) {
			emitterMatched = true
		}
	}
	if !emitterMatched {
		return fmt.Errorf("complete PUSH relocation emitter changed")
	}
	const relocation = `package reference
func (ab *AsmBuf) relput4(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr) {
	var rel obj.Reloc
	v := vaddr(ctxt, p, a, &rel)
	if rel.Siz != 0 {
		if rel.Siz != 4 { ctxt.Diag("bad reloc") }
		rel.Off = int32(p.Pc + int64(ab.Len()))
		cursym.AddRel(ctxt, rel)
	}
	ab.PutInt32(int32(v))
}`
	oldRelocation := strings.Replace(relocation,
		"rel.Off = int32(p.Pc + int64(ab.Len()))\n\t\tcursym.AddRel(ctxt, rel)",
		"r := obj.Addrel(cursym)\n\t\t*r = rel\n\t\tr.Off = int32(p.Pc + int64(ab.Len()))", 1)
	relocationMatched := false
	for _, reference := range []string{relocation, oldRelocation} {
		want, err := parser.ParseFile(token.NewFileSet(), "reference.go", reference, 0)
		if err == nil && functions["relput4"] != nil && canonical(functions["relput4"]) == canonical(want.Decls[0]) {
			relocationMatched = true
		}
	}
	if !relocationMatched {
		return fmt.Errorf("complete four-byte relocation sink changed")
	}
	const value = `package reference
func vaddr(ctxt *obj.Link, p *obj.Prog, a *obj.Addr, r *obj.Reloc) int64 {
	if r != nil { *r = obj.Reloc{} }
	switch a.Name {
	case obj.NAME_STATIC, obj.NAME_GOTREF, obj.NAME_EXTERN:
		s := a.Sym
		if r == nil {
			ctxt.Diag("need reloc for %v", obj.Dconv(p, a))
			log.Fatalf("reloc")
		}
		if a.Name == obj.NAME_GOTREF {
			r.Siz = 4
			r.Type = objabi.R_GOTPCREL
		} else if useAbs(ctxt, s) {
			r.Siz = 4
			r.Type = objabi.R_ADDR
		} else {
			r.Siz = 4
			r.Type = objabi.R_PCREL
		}
		r.Off = -1
		r.Sym = s
		r.Add = a.Offset
		return 0
	}
	if (a.Type == obj.TYPE_MEM || a.Type == obj.TYPE_ADDR) && a.Reg == REG_TLS {
		if r == nil {
			ctxt.Diag("need reloc for %v", obj.Dconv(p, a))
			log.Fatalf("reloc")
		}
		if !ctxt.Flag_shared || isAndroid || ctxt.Headtype == objabi.Hdarwin {
			r.Type = objabi.R_TLS_LE
			r.Siz = 4
			r.Off = -1
			r.Add = a.Offset
		}
		return 0
	}
	return a.Offset
}`
	wantValue, err := parser.ParseFile(token.NewFileSet(), "reference.go", value, 0)
	if err != nil || functions["vaddr"] == nil || canonical(functions["vaddr"]) != canonical(wantValue.Decls[0]) {
		return fmt.Errorf("complete relocation value calculation changed")
	}
	return nil
}

func TestX86StackNamedAddressCompleteGoRuleCarrier(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := x86StackAddressEncoderCarrier(source); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, from, to string }{
		{"class", "{Zil_, 1, argList{Yi32}}", "{Zil_, 1, argList{Yiauto}}"},
		{"arity", "{Zil_, 1, argList{Yi32}}", "{Zil_, 1, argList{Yi32, Yrl}}"},
		{"encoder", "{Zil_, 1, argList{Yi32}}", "{Zib_, 1, argList{Yi32}}"},
		{"offset", "{Zil_, 1, argList{Yi32}}", "{Zil_, 2, argList{Yi32}}"},
		{"mode", "{APUSHL, ypushl, P32,", "{APUSHL, ypushl, Py,"},
		{"bytes", "{APUSHL, ypushl, P32, opBytes{0x50,", "{APUSHL, ypushl, P32, opBytes{0x51,"},
		{"shared", "return ctxt.Arch.Family == sys.I386 && !ctxt.Flag_shared", "return ctxt.Arch.Family == sys.I386"},
		{"absolute", "if a.Sym != nil && useAbs(ctxt, a.Sym) {", "if a.Sym != nil {"},
		{"emitter", "case Z_il, Zil_:", "case Z_il, Zil_rr:"},
		{"operand direction", "if yt.zcase == Zil_ {", "if yt.zcase == Z_il {"},
		{"relocation sink", "v := vaddr(ctxt, p, a, &rel)", "v := vaddr(ctxt, p, a, nil)"},
		{"absolute relocation", "} else if useAbs(ctxt, s) {", "} else if s != nil {"},
		{"missing sink", "log.Fatalf(\"reloc\")", "return 0"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if !strings.Contains(string(source), mutation.from) {
				t.Fatal("mutation missed its actual source rule")
			}
			changed := strings.Replace(string(source), mutation.from, mutation.to, 1)
			if x86StackAddressEncoderCarrier([]byte(changed)) == nil {
				t.Fatal("changed source rule retained its family certificate")
			}
		})
	}
}

func TestX86StackNamedAddressSourceClassDoesNotGrantMemory(t *testing.T) {
	for _, spelling := range []string{
		"$·cell(SB)", "$cell<>+8(SB)", " \t$runtime·mainPC(SB)",
		"$·cell(SB)(AX)", "$·cell(SB)(R8)(X1*4)",
	} {
		operand, err := parseOperandForArch(ArchAMD64, strings.TrimSpace(spelling))
		if err != nil || !x86AbsoluteRelocationSource(operand, "386", 32) || isAMD64MemoryOperand(operand) {
			t.Fatalf("independent absolute source class changed: %s: %v", spelling, err)
		}
		before := operand
		for _, arch := range []string{"386", "amd64", "arm64"} {
			for _, bits := range []int{8, 16, 32, 64} {
				want := arch == "386" && bits == 32
				if x86AbsoluteRelocationSource(operand, arch, bits) != want || !reflect.DeepEqual(operand, before) {
					t.Fatal("pure source classification changed operand identity or source mode")
				}
			}
		}
	}
	for _, spelling := range []string{
		"·cell(SB)", "$16(AX)", "$arg+0(FP)", "$local-8(SP)",
		"$16(SB)", "$·cell*(SB)", "$$·cell(SB)",
	} {
		operand, err := parseOperandForArch(ArchAMD64, spelling)
		if err == nil && x86AbsoluteRelocationSource(operand, "386", 32) {
			t.Fatal("unregistered source role acquired relocation permission:", spelling)
		}
	}
}
