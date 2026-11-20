package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86SymbolIndexedAddressGoRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			operand     string
			accepted64  bool
			base, index Reg
			scale       int64
		}{
			{"dst_base+0(FP)(SI*1)", true, "", SI, 1},
			{"dst_base + (2 * 4) (FP) (CX * 2)", true, "", CX, 2},
			{"local-8(SP)(BX*4)", true, "", BX, 4},
			{"table<>+8(SB)(BX*8)", false, "", BX, 8},
			{"dst_base(FP)(SI)", false, SI, "", 0},
			{"dst_base(FP)(SP)", true, SP, "", 0},
			{"dst_base(FP)(SP)(CX*2)", true, SP, CX, 2},
			{"dst_base(FP)(SI)(CX*2)", false, SI, CX, 2},
			{"table<>(SB)(SI)", false, SI, "", 0},
			{"table<>(SB)(SI)(CX*2)", false, SI, CX, 2},
		} {
			t.Run(arch+"/"+row.operand, func(t *testing.T) {
				source := "TEXT index(SB),4,$0-32\nLEAL " + row.operand + ",AX\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, source, arch == "386" || row.accepted64)
				operand, err := parseOperandForArch(ArchAMD64, row.operand)
				if err != nil || operand.Kind != OpMem || operand.Mem.Sym == "" ||
					operand.Mem.Base != row.base || operand.Mem.Index != row.index || operand.Mem.Scale != row.scale {
					t.Fatalf("symbol role/base/index was lost: %+v / %v", operand, err)
				}
				copy, err := parseOperandForArch(ArchAMD64, operand.String())
				if err != nil || !reflect.DeepEqual(copy, operand) {
					t.Fatalf("typed address round trip changed role: %s => %+v / %v", operand.String(), copy, err)
				}
			})
		}
	}
}

func TestX86SymbolIndexedAddressCompleteNamedForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		widths := []string{"W", "L"}
		if arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			for _, role := range []string{"FP", "SP", "SB"} {
				for _, prefix := range []string{"arg", "arg+0", "arg-8", "arg + (2 * 4)"} {
					for _, scale := range []string{"1", "2", "4", "8"} {
						operand := prefix + "(" + role + ")(CX*" + scale + ")"
						t.Run(arch+"/"+width+"/"+operand, func(t *testing.T) {
							source := "TEXT index(SB),4,$0-32\nLEA" + width + " " + operand + ",AX\nRET\n"
							x86ScalarLiteralExpectedGoListing(t, arch, source, arch == "386" || role != "SB")
							parsed, err := parseOperandForArch(ArchAMD64, operand)
							if err != nil || parsed.Kind != OpMem || parsed.Mem.Index != CX || parsed.Mem.Sym != prefix+"("+role+")" {
								t.Fatalf("named address roles: %+v / %v", parsed, err)
							}
							_, err = x86LEAOperandWidth(Instr{Op: Op("LEA" + width), Args: []Operand{parsed, {Kind: OpReg, Reg: AX}}}, arch)
							if role != "SB" && !errors.Is(err, ErrProbeNeedsContext) || role == "SB" && (err == nil) != (arch == "386") {
								t.Fatalf("encoding shape borrowed storage permission: %v", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86SymbolIndexedAddressRejectsMalformedGroups(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, operand := range []string{
			"0(FP)(CX*2)", "0(SB)(CX*2)", "arg+UNKNOWN(FP)(CX*2)",
			"arg(FP)(AX+CX)",
			"arg(FP)(CX*2)(DX*4)", "arg(FP)(AX)(CX*2)(DX*4)",
			"arg(FP)(RAX*2)", "arg(FP)(CX*2)trailing", "arg(FP)(CX*2",
		} {
			t.Run(arch+"/"+operand, func(t *testing.T) {
				source := "TEXT index(SB),4,$0-32\nLEAL " + operand + ",AX\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, source, false)
				if _, err := parseOperandForArch(ArchAMD64, operand); err == nil {
					t.Fatal("malformed group fell back to an ordinary symbol")
				}
			})
		}
	}
}

func TestX86SymbolIndexedAddressPseudoOverwriteNeedsContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range [][2]string{{"arg(FP)(FP*2)", "arg(FP)"}, {"arg(FP)(SB*2)", "arg(SB)"}} {
			source := func(operand string) string {
				return "TEXT index(SB),4,$0-32\nLEAL " + operand + ",AX\nRET\n"
			}
			left := x86PackedShiftActualGoBytes(t, arch, source(row[0]))
			right := x86PackedShiftActualGoBytes(t, arch, source(row[1]))
			if !bytes.Equal(left, right) {
				t.Fatalf("actual Go pseudo role overwrite: %v: %x != %x", row, left, right)
			}
			if _, err := parseOperandForArch(ArchAMD64, row[0]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unbound alternate pseudo role did not remain Context: %v", err)
			}
		}
	}
	operand, err := parseOperandForArch(ArchAMD64, "arg(SB)(SI)(CX)")
	if err != nil || operand.Kind != OpMem || operand.Mem.Index != CX || operand.Mem.Scale != 0 {
		t.Fatalf("unscaled third group role was lost: %+v / %v", operand, err)
	}
	if err := x86SymbolIndexedMemoryError(operand.Mem, "386"); err == nil {
		t.Fatal("Go asmidx rejects zero scale; it must not be normalized to one")
	}
}

func TestX86SymbolIndexedAddressActualObjectRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		pc := 8
		if arch == "386" {
			pc = 4
		}
		for _, row := range []struct{ symbolic, physical string }{
			{"arg+0(FP)(SI*1)", fmt.Sprintf("%d(SP)(SI*1)", pc)},
			{"arg+(2*4)(FP)(CX*2)", fmt.Sprintf("%d(SP)(CX*2)", pc+8)},
			{"local+8(SP)(BX*4)", "8(SP)(BX*4)"},
			{"arg(FP)(SP)(CX*2)", fmt.Sprintf("%d(SP)(CX*2)", pc)},
		} {
			source := func(operand string) string {
				return "TEXT index(SB),4,$0-32\nLEAL " + operand + ",AX\nRET\n"
			}
			symbolic := x86PackedShiftActualGoBytes(t, arch, source(row.symbolic))
			physical := x86PackedShiftActualGoBytes(t, arch, source(row.physical))
			if !bytes.Equal(symbolic, physical) {
				t.Fatalf("%s Go role changed actual address: %s=%x, %s=%x", arch, row.symbolic, symbolic, row.physical, physical)
			}
		}
		if arch == "386" {
			for _, address := range []string{"table<>(SB)(CX*4)", "table<>(SB)(SI)(CX*4)"} {
				source := func(operand string) string {
					return "TEXT index(SB),4,$0-0\nMOVL $" + operand + ",AX\nRET\n"
				}
				left := x86PackedShiftActualGoBytes(t, arch, source(address))
				right := x86PackedShiftActualGoBytes(t, arch, source("table<>(SB)"))
				if !bytes.Equal(left, right) {
					t.Fatalf("386 TYPE_ADDR unexpectedly consumed a base/index: %s: %x != %x", address, left, right)
				}
			}
			// In Go's NAME_PARAM/NAME_EXTERN encoder, Reg is not Index.
			// The nonscaled second register is discarded, not multiplied by 1.
			for _, pair := range [][2]string{{"arg(FP)(SI)", "arg(FP)"}, {"table<>(SB)(SI)", "table<>(SB)"}} {
				source := func(operand string) string {
					return "TEXT index(SB),4,$0-32\nLEAL " + operand + ",AX\nRET\n"
				}
				left := x86PackedShiftActualGoBytes(t, arch, source(pair[0]))
				right := x86PackedShiftActualGoBytes(t, arch, source(pair[1]))
				if !bytes.Equal(left, right) {
					t.Fatalf("386 nonscaled annotation became an index: %v: %x != %x", pair, left, right)
				}
			}
		}
	}
}

func TestX86SymbolIndexedAddressActualScaleTokens(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, scale := range []string{"1", "2", "4", "8", "0", "3", "16", "-1", "01", "0x1", "(1)", "1+0"} {
			t.Run(arch+"/"+scale, func(t *testing.T) {
				accepted := scale == "1" || scale == "2" || scale == "4" || scale == "8"
				operand := "arg(FP)(CX*" + scale + ")"
				source := "TEXT index(SB),4,$0-32\nLEAL " + operand + ",AX\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, source, accepted)
				parsed, err := parseOperandForArch(ArchAMD64, operand)
				if accepted && (err != nil || parsed.Kind != OpMem) || !accepted && err == nil {
					t.Fatalf("scale token accepted=%t: %+v / %v", accepted, parsed, err)
				}
			})
		}
	}
}

func TestX86SymbolIndexedAddressControlUsesBranchNotMemory(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"CALL", "JMP", "RET"} {
			var annotated, plain strings.Builder
			annotated.WriteString("TEXT index(SB),4,$0-0\n")
			plain.WriteString("TEXT index(SB),4,$0-0\n")
			for _, name := range x86SymbolIndexedActualRegisterNames(t) {
				for _, suffix := range []string{"", "*1"} {
					if suffix != "" {
						switch name {
						case "CS", "DS", "ES", "FS", "GS":
							// prefixof still sees these Index fields after
							// progedit changes TYPE_MEM to TYPE_BRANCH.
							continue
						}
					}
					fmt.Fprintf(&annotated, "%s target<>+4(SB)(%s%s)\n", op, name, suffix)
					fmt.Fprintf(&plain, "%s target<>+4(SB)\n", op)
				}
			}
			annotated.WriteString("RET\n")
			plain.WriteString("RET\n")
			if !bytes.Equal(x86PackedShiftActualGoBytes(t, arch, annotated.String()), x86PackedShiftActualGoBytes(t, arch, plain.String())) {
				t.Fatalf("%s %s TYPE_BRANCH consumed an unused Go register annotation", arch, op)
			}
			for name, prefix := range x86SymbolIndexedActualSegmentPrefixes(t, arch) {
				// NOFRAME keeps the original prefix adjacent to the branch:
				// this is an object-only source-role oracle, never a call ABI.
				source := func(operand string) string {
					return "TEXT index(SB),516,$0-0\n" + op + " " + operand + "\nRET\n"
				}
				address := "target<>+4(SB)(" + name + "*1)"
				got := x86PackedShiftActualGoBytes(t, arch, source(address))
				want := x86PackedShiftActualGoBytes(t, arch, source("target<>+4(SB)"))
				if prefix != 0 {
					want = append([]byte{prefix}, want...)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s %s TYPE_BRANCH prefix differs from actual Go prefixof: %s / %x != %x", arch, op, name, got, want)
				}
				file, err := Parse(ArchAMD64, source(address))
				if err != nil {
					t.Fatal(err)
				}
				if err := validateResolvedImmediates(ArchAMD64, file.Funcs[0]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("source-encoder branch prefix acquired an entry contract: %v", err)
				}
			}
			for _, register := range []string{"SI", "R11*4"} {
				source := func(operand string) string {
					return "TEXT index(SB),4,$0-0\n" + op + " " + operand + "\nRET\n"
				}
				address := "target<>+4(SB)(" + register + ")"
				annotated := x86PackedShiftActualGoBytes(t, arch, source(address))
				plain := x86PackedShiftActualGoBytes(t, arch, source("target<>+4(SB)"))
				if !bytes.Equal(annotated, plain) {
					t.Fatalf("Go named control operand unexpectedly consumed an index: %s %s / %x != %x", arch, op, annotated, plain)
				}
				indexedListing, _ := x86ScalarLiteralGoListing(t, arch, source(address))
				plainListing, _ := x86ScalarLiteralGoListing(t, arch, source("target<>+4(SB)"))
				relocations := func(listing string) []string {
					var rows []string
					for _, line := range strings.Split(listing, "\n") {
						if line = strings.TrimSpace(line); strings.HasPrefix(line, "rel ") {
							rows = append(rows, line)
						}
					}
					return rows
				}
				left, right := relocations(indexedListing), relocations(plainListing)
				if len(left) == 0 || !reflect.DeepEqual(left, right) {
					t.Fatalf("Go named branch relocation changed: %s %s / %v != %v", arch, op, left, right)
				}
				file, err := Parse(ArchAMD64, source(address))
				if err != nil {
					t.Fatal(err)
				}
				if err := validateResolvedImmediates(ArchAMD64, file.Funcs[0]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("named source branch became an ordinary RIP memory error/permission: %s %s / %v", arch, op, err)
				}
			}
		}
	}
}

func TestX86SymbolIndexedControlThreeAPIsRequireEntryContract(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"CALL", "JMP", "RET"} {
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				pkg := x86AddSubLiteralPackage(t, target.arch, "func index()\n")
				source := "TEXT ·index(SB),4,$0-0\n" + op + " target<>+4(SB)(CX*2)\nRET\n"
				x86ScalarLiteralGoListing(t, target.arch, source)
				file, err := Parse(ArchAMD64, source)
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
						context := llvm.NewContext()
						defer context.Dispose()
						switch api {
						case "text":
							_, err = Translate(file, options)
						case "module":
							var module llvm.Module
							module, err = TranslateModuleInContext(context, file, options)
							if !module.IsNil() {
								defer module.Dispose()
							}
						case "GoModule":
							var result *GoModuleTranslation
							result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
							if result != nil && !result.Module.IsNil() {
								defer result.Module.Dispose()
							}
						}
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("grouped source branch lost its entry contract: %v", err)
						}
					})
				}
			})
		}
	}
}

func TestX86SymbolIndexedAddressPrefixAndPhysicalBanks(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, role := range []string{"FP", "SP", "SB"} {
			operand := "$arg+8(" + role + ")(CX*2)"
			source := "TEXT index(SB),4,$0-32\nMOVL " + operand + ",AX\nRET\n"
			x86ScalarLiteralExpectedGoListing(t, arch, source, arch == "386" || role != "SB")
			parsed, err := parseOperandForArch(ArchAMD64, operand)
			if err != nil || parsed.Kind != OpSym || parsed.Sym != operand {
				t.Fatalf("address prefix became a load: %+v / %v", parsed, err)
			}
			if role != "SB" && !errors.Is(unresolvedSymbolicImmediateError(parsed), ErrProbeNeedsContext) {
				t.Fatal("known FP/AUTO syntax became an unresolved numeric constant")
			}
		}
		for _, index := range []string{"SP", "BP", "SI", "R8", "R12", "X0"} {
			parsed, err := parseOperandForArch(ArchAMD64, "arg(FP)("+index+"*2)")
			if err != nil {
				t.Fatal(err)
			}
			_, err = x86LEAOperandWidth(Instr{Op: "LEAL", Args: []Operand{parsed, {Kind: OpReg, Reg: AX}}}, arch)
			if err == nil {
				t.Fatalf("%s unbound indexed FP %s acquired permission", arch, index)
			}
		}
	}
	// The architectural decoder's physical SP+index stays physical. A named
	// source FP role is never inferred from a byte pattern or its displacement.
	for _, arch := range []string{"amd64", "386"} {
		code := x86PackedShiftActualGoBytes(t, arch, "TEXT index(SB),4,$0-32\nLEAL arg(FP)(SI*1),AX\nRET\n")
		mode := 64
		if arch == "386" {
			mode = 32
		}
		decoded, err := decodeX86RawDirectiveGroup(code, mode, 0, "original Go LEA bytes", nil)
		if err != nil || len(decoded) != 2 || len(decoded[0].Args) != 2 || decoded[0].Args[0].Kind != OpMem ||
			decoded[0].Args[0].Mem.Sym != "" || decoded[0].Args[0].Mem.Base != SP || decoded[0].Args[0].Mem.Index != SI {
			t.Fatalf("%s decoder invented an FP source role: %+v / %v", arch, decoded, err)
		}
	}
}

func TestX86SymbolIndexedAddressRecognitionIsArchitectureScoped(t *testing.T) {
	operand, err := parseOperandForArch(ArchAMD64, "$table(SB)(SI)(CX*2)")
	if err != nil || operand.Kind != OpSym {
		t.Fatalf("typed address: %+v / %v", operand, err)
	}
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchARM64, ArchWASM} {
		err := unresolvedSymbolicImmediateErrorForArch(operand, arch)
		if arch == ArchAMD64 && err != nil || arch != ArchAMD64 && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s borrowed x86-only operand grammar: %v", arch, err)
		}
	}
	if err := unresolvedSymbolicImmediateError(operand); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unscoped consumer borrowed x86 grammar: %v", err)
	}
}

func TestX86SymbolIndexedAddressNonGPAnnotations(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, role := range []string{"FP", "SP", "SB"} {
			for _, register := range []string{"FS", "GS", "X0"} {
				operand := "arg(" + role + ")(" + register + ")"
				t.Run(arch+"/"+operand, func(t *testing.T) {
					source := func(address string) string {
						return "TEXT index(SB),4,$0-32\nLEAL " + address + ",AX\nRET\n"
					}
					x86ScalarLiteralExpectedGoListing(t, arch, source(operand), arch == "386")
					parsed, err := parseOperandForArch(ArchAMD64, operand)
					if err != nil || parsed.Kind != OpMem || parsed.Mem.Base != Reg(register) {
						t.Fatalf("original non-GP annotation was lost: %+v / %v", parsed, err)
					}
					if arch == "386" {
						annotated := x86PackedShiftActualGoBytes(t, arch, source(operand))
						plain := x86PackedShiftActualGoBytes(t, arch, source("arg("+role+")"))
						if !bytes.Equal(annotated, plain) {
							t.Fatalf("386 encoder consumed the named Reg annotation: %x != %x", annotated, plain)
						}
						if role == "SB" {
							addressSource := func(address string) string {
								return "TEXT index(SB),4,$0-0\nMOVL $" + address + ",AX\nRET\n"
							}
							annotated = x86PackedShiftActualGoBytes(t, arch, addressSource(operand))
							plain = x86PackedShiftActualGoBytes(t, arch, addressSource("arg(SB)"))
							if !bytes.Equal(annotated, plain) {
								t.Fatalf("386 relocated immediate consumed Reg: %x != %x", annotated, plain)
							}
						}
					}
					err = x86SymbolIndexedMemoryError(parsed.Mem, arch)
					if arch == "386" && role == "SB" && err != nil ||
						arch == "386" && role != "SB" && !errors.Is(err, ErrProbeNeedsContext) || arch == "amd64" && err == nil {
						t.Fatalf("ignored Reg annotation changed the native role or granted frame permission: %v", err)
					}
				})
			}
		}
	}
}

func x86SymbolIndexedActualRegisterNames(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "list6.go")
	file, err := goparser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "Register" {
			return true
		}
		if len(declaration.Values) != 1 {
			t.Fatal("unexpected Go Register declaration")
		}
		array, ok := declaration.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("Go Register is not a literal inventory")
		}
		for _, element := range array.Elts {
			literal, ok := element.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("Go Register contains a nonliteral spelling")
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		return false
	})
	if len(names) != 201 {
		t.Fatalf("actual Go x86 Register inventory changed: %d", len(names))
	}
	return names
}

func x86SymbolIndexedActualSegmentPrefixes(t *testing.T, arch string) map[string]byte {
	t.Helper()
	file, err := goparser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var function *ast.FuncDecl
	for _, declaration := range file.Decls {
		if candidate, ok := declaration.(*ast.FuncDecl); ok && candidate.Name.Name == "prefixof" {
			if function != nil {
				t.Fatal("duplicate actual Go prefixof")
			}
			function = candidate
		}
	}
	if function == nil || function.Body == nil {
		t.Fatal("actual Go prefixof is missing")
	}
	path := func(expression ast.Expr) string {
		var visit func(ast.Expr) string
		visit = func(expression ast.Expr) string {
			switch expression := expression.(type) {
			case *ast.Ident:
				return expression.Name
			case *ast.SelectorExpr:
				return visit(expression.X) + "." + expression.Sel.Name
			}
			return ""
		}
		return visit(expression)
	}
	suppressed := false
	prefixes := make(map[string]byte)
	for _, statement := range function.Body.List {
		if gate, ok := statement.(*ast.IfStmt); ok {
			condition, ok := gate.Cond.(*ast.BinaryExpr)
			if ok && condition.Op == token.EQL && path(condition.X) == "ctxt.Arch.Family" && path(condition.Y) == "sys.I386" {
				if len(gate.Body.List) == 0 {
					t.Fatal("empty actual Go I386 prefix gate")
				}
				last, ok := gate.Body.List[len(gate.Body.List)-1].(*ast.ReturnStmt)
				if !ok || gate.Else != nil || len(last.Results) != 1 {
					t.Fatal("unknown actual Go I386 prefix gate")
				}
				zero, ok := last.Results[0].(*ast.BasicLit)
				if !ok || zero.Kind != token.INT || zero.Value != "0" {
					t.Fatal("actual Go I386 prefix gate does not suppress the prefix")
				}
				suppressed = true
			}
		}
		index, ok := statement.(*ast.SwitchStmt)
		if !ok || path(index.Tag) != "a.Index" {
			continue
		}
		for _, statement := range index.Body.List {
			row := statement.(*ast.CaseClause)
			if len(row.List) != 1 || len(row.Body) != 1 {
				continue
			}
			name := strings.TrimPrefix(path(row.List[0]), "REG_")
			result, ok := row.Body[0].(*ast.ReturnStmt)
			if !ok || len(result.Results) != 1 {
				continue
			}
			literal, ok := result.Results[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.INT {
				t.Fatal("actual Go segment prefix is not a literal")
			}
			value, err := strconv.ParseUint(literal.Value, 0, 8)
			if err != nil {
				t.Fatal(err)
			}
			prefixes[name] = byte(value)
		}
	}
	if !reflect.DeepEqual(prefixes, map[string]byte{"CS": 0x2e, "DS": 0x3e, "ES": 0x26, "FS": 0x64, "GS": 0x65}) {
		t.Fatalf("actual Go segment prefix inventory changed: %v", prefixes)
	}
	if arch == "386" && suppressed {
		for name := range prefixes {
			prefixes[name] = 0
		}
	}
	return prefixes
}

func TestX86SymbolIndexedAddressCompleteIgnoredRegisterInventory(t *testing.T) {
	prefixes := x86SymbolIndexedActualSegmentPrefixes(t, "386")
	var annotated, plain strings.Builder
	annotated.WriteString("TEXT index(SB),4,$0-0\n")
	plain.WriteString("TEXT index(SB),4,$0-0\n")
	for _, name := range x86SymbolIndexedActualRegisterNames(t) {
		operand := "table<>(SB)(" + name + ")"
		parsed, err := parseOperandForArch(ArchAMD64, operand)
		if !x86SymbolGoRegisterName(name) || err != nil || parsed.Mem.Base != Reg(name) {
			t.Fatalf("actual Go Register annotation was lost: %s / %+v / %v", name, parsed, err)
		}
		_, err = x86LEAOperandWidth(Instr{Op: "LEAL", Args: []Operand{parsed, {Kind: OpReg, Reg: AX}}}, "386")
		if name == "TLS" {
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unmodeled Go TLS progedit did not remain Context: %v", err)
			}
			// MOVL named(TLS) is rewritten before oclass: unlike ordinary
			// ignored annotations it performs two native memory reads.
			source := func(address string) string {
				return "TEXT index(SB),4,$0-0\nMOVL " + address + ",AX\nRET\n"
			}
			if bytes.Equal(x86PackedShiftActualGoBytes(t, "386", source(operand)), x86PackedShiftActualGoBytes(t, "386", source("table<>(SB)"))) {
				t.Fatal("actual Go named TLS rewrite was lost")
			}
		} else {
			if err != nil {
				t.Fatalf("ignored Go Reg annotation became a physical-register requirement: %s / %v", name, err)
			}
			fmt.Fprintf(&annotated, "LEAL %s,AX\nMOVL %s,AX\n", operand, operand)
			plain.WriteString("LEAL table<>(SB),AX\nMOVL table<>(SB),AX\n")
		}
		fmt.Fprintf(&annotated, "MOVL $%s,AX\n", operand)
		plain.WriteString("MOVL $table<>(SB),AX\n")
		switch name {
		case "CS", "DS", "ES", "FS", "GS":
			address := "table<>(SB)(" + name + "*1)"
			source := func(address string) string {
				return "TEXT index(SB),4,$0-0\nMOVL $" + address + ",AX\nRET\n"
			}
			left := x86PackedShiftActualGoBytes(t, "386", source(address))
			right := x86PackedShiftActualGoBytes(t, "386", source("table<>(SB)"))
			prefix := prefixes[name]
			if prefix == 0 && !bytes.Equal(left, right) ||
				prefix != 0 && (len(left) != len(right)+1 || left[0] != prefix || !bytes.Equal(left[1:], right)) {
				t.Fatalf("actual Go TYPE_ADDR bytes disagree with its prefixof: %s prefix=%x / %x != %x", name, prefix, left, right)
			}
			index, err := parseOperandForArch(ArchAMD64, address)
			if err != nil {
				t.Fatal(err)
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			ctx.goarch = "386"
			before := output.Len()
			if _, err := ctx.addrFromSymbolIndexedAddress(index.Mem); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != before {
				t.Fatalf("unmodeled TYPE_ADDR prefix emitted IR: %v", err)
			}
		default:
			fmt.Fprintf(&annotated, "MOVL $table<>(SB)(%s*1),AX\n", name)
			plain.WriteString("MOVL $table<>(SB),AX\n")
		}
	}
	annotated.WriteString("RET\n")
	plain.WriteString("RET\n")
	left := x86PackedShiftActualGoBytes(t, "386", annotated.String())
	right := x86PackedShiftActualGoBytes(t, "386", plain.String())
	if !bytes.Equal(left, right) {
		t.Fatalf("386 ignored Reg/TYPE_ADDR Index changed the complete object bytes (lengths %d/%d)", len(left), len(right))
	}
	for _, name := range []string{"R0", "R7", "R16", "RAX", "R8W", "F8", "M8", "MM0", "K8", "X32", "Y32", "Z32", "CR16", "DR8", "TR8", "X00", "V0", "PN0", "g", "ax"} {
		operand := "table<>(SB)(" + name + ")"
		source := "TEXT index(SB),4,$0-0\nLEAL " + operand + ",AX\nRET\n"
		x86ScalarLiteralExpectedGoListing(t, "386", source, false)
		if x86SymbolGoRegisterName(name) {
			t.Fatalf("unregistered x86 annotation was authorized: %s", name)
		}
		if _, err := parseOperandForArch(ArchAMD64, operand); err == nil {
			t.Fatalf("unregistered x86 annotation was parsed: %s", name)
		}
	}
}

func TestX86SymbolIndexedAddressSegmentIndexNeedsContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, role := range []string{"FP", "SP", "SB"} {
			for _, register := range []string{"CS", "SS", "DS", "ES", "FS", "GS", "X0"} {
				operand := "arg(" + role + ")(" + register + "*1)"
				t.Run(arch+"/"+operand, func(t *testing.T) {
					source := "TEXT index(SB),4,$0-32\nLEAL " + operand + ",AX\nRET\n"
					accepted := register != "X0" && (arch == "386" || role != "SB")
					x86ScalarLiteralExpectedGoListing(t, arch, source, accepted)
					parsed, err := parseOperandForArch(ArchAMD64, operand)
					if err != nil || parsed.Mem.Index != Reg(register) || parsed.Mem.Base != "" {
						t.Fatalf("segment index became an ignored Reg annotation: %+v / %v", parsed, err)
					}
					err = x86SymbolIndexedMemoryError(parsed.Mem, arch)
					if accepted && !errors.Is(err, ErrProbeNeedsContext) || !accepted && err == nil {
						t.Fatalf("unbound segment/VSIB source acquired permission: %v", err)
					}
				})
			}
		}
	}
}

func TestX86SymbolIndexedAddressEmptyName(t *testing.T) {
	for _, prefix := range []string{"", "+0", "-0", "+(2*4)", "   "} {
		for _, role := range []string{"FP", "SB"} {
			operand := prefix + "(" + role + ")(SI*1)"
			for _, arch := range []string{"amd64", "386"} {
				source := "TEXT index(SB),4,$0-0\nLEAL " + operand + ",AX\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, source, false)
			}
			if _, err := parseOperandForArch(ArchAMD64, operand); err == nil {
				t.Fatalf("empty symbolic name was accepted: %q", operand)
			}
		}
	}
}

func TestX86SymbolIndexedFPDoesNotGrantFramePermission(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, instruction := range []string{
			"LEAL x+0(FP)(CX*2),AX", "MOVL x+0(FP)(CX*2),AX",
			"MOVL AX,x+0(FP)(CX*2)", "MOVL $x+0(FP)(CX*2),AX",
			"LEAL local+8(SP)(CX*2),AX", "MOVL local+8(SP)(CX*2),AX",
		} {
			t.Run(target.triple+"/"+instruction, func(t *testing.T) {
				pkg := x86AddSubLiteralPackage(t, target.arch, "func index(x uint32)\n")
				source := "TEXT ·index(SB),4,$0-4\nMOVL $0,CX\n" + instruction + "\nRET\n"
				file, err := Parse(ArchAMD64, source)
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
						context := llvm.NewContext()
						defer context.Dispose()
						switch api {
						case "text":
							_, err = Translate(file, options)
						case "module":
							var module llvm.Module
							module, err = TranslateModuleInContext(context, file, options)
							if !module.IsNil() {
								defer module.Dispose()
							}
						case "GoModule":
							var result *GoModuleTranslation
							result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
							if result != nil && !result.Module.IsNil() {
								defer result.Module.Dispose()
							}
						}
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("new syntax borrowed FP/stack backing permission: %v", err)
						}
					})
				}
			})
		}
	}
}

func TestX86SymbolIndexedSBThreeAPIsFiveLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			pkg := x86AddSubLiteralPackage(t, target.arch, "func index() uint32\n")
			var source strings.Builder
			source.WriteString("DATA ·table<>+0(SB)/8,$7\nGLOBL ·table<>(SB),$32\nTEXT ·index(SB),4,$0-4\nMOVL $1,CX\n")
			widths := []string{"W", "L"}
			if target.arch == "amd64" {
				widths = append(widths, "Q")
			}
			for _, width := range widths {
				fmt.Fprintf(&source, "LEA%s ·table<>(SB),DX\n", width)
				if target.arch == "386" {
					for _, scale := range []int{1, 2, 4, 8} {
						fmt.Fprintf(&source, "LEA%s ·table<>+(2*4)(SB)(CX*%d),DX\n", width, scale)
					}
					// SI is not an input to these Go NAME_STATIC instructions.
					fmt.Fprintf(&source, "LEA%s ·table<>(SB)(SI),DX\n", width)
					fmt.Fprintf(&source, "LEA%s ·table<>(SB)(SI)(CX*2),DX\n", width)
				}
			}
			source.WriteString("MOVL ·table<>(SB),AX\n")
			if target.arch == "386" {
				source.WriteString("MOVL ·table<>(SB)(SI),AX\nMOVL $·table<>(SB)(SI)(CX*4),DX\n")
				for _, name := range x86SymbolIndexedActualRegisterNames(t) {
					if name != "TLS" {
						fmt.Fprintf(&source, "LEAL ·table<>(SB)(%s),DX\nMOVL ·table<>(SB)(%s),AX\n", name, name)
					}
					fmt.Fprintf(&source, "MOVL $·table<>(SB)(%s),DX\n", name)
					switch name {
					case "CS", "DS", "ES", "FS", "GS":
						// Source-encoder prefix ambiguity has a Context witness above.
					default:
						fmt.Fprintf(&source, "MOVL $·table<>(SB)(%s)(%s*1),DX\n", name, name)
					}
				}
			}
			source.WriteString("MOVL AX,ret+0(FP)\nRET\n")
			// Invoke both actual compatibility assemblers, not the current-only
			// optab helper. No numerical/runtime claim is made for 386 here.
			x86ScalarLiteralGoListing(t, target.arch, source.String())
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
					context := llvm.NewContext()
					defer context.Dispose()
					var ir string
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						var module llvm.Module
						module, err = TranslateModuleInContext(context, file, options)
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
					case "GoModule":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(context, pkg, []byte(source.String()), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(ir, "load i64, ptr %reg_SI") {
						t.Fatal("386 encoder's discarded Reg became a value dependency")
					}
					compileLLVMToObject(t, llc, target.triple, "symbol-index.ll", "symbol-index.o", ir)
				})
			}
		})
	}
}

func TestX86SymbolIndexedMemoryConsumerRejectsBeforeIR(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, address := range []string{
			"arg(FP)(CX*2)", "local(SP)(BX*4)", "arg(FP)(AX)(BX*2)",
			"table(SB)(SP*1)", "table(SB)(X0*1)", "table(SB)(SI)(CX)",
		} {
			parsed, err := parseOperandForArch(ArchAMD64, address)
			if err != nil {
				t.Fatal(err)
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			ctx.goarch = target.arch
			before := output.Len()
			if _, err := ctx.addrFromPlainMem(parsed.Mem); err == nil || output.Len() != before {
				t.Fatalf("%s %s emitted an unproved symbolic pointer: %v", target.triple, address, err)
			}
		}
		if target.arch == "amd64" {
			for _, address := range []string{"table(SB)(CX*1)", "table(SB)(SI)", "table(SB)(SI)(CX*2)"} {
				parsed, err := parseOperandForArch(ArchAMD64, address)
				if err != nil {
					t.Fatal(err)
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				before := output.Len()
				if _, err := ctx.addrFromPlainMem(parsed.Mem); err == nil || output.Len() != before {
					t.Fatalf("AMD64 RIP+index became a native address: %s / %v", address, err)
				}
			}
		}
	}
}

func TestX86SymbolIndexedFPDoesNotBorrowRawReturnOrCallerPermission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, source := range []string{
			"LEAL arg(FP)(CX*2),AX", "MOVL arg(FP)(CX*2),AX", "MOVL AX,arg(FP)(CX*2)",
			"LEAL local(SP)(CX*2),AX", "MOVL local(SP)(CX*2),AX", "MOVL AX,local(SP)(CX*2)",
		} {
			file, err := Parse(ArchAMD64, "TEXT index(SB),4,$0-8\nMOVL $0,CX\n"+source+"\nBYTE $0xc3\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"index": {Args: []LLVMType{I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s raw RET acquired an indexed named-frame permission: %v", arch, err)
			}
		}
	}
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX", "MOVL $0,SI\nLEAQ x_base+0(FP)(SI*1),SI", 1)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("ordinary actual typed caller supplied dynamic FP storage: %v", err)
	}
}
