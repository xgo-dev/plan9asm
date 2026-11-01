package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

func TestX86UnnamedAddressImmediateUnscaledSecondGroup(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, operation := range []string{"MOVL", "MOVQ"} {
			if arch == "386" && operation == "MOVQ" {
				continue
			}
			for _, address := range []string{"1(AX)(CX)", "-16(BP)(DI)", "0(AX)(AX)"} {
				t.Run(arch+"/"+operation+"/"+address, func(t *testing.T) {
					source := "TEXT addr(SB),4,$0-0\n" + operation + " $" + address + ",DX\nRET\n"
					x86UnnamedScale0OriginalGoRejection(t, arch, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					original := file.Funcs[0].Instrs[1]
					memory, matched, err := x86UnnamedSourceAddress(original.Args[0])
					if err != nil || !matched || memory.Index == "" || memory.Scale != 0 {
						t.Errorf("source Index/Scale0 was changed: %+v, %v", memory, err)
					}
					if _, _, err := normalizeX86SourceIntegerAddress(original, arch); err == nil {
						t.Error("Go-invalid Scale0 became a legal LEA source")
					}
				})
			}
		}
	}
}

// asmidx's scale diagnostic has no source position. Keep the generic oracle
// strict: this local witness binds one complete MOV source and the exact
// base/index tuple to the selected SDK's independently inspected diagnostic.
func x86UnnamedScale0OriginalGoRejection(t *testing.T, arch, source string) {
	t.Helper()
	match := regexp.MustCompile(`^TEXT addr\(SB\),4,\$0-0\n(MOVB|MOVW|MOVL|MOVQ|LEAW|LEAL|LEAQ) (\$?)(-?[0-9]+)\((AX|BP)\)\((AX|CX|DI)\),DX\nRET\n$`).FindStringSubmatch(source)
	if match == nil {
		// The store controls have exactly the same one-instruction physical
		// tuple, but bind it from To rather than claiming a From rewrite.
		store := regexp.MustCompile(`^TEXT addr\(SB\),4,\$0-0\n(MOVB|MOVW|MOVL|MOVQ) DX,(-?[0-9]+)\((AX|BP)\)\((AX|CX|DI)\)\nRET\n$`).FindStringSubmatch(source)
		if store != nil {
			match = []string{store[0], store[1], "", store[2], store[3], store[4]}
		}
	}
	if match == nil || arch != "386" && arch != "amd64" || arch == "386" && strings.HasSuffix(match[1], "Q") ||
		strings.HasPrefix(match[1], "LEA") && match[2] != "" {
		t.Fatalf("unbound Scale0 rejection fixture: %s / %q", arch, source)
	}
	want := x86UnnamedAsmidxDiagnostic(t, match[4], match[5])
	dir := t.TempDir()
	asm := filepath.Join(dir, "scale0.s")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "literal", "-o", filepath.Join(dir, "scale0.o"), asm)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := x86UnnamedAsmidxOutcome(output, err, ctx.Err(), want); failure != nil {
		t.Fatalf("exact Scale0 source rejection lost its tuple/exit/lifecycle: %v / %v\nwant %q\ngot %q", err, ctx.Err(), want, output)
	}
	for _, changed := range []string{
		strings.Replace(want, "bad address 0/", "bad address 3/", 1),
		strings.Replace(want, "bad address", "foreign address", 1),
		want + want, want + "unexpected diagnostic\n", "asm: assembly failed\n", "",
	} {
		if x86UnnamedAsmidxOutcome([]byte(changed), err, nil, want) == nil {
			t.Fatal("local source oracle accepted a changed/repeated/missing diagnostic")
		}
	}
	for _, failure := range []error{nil, errors.New("launch failure"), errors.Join(err, errors.New("cleanup failure"))} {
		if x86UnnamedAsmidxOutcome(output, failure, nil, want) == nil {
			t.Fatal("local source oracle accepted an unknown/cleanup process outcome")
		}
	}
	if x86UnnamedAsmidxOutcome(output, err, context.DeadlineExceeded, want) == nil {
		t.Fatal("local source oracle accepted a timed-out process")
	}
	t.Logf("ORIGINAL_SCALE0_REJECTION arch=%s sourceSHA=%x source=%q outputSHA=%x output=%q", arch, sha256.Sum256([]byte(source)), source, sha256.Sum256(output), output)
}

func x86UnnamedAsmidxOutcome(output []byte, err, contextErr error, expected string) error {
	exit, ok := err.(*exec.ExitError)
	if contextErr != nil || !ok || exit.ProcessState == nil || !exit.ProcessState.Exited() || exit.ExitCode() != 1 || string(output) != expected {
		return fmt.Errorf("unbound asmidx outcome: %v / %v / %q", err, contextErr, output)
	}
	return nil
}

func x86UnnamedAsmidxDiagnostic(t *testing.T, base, index string) string {
	t.Helper()
	expression := func(node ast.Node) string {
		var text bytes.Buffer
		if err := printer.Fprint(&text, token.NewFileSet(), node); err != nil {
			t.Fatal(err)
		}
		return text.String()
	}
	read := func(relative string) *ast.File {
		path := filepath.Join(runtime.GOROOT(), "src", relative)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := goparser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ACTUAL_ASMIDX_SOURCE file=%s SHA=%x", relative, sha256.Sum256(data))
		return file
	}
	file := read("cmd/internal/obj/x86/asm6.go")
	format, calls := "", 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "asmidx" {
			continue
		}
		ast.Inspect(function, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || expression(call.Fun) != "ctxt.Diag" || len(call.Args) != 4 {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil || !strings.HasPrefix(text, "asmidx: bad address") {
				return true
			}
			calls++
			format = text
			arguments := expression(call.Args[1]) + "/" + expression(call.Args[2]) + "/" + expression(call.Args[3])
			if format == "asmidx: bad address %d/%s/%s" && arguments == "scale/rconv(index)/rconv(base)" ||
				format == "asmidx: bad address %d/%d/%d" && arguments == "scale/index/base" {
				return true
			}
			t.Fatalf("unreviewed actual Go asmidx diagnostic: %s / %s", format, arguments)
			return false
		})
	}
	if calls != 1 {
		t.Fatalf("actual Go has %d matching asmidx diagnostics", calls)
	}
	if format == "asmidx: bad address %d/%s/%s" {
		return "asm: " + fmt.Sprintf(format, 0, index, base) + "\nasm: assembly failed\n"
	}
	// Older SDKs print obj register IDs. Derive those IDs from the actual
	// RBaseAMD64 expression and REG_AL+iota declaration, not GoVersion.
	registerBase, found := int64(0), false
	ast.Inspect(read("cmd/internal/obj/util.go"), func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != "RBaseAMD64" {
			return true
		}
		if found || len(value.Values) != 1 {
			t.Fatal("ambiguous actual RBaseAMD64")
		}
		multiply, ok := value.Values[0].(*ast.BinaryExpr)
		if !ok || multiply.Op != token.MUL {
			t.Fatal("unreviewed RBaseAMD64 expression")
		}
		left, leftErr := strconv.ParseInt(expression(multiply.X), 10, 64)
		right, rightErr := strconv.ParseInt(expression(multiply.Y), 10, 64)
		if leftErr != nil || rightErr != nil || left != 2 || right != 1024 {
			t.Fatal("unreviewed actual RBaseAMD64 factors")
		}
		registerBase, found = left*right, true
		return false
	})
	if !found {
		t.Fatal("actual RBaseAMD64 missing")
	}
	ids := map[string]int64{}
	for _, declaration := range read("cmd/internal/obj/x86/a.out.go").Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST || len(group.Specs) == 0 {
			continue
		}
		first := group.Specs[0].(*ast.ValueSpec)
		if len(first.Names) != 1 || first.Names[0].Name != "REG_AL" {
			continue
		}
		if len(first.Values) != 1 || expression(first.Values[0]) != "obj.RBaseAMD64 + iota" || len(ids) != 0 {
			t.Fatal("unreviewed actual REG_AL+iota declaration")
		}
		for offset, item := range group.Specs {
			value, ok := item.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || offset > 0 && len(value.Values) != 0 {
				break // Later bounds constants are not register enum entries.
			}
			ids[strings.TrimPrefix(value.Names[0].Name, "REG_")] = registerBase + int64(offset)
		}
	}
	for offset, name := range x86SymbolIndexedActualRegisterNames(t) {
		if ids[name] != registerBase+int64(offset) {
			t.Fatalf("actual register spelling/ID mismatch: %s / %d", name, ids[name])
		}
	}
	baseID, baseOK := ids[base]
	indexID, indexOK := ids[index]
	if !baseOK || !indexOK {
		t.Fatal("fixture register is not in the actual SDK enum")
	}
	return "asm: " + fmt.Sprintf(format, 0, indexID, baseID) + "\nasm: assembly failed\n"
}

func TestX86UnnamedAddressImmediateScale0ConstantFamily(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{
			"MOV", "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST",
			"SAL", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR", "IMUL", "IMUL3",
			"BT", "BTC", "BTR", "BTS", "PUSH",
		} {
			for _, suffix := range []string{"B", "W", "L", "Q"} {
				if suffix == "Q" && arch == "386" || stem == "MOV" && suffix != "B" && suffix != "W" ||
					suffix == "B" && (strings.HasPrefix(stem, "IMUL") || strings.HasPrefix(stem, "BT") || stem == "PUSH") ||
					stem == "PUSH" && (suffix == "L" && arch != "386" || suffix == "Q" && arch != "amd64") {
					continue
				}
				t.Run(arch+"/"+stem+suffix, func(t *testing.T) {
					operand := "$1(AX)(CX),DX"
					if stem == "CMP" {
						operand = "DX,$1(AX)(CX)"
					} else if stem == "IMUL3" {
						operand = "$1(AX)(CX),BX,DX"
					} else if stem == "PUSH" {
						operand = "$1(AX)(CX)"
					}
					ending := "RET\n"
					if stem == "PUSH" {
						ending = "POP" + suffix + " DX\nRET\n"
					}
					source := "TEXT addr(SB),4,$0-0\n" + stem + suffix + " " + operand + "\n" + ending
					original := x86PackedShiftActualGoBytes(t, arch, source)
					plain := x86PackedShiftActualGoBytes(t, arch, strings.ReplaceAll(source, "(AX)(CX)", ""))
					if !bytes.Equal(original, plain) {
						t.Fatalf("constant source consumed its ignored Scale0: %x != %x", original, plain)
					}
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					if _, _, err := normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediateScale0ThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, operation := range []string{"MOVL", "MOVQ"} {
			if target.arch == "386" && operation == "MOVQ" {
				continue
			}
			t.Run(target.triple+"/"+operation, func(t *testing.T) {
				source := "TEXT ·addr(SB),4,$0-0\nMOVL $2,AX\nMOVL $3,CX\n" + operation + " $1(AX)(CX),DX\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				pkg := x86AddSubLiteralPackage(t, target.arch, "func addr()\n")
				resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
				sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(api, func(t *testing.T) {
						context := llvm.NewContext()
						defer context.Dispose()
						var err error
						switch api {
						case "text":
							_, err = Translate(file, options)
						case "module":
							var module llvm.Module
							module, err = TranslateModuleInContext(context, file, options)
							if !module.IsNil() {
								module.Dispose()
							}
						case "GoModule":
							var result *GoModuleTranslation
							result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
							if result != nil && !result.Module.IsNil() {
								result.Module.Dispose()
							}
						}
						if err == nil {
							t.Error(fmt.Sprintf("%s %s silently changed Scale0 to Scale1", target.arch, api))
						}
					})
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateDirectLEAScale0(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, operation := range []string{"LEAW", "LEAL", "LEAQ"} {
			if target.arch == "386" && operation == "LEAQ" {
				continue
			}
			t.Run(target.triple+"/"+operation, func(t *testing.T) {
				x86UnnamedScale0OriginalGoRejection(t, target.arch, "TEXT addr(SB),4,$0-0\n"+operation+" 1(AX)(CX),DX\nRET\n")
				source := "TEXT ·addr(SB),4,$0-0\nMOVL $2,AX\nMOVL $3,CX\n" + operation + " 1(AX)(CX),DX\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				pkg := x86AddSubLiteralPackage(t, target.arch, "func addr()\n")
				resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
				sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(api, func(t *testing.T) {
						context := llvm.NewContext()
						defer context.Dispose()
						var err error
						switch api {
						case "text":
							_, err = Translate(file, options)
						case "module":
							var module llvm.Module
							module, err = TranslateModuleInContext(context, file, options)
							if !module.IsNil() {
								module.Dispose()
							}
						case "GoModule":
							var result *GoModuleTranslation
							result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
							if result != nil && !result.Module.IsNil() {
								result.Module.Dispose()
							}
						}
						if err == nil {
							t.Fatal("direct source LEA silently changed Scale0 to Scale1")
						}
					})
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediatePhysicalMemoryThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, suffix := range []string{"B", "W", "L", "Q"} {
			if target.arch == "386" && suffix == "Q" {
				continue
			}
			for _, store := range []bool{false, true} {
				instruction := "MOV" + suffix + " 1(AX)(CX),DX"
				if store {
					instruction = "MOV" + suffix + " DX,1(AX)(CX)"
				}
				t.Run(target.triple+"/"+instruction, func(t *testing.T) {
					x86UnnamedScale0OriginalGoRejection(t, target.arch, "TEXT addr(SB),4,$0-0\n"+instruction+"\nRET\n")
					source := "TEXT ·addr(SB),4,$0-0\nMOVL $2,AX\nMOVL $3,CX\nMOVL $4,DX\n" + instruction + "\nRET\n"
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					pkg := x86AddSubLiteralPackage(t, target.arch, "func addr()\n")
					resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							context := llvm.NewContext()
							defer context.Dispose()
							var err error
							switch api {
							case "text":
								_, err = Translate(file, options)
							case "module":
								var module llvm.Module
								module, err = TranslateModuleInContext(context, file, options)
								if !module.IsNil() {
									module.Dispose()
								}
							case "GoModule":
								var result *GoModuleTranslation
								result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
								if result != nil && !result.Module.IsNil() {
									result.Module.Dispose()
								}
							}
							if err == nil {
								t.Fatal("physical memory source with a missing SIB multiplier was accepted")
							}
						})
					}
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediatePhysicalSIBIndexSP(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, scale := range []string{"1", "2", "4", "8"} {
			for _, op := range []string{"MOVL", "LEAL"} {
				t.Run(arch+"/"+op+"/"+scale, func(t *testing.T) {
					x86ScalarLiteralExpectedGoListing(t, arch, "TEXT addr(SB),4,$0-0\n"+op+" 1(AX)(SP*"+scale+"),DX\nRET\n", false)
				})
			}
		}
		for _, address := range []string{"1(AX)(SP)", "1(SP)(CX)"} {
			t.Run(arch+"/constant/"+address, func(t *testing.T) {
				// SP as an ignored annotation does not create a SIB or
				// a private stack read. Only the original TYPE_CONST
				// role is independently established by these bytes.
				source := "TEXT addr(SB),4,$0-0\nADDL $" + address + ",DX\nRET\n"
				original := x86PackedShiftActualGoBytes(t, arch, source)
				plain := x86PackedShiftActualGoBytes(t, arch, strings.Replace(source, "$"+address, "$1", 1))
				if !bytes.Equal(original, plain) {
					t.Fatalf("constant-class source consumed an ignored SP/index: %x != %x", original, plain)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				derived, changed, err := normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch)
				if err != nil || !changed || derived.Args[0].Kind != OpImm || derived.Args[0].Imm != 1 {
					t.Fatalf("constant-class SP annotation changed role: %+v / %v", derived, err)
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateCompleteGroupBoundaries(t *testing.T) {
	valid := []string{
		"1(AX)", "-16(BP)", "1(SP)", "1(CX*1)", "1(CX*2)", "1(CX*4)", "1(CX*8)",
		"1(AX)(CX*1)", "1(AX)(CX*2)", "1(AX)(CX*4)", "1(AX)(CX*8)",
		"1( AX ) ( CX * 2 )",
	}
	invalid := []string{
		"1(AX)(CX*0)", "1(AX)(CX*3)", "1(AX)(CX*01)", "1(AX)(CX*0x1)",
		"1(AX)(CX*+1)", "1(AX)(CX*-1)", "1(AX)(CX*(1))", "1(AX)(CX*1+1)",
		"1(AX)(CX*)", "1(AX)(CX*1)(DX)", "1(AX*1)(CX*1)",
		"1()(CX*1)", "1(AX)(NOTREG*1)",
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, domain := range []struct{ op, prefix string }{{"MOVL", "$"}, {"ADDL", "$"}, {"MOVL", ""}, {"LEAL", ""}} {
			for _, group := range []struct {
				addresses []string
				accepted  bool
			}{{valid, true}, {invalid, false}} {
				for _, address := range group.addresses {
					t.Run(arch+"/"+domain.op+"/"+domain.prefix+address, func(t *testing.T) {
						source := "TEXT addr(SB),4,$0-0\n" + domain.op + " " + domain.prefix + address + ",DX\nRET\n"
						x86ScalarLiteralExpectedGoListing(t, arch, source, group.accepted)
						file, err := Parse(ArchAMD64, source)
						if err == nil {
							_, _, err = normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch)
						}
						if (err == nil) != group.accepted {
							t.Fatalf("source group accepted=%t: %v", group.accepted, err)
						}
					})
				}
			}
		}
	}
}

func TestX86UnnamedAddressImmediatePhysicalGroupState(t *testing.T) {
	for _, row := range []struct {
		text   string
		memory MemRef
	}{
		{"1(AX)", MemRef{Base: AX, Off: 1}},
		{"1(CX*1)", MemRef{Index: CX, Scale: 1, Off: 1}},
		{"1(CX*2)", MemRef{Index: CX, Scale: 2, Off: 1}},
		{"1(AX)(CX)", MemRef{Base: AX, Index: CX, Off: 1}},
		{"1( AX ) ( CX )", MemRef{Base: AX, Index: CX, Off: 1}},
		{"1(AX)(CX*1)", MemRef{Base: AX, Index: CX, Scale: 1, Off: 1}},
		{"(1<<4)(AX)(CX*4)", MemRef{Base: AX, Index: CX, Scale: 4, Off: 16}},
		{"1(AX)(SP)", MemRef{Base: AX, Index: SP, Off: 1}},
	} {
		t.Run(row.text, func(t *testing.T) {
			operand, err := parseOperandForArch(ArchAMD64, row.text)
			if err != nil || operand.Kind != OpMem || operand.Mem != row.memory {
				t.Fatalf("stock-Go source Reg/Index/Scale changed: %+v, want %+v: %v", operand, row.memory, err)
			}
		})
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVL", "LEAL"} {
			x86UnnamedScale0OriginalGoRejection(t, arch, "TEXT addr(SB),4,$0-0\n"+op+" 1(AX)(CX),DX\nRET\n")
		}
	}
}

func TestX86UnnamedAddressImmediatePhysicalRoleIsolation(t *testing.T) {
	for _, source := range []string{
		"table<>(SB)", "table<>(SB)(AX)(CX)", "a+8(FP)", "a+8(FP)(CX)",
		"local+8(SP)", "local+8(SP)(AX)(CX)", "2(PC)",
		"1(FS)", "1(GS)", "1(AX)(FS)", "1(AX)(GS)", "1(TLS)",
	} {
		t.Run(source, func(t *testing.T) {
			// The x86 source adapter must not relabel named/prefix/branch
			// operands into ordinary SIB permission. Their independent
			// existing parser and storage/source contracts remain in charge.
			var before Operand
			var oldErr error
			if memory, matched, err := parseX86SymbolIndexedMemory(source); matched {
				before, oldErr = Operand{Kind: OpMem, Mem: memory}, err
			} else {
				before, oldErr = parseOperand(source)
			}
			after, err := parseOperandForArch(ArchAMD64, source)
			if (err == nil) != (oldErr == nil) || err == nil && !reflect.DeepEqual(after, before) {
				t.Fatalf("independent source role changed: %+v / %v != %+v / %v", after, err, before, oldErr)
			}
		})
	}
	for _, operand := range []Operand{
		{Kind: OpSym, Sym: "$1(AX)(CX)"},
		{Kind: OpMem, Mem: MemRef{Sym: "a+8(FP)", Base: AX, Index: CX}},
		{Kind: OpMem, Mem: MemRef{Base: AX, Segment: FS, Index: CX}},
		{Kind: OpMem, Mem: MemRef{Base: AX, Index: FS}},
		{Kind: OpMem, Mem: MemRef{Base: AX}},
		{Kind: OpMem, Mem: MemRef{Index: CX, Scale: 1}},
	} {
		if err := validateX86SourceMemoryScale(Instr{Args: []Operand{operand}}); err != nil {
			t.Fatalf("non-SIB/valid missing-register role was rejected: %+v: %v", operand, err)
		}
	}
	for _, scale := range []int64{0, -1, 3, 16} {
		if err := validateX86SourceMemoryScale(Instr{Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Index: CX, Scale: scale}}}}); err == nil {
			t.Fatalf("ordinary source SIB accepted scale %d", scale)
		}
	}
	for _, marker := range []Instr{
		{x86Encoded: true},
		{x86SourceRaw: &x86SourceRawInstruction{}},
	} {
		marker.Args = []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Index: CX}}}
		if err := validateX86SourceMemoryScale(marker); err != nil {
			t.Fatal("source guard reclassified a decoded physical instruction")
		}
	}
	// ARM64 keeps its independent unscaled-register memory convention.
	operand, err := parseOperandForArch(ArchARM64, "(R0)(R1)")
	if err != nil || operand.Mem.Index != "R1" || operand.Mem.Scale != 1 {
		t.Fatalf("x86 source grammar changed ARM64: %+v / %v", operand, err)
	}
}

func TestX86UnnamedAddressImmediateIgnoredRegisterInventory(t *testing.T) {
	names := x86SymbolIndexedActualRegisterNames(t)
	for _, arch := range []string{"386", "amd64"} {
		prefixes := x86SymbolIndexedActualSegmentPrefixes(t, arch)
		plain := x86PackedShiftActualGoBytes(t, arch, "TEXT addr(SB),4,$0-0\nADDL $1,DX\nRET\n")
		for _, name := range names {
			t.Run(arch+"/"+name, func(t *testing.T) {
				// Both Reg and unscaled Index are source annotations in this
				// TYPE_CONST row. No physical bank read follows from them.
				source := "TEXT addr(SB),4,$0-0\nADDL $1(" + name + ")(" + name + "),DX\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				derived, changed, err := normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch)
				if name == "TLS" {
					// The independent original probe reports need-reloc/reloc,
					// not a successful constant object or a source N/A proof.
					// No native TLS producer is present in this fixture.
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unbound TLS source lost Context: %v", err)
					}
					return
				}
				original := x86PackedShiftActualGoBytes(t, arch, source)
				want := plain
				if prefix := prefixes[name]; prefix != 0 {
					want = append([]byte{prefix}, plain...)
				}
				if !bytes.Equal(original, want) {
					t.Fatalf("original TYPE_ADDR prefix/constant encoding differs: %x != %x", original, want)
				}
				if name == "CS" || name == "SS" || name == "DS" || name == "ES" || name == "FS" || name == "GS" || name == "TLS" {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unbound segment/TLS source lost Context: %v", err)
					}
					return
				}
				if err != nil || !changed || derived.Args[0].Kind != OpImm || derived.Args[0].Imm != 1 {
					t.Fatalf("ignored source register became a physical input: %+v / %v", derived, err)
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateScale0FiveLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source := "TEXT ·addr(SB),4,$0-4\nMOVL $3,AX\nMOVL $2,CX\nMOVL $1,BX\n" +
				"MOVL $1(AX),DX\nMOVL $1(CX*1),DX\nMOVL $1(AX)(CX*8),DX\n" +
				"MOVB $1(X31)(Y20),BX\nMOVW $1(R15)(X31),BX\nADDL $1(AX)(CX),BX\n" +
				"IMUL3L $1(AX)(CX),DX,BX\nCMPL BX,$1(AX)(CX)\n" +
				"MOVL BX,ret+0(FP)\nRET\n"
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			pkg := x86AddSubLiteralPackage(t, target.arch, "func addr() uint32\n")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
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
						result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(ir, "%reg_X31") || strings.Contains(ir, "%reg_Y20") || strings.Contains(ir, "%reg_R15") {
						t.Fatal("TYPE_CONST annotations acquired physical inputs")
					}
					compileLLVMToObject(t, llc, target.triple, "scale0.ll", "scale0.o", ir)
				})
			}
		})
	}
}
