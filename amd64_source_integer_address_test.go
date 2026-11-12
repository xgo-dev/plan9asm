package plan9asm

import (
	"bytes"
	"crypto/sha256"
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

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

// The source rewrite precedes oclass. Keep the complete actual stock-Go rule,
// including its NAME_EXTERN/STATIC distinction; a version number is not proof.
const x86SourceAddressGoRewrite = `
if p.From.Type == obj.TYPE_ADDR && (ctxt.Arch.Family == sys.AMD64 || p.From.Name != obj.NAME_EXTERN && p.From.Name != obj.NAME_STATIC) {
	switch p.As {
	case AMOVL:
		p.As = ALEAL
		p.From.Type = obj.TYPE_MEM
	case AMOVQ:
		p.As = ALEAQ
		p.From.Type = obj.TYPE_MEM
	}
}`

func x86SourceAddressRewriteRule(source []byte) error {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "obj6.go", source, 0)
	if err != nil {
		return err
	}
	count := 0
	var actual string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "progedit" || function.Body == nil {
			continue
		}
		for _, statement := range function.Body.List {
			conditional, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			var condition bytes.Buffer
			if err := format.Node(&condition, set, conditional.Cond); err != nil {
				return err
			}
			if !strings.HasPrefix(condition.String(), "p.From.Type == obj.TYPE_ADDR &&") {
				continue
			}
			count++
			var body bytes.Buffer
			if err := format.Node(&body, set, conditional); err != nil {
				return err
			}
			actual = body.String()
		}
	}
	if count != 1 || actual != strings.TrimSpace(x86SourceAddressGoRewrite) {
		return fmt.Errorf("unrecognized stock-Go source-address rewrite (%d rules): %s", count, actual)
	}
	return nil
}

func TestX86UnnamedAddressImmediateActualGoSourceRule(t *testing.T) {
	// This existing observer binds the invoked driver/asm and complete source
	// bytes pre/post. Its float rewrite observation does not grant permissions.
	x86ScalarLiteralActualGoRewriteSet(t)
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "obj6.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86SourceAddressRewriteRule(source); err != nil {
		t.Fatal(err)
	}
	t.Logf("SOURCE_ADDRESS_REWRITE Go=%s SHA256=%x", runtime.Version(), sha256.Sum256(source))
	for _, change := range [][2]string{
		{"p.From.Type == obj.TYPE_ADDR &&", "p.From.Type == obj.TYPE_MEM &&"},
		{"ctxt.Arch.Family == sys.AMD64 ||", "ctxt.Arch.Family == sys.I386 ||"},
		{"p.From.Name != obj.NAME_EXTERN &&", "p.From.Name == obj.NAME_EXTERN &&"},
		{"p.From.Name != obj.NAME_STATIC", "p.From.Name == obj.NAME_STATIC"},
		{"case AMOVL:", "case AMOVW:"}, {"p.As = ALEAL", "p.As = AMOVL"},
		{"p.From.Type = obj.TYPE_MEM", "p.From.Type = obj.TYPE_CONST"},
		{"case AMOVQ:", "case AMOVB:"}, {"p.As = ALEAQ", "p.As = AMOVQ"},
	} {
		t.Run(change[0], func(t *testing.T) {
			// Mutate the independently matched complete rule, not an earlier
			// identical token in an unrelated obj6.go function.
			copy := strings.Replace(x86SourceAddressGoRewrite, change[0], change[1], 1)
			fixture := "package x86\nfunc progedit() {\n" + copy + "\n}\n"
			if copy == x86SourceAddressGoRewrite || x86SourceAddressRewriteRule([]byte(fixture)) == nil {
				t.Fatal("changed actual source rule was accepted")
			}
		})
	}
}

func TestX86UnnamedAddressImmediateGoDoubleShiftRejectsTypeAddr(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, operation := range []string{"SHLW", "SHLL", "SHLQ", "SHRW", "SHRL", "SHRQ"} {
			if arch == "386" && strings.HasSuffix(operation, "Q") {
				continue
			}
			t.Run(arch+"/"+operation, func(t *testing.T) {
				source := "TEXT addr(SB),4,$0-0\n" + operation + " $16(AX),CX,BX\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, source, false)
				// oclass alone is insufficient: movDoubleShift explicitly
				// requires TYPE_CONST rather than this original TYPE_ADDR.
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch); err == nil {
					t.Fatal("Go-invalid source identity was rewritten into a valid double shift")
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateImmutableAndProtected(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		file, err := Parse(ArchAMD64, "TEXT addr(SB),4,$0-0\nMOVL $16(AX)(CX*4),BX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		before := append([]Instr(nil), file.Funcs[0].Instrs...)
		for index := range before {
			before[index].Args = append([]Operand(nil), before[index].Args...)
		}
		derived, err := normalizeX86SourceIntegerAddresses(file, Options{Goarch: arch})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, file.Funcs[0].Instrs) || derived.Funcs[0].Instrs[1].Op != "LEAL" ||
			derived.Funcs[0].Instrs[1].Raw != before[1].Raw {
			t.Fatal("adapter changed source or lost its original source spelling")
		}
		again, err := normalizeX86SourceIntegerAddresses(derived, Options{Goarch: arch})
		if err != nil || !reflect.DeepEqual(derived, again) {
			t.Fatalf("adapter is not idempotent: %v", err)
		}
		for _, field := range []string{"addressBits", "addressOverride", "encoded", "LOCK", "rawText", "sourceStack", "fixedLocal"} {
			t.Run(arch+"/"+field, func(t *testing.T) {
				protected := *file
				protected.Funcs = append([]Func(nil), file.Funcs...)
				protected.Funcs[0].Instrs = append([]Instr(nil), before...)
				switch field {
				case "addressBits":
					protected.Funcs[0].Instrs[1].x86AddressBits = 32
				case "addressOverride":
					protected.Funcs[0].Instrs[1].x86UnboundAddressOverride = true
				case "encoded":
					protected.Funcs[0].Instrs[1].x86Encoded = true
				case "LOCK":
					protected.Funcs[0].Instrs = append(protected.Funcs[0].Instrs, Instr{Op: "LOCK"})
				case "rawText":
					protected.Funcs[0].X86RawText = []byte{0xc3}
				case "sourceStack":
					protected.Funcs[0].x86SourceStack = &x86SourceStackProof{}
				case "fixedLocal":
					protected.Funcs[0].x86FixedLocal = &x86FixedLocalProof{}
				}
				if _, err := normalizeX86SourceIntegerAddresses(&protected, Options{Goarch: arch}); err == nil {
					t.Fatal("address adapter inherited an unrelated original-source/encoder certificate")
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateSourceRoles(t *testing.T) {
	for _, spelling := range []string{
		"$·cell(SB)", "$local+16(SP)", "$arg+8(FP)", "16(AX)", "$16",
		"$·cell(SB)(BX*4)", "$·cell(SB)(AX)(CX*2)",
		"$runtime·mainPC+16(SB)", "$runtime·mainPC(SB)(BX)",
		"$runtime·mainPC+16(SB)(BX*1)", "$runtime·mainPC-8(SB)(AX)(CX*4)",
		"$local+16(SP)(BX*4)", "$arg+8(FP)(AX)(CX*2)",
	} {
		operand, err := parseOperandForArch(ArchAMD64, spelling)
		if err != nil {
			t.Fatal(err)
		}
		if _, matched, err := x86UnnamedSourceAddress(operand); err != nil || matched {
			t.Fatalf("independent source role was reclassified: %s: %v", spelling, err)
		}
	}
	for _, address := range []string{"16(FS)", "8(AX)(GS*1)", "16(TLS)", "16(AX)(CX*3)", "16(AX)(CX*01)", "16(AX)(CX*4)(DX*2)"} {
		operand := Operand{Kind: OpSym, Sym: "$" + address}
		if _, matched, err := x86UnnamedSourceAddress(operand); !matched || err == nil {
			t.Fatalf("unbound/invalid source address gained authority: %s / %v", address, err)
		}
	}
}

func TestX86UnnamedAddressImmediateParenthesizedDisplacement(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, expression := range []string{"(1<<4)", "((1<<4))", "(8+(2*4))", "-((1<<4))"} {
			t.Run(arch+"/"+expression, func(t *testing.T) {
				instruction := "MOVW $" + expression + "(AX),BX"
				fixture := "TEXT addr(SB),4,$0-0\n" + instruction + "\nRET\n"
				original := x86PackedShiftActualGoBytes(t, arch, fixture)
				literal := "16"
				if strings.HasPrefix(expression, "-") {
					literal = "-16"
				}
				plain := x86PackedShiftActualGoBytes(t, arch, strings.Replace(fixture, "$"+expression+"(AX)", "$"+literal, 1))
				if !bytes.Equal(original, plain) {
					t.Fatalf("original constant expression changed its encoding: %x != %x", original, plain)
				}
				file, err := Parse(ArchAMD64, fixture)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"addr": {Ret: Void}}}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// This matrix is independent of the adapter: classify actual signed offsets
// from the complete Yi8/Yu8/Yi32 source domains, including the 386 truncation.
func TestX86UnnamedAddressImmediateCompleteLiteralClassBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, family := range []string{
			"MOV", "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST",
			"IMUL", "IMUL3", "PUSH", "BT", "BTC", "BTR", "BTS",
			"SAL", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR",
		} {
			for _, suffix := range []string{"B", "W", "L", "Q"} {
				if family == "MOV" && (suffix == "L" || suffix == "Q") ||
					suffix == "B" && (strings.HasPrefix(family, "IMUL") || strings.HasPrefix(family, "BT") || family == "PUSH") {
					continue
				}
				for _, value := range []int64{
					-2147483649, -2147483648, -129, -128, -1, 0, 1, 3, 4, 127,
					128, 255, 256, 2147483647, 2147483648, 4294967295, 4294967296,
				} {
					operation := family + suffix
					literal := value
					if arch == "386" {
						literal = int64(int32(value))
					}
					accepted := literal >= -2147483648 && literal <= 4294967295
					if strings.HasPrefix(family, "BT") {
						accepted = literal >= -128 && literal <= 127
					} else if family == "SAL" || family == "SHL" || family == "SHR" || family == "SAR" ||
						family == "ROL" || family == "ROR" || family == "RCL" || family == "RCR" {
						accepted = literal >= 0 && literal <= 255 // Yi8 does not cover Yu8.
					}
					if arch == "386" && suffix == "Q" || family == "PUSH" &&
						(suffix == "L" && arch != "386" || suffix == "Q" && arch != "amd64") {
						accepted = false
					}
					t.Run(fmt.Sprintf("%s/%s/%d", arch, operation, value), func(t *testing.T) {
						annotation := fmt.Sprintf("$%d(AX)(CX*1)", value)
						operands := annotation + ",BX"
						if family == "CMP" {
							operands = "BX," + annotation
						} else if family == "IMUL3" {
							operands = annotation + ",CX,BX"
						} else if family == "PUSH" {
							operands = annotation
						}
						ending := "RET\n"
						if family == "PUSH" {
							ending = "POP" + suffix + " BX\nRET\n"
						}
						fixture := "TEXT addr(SB),4,$0-0\n" + operation + " " + operands + "\n" + ending
						listing, goErr := x86ScalarLiteralExpectedGoListing(t, arch, fixture, accepted)
						if !accepted {
							t.Logf("ACTUAL_TYPE_ADDR_REJECTION arch=%s instruction=%q error=%v diagnostic=%q", arch, operation+" "+operands, goErr, listing)
						}
						file, err := Parse(ArchAMD64, fixture)
						if err != nil {
							t.Fatal(err)
						}
						_, _, err = normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch)
						if (err == nil) != accepted {
							t.Fatalf("literal class mismatch: accepted=%v: %v", accepted, err)
						}
					})
				}
			}
		}
	}
}

func TestX86UnnamedAddressImmediateDefaultMode(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT addr(SB),4,$0-0\nMOVL $3,AX\nMOVL $16(AX),BX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Sigs: map[string]FuncSig{"addr": {Ret: Void}}}
	if _, err := normalizeX86SourceIntegerAddresses(file, options); err != nil {
		t.Fatalf("default AMD64 mode was lost: %v", err)
	}
	if _, err := Translate(file, options); err != nil {
		t.Fatal(err)
	}
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestX86UnnamedAddressImmediateUnresolvedDisplacement(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, instruction := range []string{"MOVL $UNKNOWN(AX),BX", "MOVW $UNKNOWN(AX)(CX*1),BX"} {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT addr(SB),4,$0-0\n" + instruction + "\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"addr": {Ret: Void}}}); err == nil {
					t.Fatal("unresolved displacement became a zero-valued literal")
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateThreeAPIsCannotGrantSourceRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, instruction := range []string{
			"MOVL $16(AX),X0", "MOVL $16(AX),(BX)",
			"MOVL $UNKNOWN(AX),BX", "MOVW $UNKNOWN(AX)(CX*1),BX",
			"MOVW $16(FS),BX", "MOVL $16(AX)(GS*1),BX",
			"MOVL $16(AX)(SP*1),BX", "MOVW $16(AX)(CX*3),BX",
			"ADDW $16(AX),$8(BX)", "FMOVD $16(AX),F0",
			"FMOVDP F0,$16(AX)", "MOVSS $16(AX),X0",
			"SHRW $16(AX),CX,BX", "MOVB $16(AX),BX\nMOVQ BX,(SP)\nBYTE $0xc3",
		} {
			t.Run(target.triple+"/"+instruction, func(t *testing.T) {
				source := "TEXT ·addr(SB),4,$0-0\n" + instruction + "\nRET\n"
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
							t.Fatal("source adapter supplied an unproved memory/encoder/operand role")
						}
					})
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateSignExtendedImm32(t *testing.T) {
	for _, operation := range []string{"ADDQ", "SUBQ", "ADCQ", "SBBQ", "ANDQ", "ORQ", "XORQ", "TESTQ", "CMPQ", "IMULQ", "IMUL3Q", "PUSHQ"} {
		for _, value := range []string{"0x80000000", "0xffffffff"} {
			t.Run(operation+"/"+value, func(t *testing.T) {
				operands := "$" + value + "(AX),BX"
				if operation == "CMPQ" {
					operands = "BX,$" + value + "(AX)"
				} else if operation == "IMUL3Q" {
					operands = "$" + value + "(AX),CX,BX"
				} else if operation == "PUSHQ" {
					operands = "$" + value + "(AX)"
				}
				instruction := operation + " " + operands
				ending := "RET\n"
				if operation == "PUSHQ" {
					ending = "POPQ BX\nRET\n"
				}
				fixture := "TEXT addr(SB),4,$0-0\n" + instruction + "\n" + ending
				original := x86PackedShiftActualGoBytes(t, "amd64", fixture)
				integer, _ := parseImmExpr(value)
				want := int64(int32(integer))
				// The signed spelling can select shorter imm8 bytes. Bind the
				// actual original instruction's decoded imm32 value instead of
				// claiming that the two source classes have identical widths.
				decoded, err := x86asm.Decode(original, 64)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, argument := range decoded.Args {
					if immediate, ok := argument.(x86asm.Imm); ok {
						found = true
						if int64(immediate) != want {
							t.Fatalf("actual Go decoded imm32=%d, want %d; original=%x", immediate, want, original)
						}
					}
				}
				if !found {
					t.Fatalf("actual Go source has no physical immediate: %x", original)
				}
				t.Logf("ORIGINAL_SIGNEXT %s %s bytes=%x decoded=%s", operation, value, original, decoded)
				file, err := Parse(ArchAMD64, fixture)
				if err != nil {
					t.Fatal(err)
				}
				derived, changed, err := normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], "amd64")
				if err != nil || !changed {
					t.Fatalf("source imm32 class: %v", err)
				}
				index := 0
				if operation == "CMPQ" {
					index = 1
				}
				if derived.Args[index].Kind != OpImm || derived.Args[index].Imm != want {
					t.Fatalf("native imm32 widened as %d, want %d", derived.Args[index].Imm, want)
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediatePushSourceModes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, suffix := range []string{"B", "W", "L", "Q"} {
			for _, value := range []string{"-128", "127", "128", "0xffffffff"} {
				t.Run(arch+"/"+suffix+"/"+value, func(t *testing.T) {
					valid := suffix == "W" || arch == "386" && suffix == "L" || arch == "amd64" && suffix == "Q"
					fixture := "TEXT addr(SB),4,$0-0\nPUSH" + suffix + " $" + value + "(AX)(CX*1)\nPOP" + suffix + " BX\nRET\n"
					if valid {
						original := x86PackedShiftActualGoBytes(t, arch, fixture)
						plain := strings.ReplaceAll(fixture, "(AX)(CX*1)", "")
						if !bytes.Equal(original, x86PackedShiftActualGoBytes(t, arch, plain)) {
							t.Fatal("PUSH TYPE_ADDR was treated as an effective address")
						}
					} else {
						x86ScalarLiteralExpectedGoListing(t, arch, fixture, false)
					}
					file, err := Parse(ArchAMD64, fixture)
					if err != nil {
						t.Fatal(err)
					}
					_, _, err = normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch)
					if (err == nil) != valid {
						t.Fatalf("PUSH source mode %s/%s: %v", arch, suffix, err)
					}
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediateThreeAPIsFiveLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			pkg := x86AddSubLiteralPackage(t, target.arch, "func addr() uint32\n")
			var source strings.Builder
			source.WriteString("TEXT ·addr(SB),4,$0-4\nMOVL $3,AX\nMOVL $2,CX\nMOVL $1,BX\nCLC\n")
			for _, stem := range []string{"MOV", "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST", "SAL", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR", "IMUL", "IMUL3", "BT", "BTC", "BTR", "BTS"} {
				for _, suffix := range []string{"B", "W", "L", "Q"} {
					if suffix == "Q" && target.arch == "386" || suffix == "B" && (strings.HasPrefix(stem, "IMUL") || strings.HasPrefix(stem, "BT")) {
						continue
					}
					operands := "$16(AX)(CX*1),BX"
					if stem == "CMP" {
						operands = "BX,$16(AX)(CX*1)"
					} else if stem == "IMUL3" {
						operands = "$16(AX)(CX*1),CX,BX"
					}
					fmt.Fprintf(&source, "%s%s %s\n", stem, suffix, operands)
				}
			}
			// TYPE_CONST ignores source Reg/Index, including non-GP banks.
			// These are not physical register availability grants in mode32.
			source.WriteString("MOVB $16(X31)(Y20*1),BX\nMOVW $8(R15)(X30*4),BX\nPUSHW $128(X31)\nPOPW DX\n")
			if target.arch == "amd64" {
				source.WriteString("PUSHQ $-128(Y20)\nPOPQ DX\n")
			} else {
				source.WriteString("PUSHL $-128(Y20)\nPOPL DX\n")
			}
			source.WriteString("MOVL BX,ret+0(FP)\nRET\n")
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			file, err := Parse(ArchAMD64, source.String())
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
						result, err = translateGoModuleInContext(context, pkg, []byte(source.String()), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(ir, "%reg_X31") || strings.Contains(ir, "%reg_Y20") || strings.Contains(ir, "%reg_R15") || strings.Contains(ir, "%reg_X30") {
						t.Fatal("discarded constant annotations became physical register inputs")
					}
					compileLLVMToObject(t, llc, target.triple, "source-address.ll", "source-address.o", ir)
				})
			}
		})
	}
}
