package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Read the complete actual frontend registration, not an Intel mnemonic list.
func x86OriginalMOVQAliases(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var aliases []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "archX86" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			index, indexed := assignment.Lhs[0].(*ast.IndexExpr)
			selector, selected := assignment.Rhs[0].(*ast.SelectorExpr)
			if !indexed || !selected || selector.Sel.Name != "AMOVQ" {
				return true
			}
			bank, registered := index.X.(*ast.Ident)
			owner, original := selector.X.(*ast.Ident)
			literal, named := index.Index.(*ast.BasicLit)
			if !registered || bank.Name != "instructions" || !original || owner.Name != "x86" || !named || literal.Kind != token.STRING {
				t.Fatal("unknown original MOVQ alias registration")
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			aliases = append(aliases, name)
			return true
		})
	}
	if !reflect.DeepEqual(aliases, []string{"MOVD", "MOVDQ2Q"}) {
		t.Fatalf("complete original MOVQ aliases changed: %v", aliases)
	}
	return aliases
}

func TestX86MOVQSourceAliasesCompleteOriginalRegistrationAndTLS(t *testing.T) {
	if !reflect.DeepEqual(x86GoMOVQSourceAliases, map[Op]Op{"MOVD": "MOVQ", "MOVDQ2Q": "MOVQ"}) {
		t.Fatal("source alias normalization differs from the complete original frontend")
	}
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, arch := range []string{"386", "amd64"} {
			for _, operands := range []string{"TLS,AX", "TLS,R15", "8(TLS),X0", "X7,0(CX)(TLS*4)", "8(TLS),M0"} {
				t.Run(arch+"/"+alias+"/"+operands, func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, alias+" "+operands)
					before := ins
					if err := x86SourceTLSMoveError(ins, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("complete actual MOVQ alias lost its source TLS boundary: %v", err)
					}
					if !reflect.DeepEqual(ins, before) {
						t.Fatal("source alias validator changed original source")
					}
				})
			}
		}
	}
}

func TestX86MOVQSourceAliasesOriginalFormsAndByteParity(t *testing.T) {
	// Every ymovq row, both overlapping register/memory axes and all immediate
	// classes are represented. The full historical/current table is pinned by
	// TestX86GPSIMDTransferCompleteLegacyOriginalTables independently.
	for _, arch := range []string{"amd64", "386"} {
		for _, operands := range []string{
			"8(BX),M0", "M0,8(BX)", "X0,M0", "8(BX),X0", "X0,X1", "X0,8(BX)",
			"AX,BX", "AX,8(BX)", "8(BX),AX", "$0,AX", "$-1,AX", "$4294967296,AX", "$1,8(BX)",
			"AX,M0", "M0,M1", "M0,AX", "AX,X0", "X0,AX", "$slot+0(FP),AX", "$slot+0(SP),AX",
		} {
			accepted := arch == "amd64" || operands == "8(BX),M0" || operands == "M0,8(BX)" ||
				operands == "X0,M0" || operands == "8(BX),X0" || operands == "X0,X1" || operands == "X0,8(BX)"
			for _, alias := range append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...) {
				t.Run(arch+"/"+alias+"/"+operands, func(t *testing.T) {
					source := "TEXT native(SB),4,$0-16\n" + alias + " " + operands + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", accepted)
					if accepted {
						canonical := strings.Replace(source, alias+" ", "MOVQ ", 1)
						first, second := x86OrderingHintGoBytes(t, arch, source), x86OrderingHintGoBytes(t, arch, canonical)
						if !bytes.Equal(first, second) {
							t.Fatalf("original Go alias bytes differ from MOVQ: %x != %x", first, second)
						}
					}
				})
			}
		}
	}
}

func TestX86MOVQSourceAliasesThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, alias := range x86OriginalMOVQAliases(t) {
			bodies := []string{alias + " x+0(FP),X0\n" + alias + " X0,X1\n" + alias + " X1,ret+8(FP)\nRET"}
			if target.arch == "amd64" {
				bodies = append(bodies,
					alias+" x+0(FP),CX\n"+alias+" CX,DX\n"+alias+" DX,ret+8(FP)\nRET",
					alias+" x+0(FP),CX\n"+alias+" CX,X0\n"+alias+" X0,DX\n"+alias+" DX,ret+8(FP)\nRET")
			}
			for _, body := range bodies {
				t.Run(target.triple+"/"+alias+"/"+body, func(t *testing.T) {
					_, _, _, source := x86ResultInitializationFixture(t, target.arch, "func Value(x uint64) uint64", body)
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(x uint64) uint64\n", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatalf("%s original alias translation: %v", api, err)
						}
						x86ResultInitializationObject(t, llc, target.triple, ir, api)
					}
				})
			}
		}
	}
}

func TestX86MOVQSourceAliasesMachineRegisterRows(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, alias := range x86OriginalMOVQAliases(t) {
			t.Run(target.triple+"/"+alias, func(t *testing.T) {
				var body strings.Builder
				for _, machine := range []string{"CR0", "CR2", "CR3", "CR4", "DR0", "DR2", "DR3", "DR6", "DR7"} {
					fmt.Fprintf(&body, "%s %s,AX\n%s AX,%s\n", alias, machine, alias, machine)
				}
				if target.arch == "amd64" {
					fmt.Fprintf(&body, "%s CR8,AX\n%s AX,CR8\n", alias, alias)
				}
				for _, machine := range []string{"GDTR", "IDTR"} {
					fmt.Fprintf(&body, "%s 0(BX),%s\n%s %s,16(BX)\n", alias, machine, alias, machine)
				}
				source := "TEXT machine(SB),4,$0-0\n" + body.String() + "RET\n"
				canonical := strings.ReplaceAll(source, alias+" ", "MOVQ ")
				if !bytes.Equal(x86OrderingHintGoBytes(t, target.arch, source), x86OrderingHintGoBytes(t, target.arch, canonical)) {
					t.Fatal("complete machine-register alias bytes changed")
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func machine()\n", target.arch, target.triple, api)
					if err != nil {
						t.Fatal("source aliases lost actual Go movtab rows", api, err)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, "machine-"+api)
				}
			})
		}
	}
}

func TestX86MOVQSourceAliasesCompleteOriginalMovtab(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected []string
	for _, row := range regexp.MustCompile(`\{AMOVQ,\s*Y\w+,\s*Ynone,[^\n]+`).FindAllString(string(source), -1) {
		actual = append(actual, strings.Join(strings.Fields(row), ""))
	}
	for _, bank := range []struct{ class, opcode string }{{"cr", "20"}, {"dr", "21"}} {
		indices := []int{0, 2, 3, 4, 8}
		if bank.class == "dr" {
			indices = []int{0, 2, 3, 6, 7}
		}
		for _, direction := range []bool{false, true} {
			for _, index := range indices {
				from, to, zcase, opcode := fmt.Sprintf("Y%s%d", bank.class, index), "Yrl", "movRegMem2op", bank.opcode
				if direction {
					from, to, zcase = to, from, "movMemReg2op"
					if bank.class == "cr" {
						opcode = "22"
					} else {
						opcode = "23"
					}
				}
				expected = append(expected, fmt.Sprintf("{AMOVQ,%s,Ynone,%s,%s,[4]uint8{0x0f,0x%s,%d,0}},", from, to, zcase, opcode, index))
			}
		}
	}
	for _, class := range []string{"Ygdtr", "Yidtr"} {
		digit := 2
		if class == "Yidtr" {
			digit = 3
		}
		expected = append(expected,
			fmt.Sprintf("{AMOVQ,Ym,Ynone,%s,movMemReg2op,[4]uint8{0x0f,0x01,%d,0}},", class, digit),
			fmt.Sprintf("{AMOVQ,%s,Ynone,Ym,movRegMem2op,[4]uint8{0x0f,0x01,%d,0}},", class, digit-2))
	}
	expected = append(expected, "{AMOVQ,Ytls,Ynone,Yrl,movTLSReg,[4]uint8{0,0,0,0}},")
	if len(expected) != 25 || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("complete original MOVQ movtab changed: %v", actual)
	}
}

func TestX86MOVQSourceAliasesRejectedFormsThreeAPIs(t *testing.T) {
	for _, alias := range append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...) {
		for _, arch := range []string{"amd64", "386"} {
			for _, operands := range []string{"TLS,X0", "AX,TLS", "$1.5,X0", "$1.5,AX", "M0,X0", "X0,Y0", "X16,X0", "AX,X0,X1"} {
				source := "TEXT Value(SB),4,$0-0\n" + alias + " " + operands + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				for _, api := range []string{"text", "module", "Go"} {
					triple := "x86_64-unknown-linux-gnu"
					if arch == "386" {
						triple = "i386-unknown-linux-gnu"
					}
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()\n", arch, triple, api)
					if err == nil || errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("%s invalid original alias became Context/success: %s %s: %v", api, alias, operands, err)
					}
				}
			}
		}
	}
}

func TestX86MOVQSourceAliasesNumericalEffectsEveryInputByte(t *testing.T) {
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, arch := range []string{"amd64", "386"} {
			for _, operands := range []string{"AX,BX", "AX,X1", "X0,BX", "X0,X1", "X0,M1"} {
				ins := x86PureGPUnknownInstruction(t, alias+" "+operands)
				canonical := ins
				canonical.Op = "MOVQ"
				for missing := -1; missing < 16; missing++ {
					for _, consumer := range x86ResultGPSIMDConsumers {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0], state.xmm[0], state.xmm[1] = 0xff, 0xffff, 0x5151
						if missing >= 0 {
							state.gp[0] &^= uint8(1) << uint(missing)
							state.xmm[0] &^= uint16(1) << uint(missing)
						}
						want := state.clone()
						accepted := consumer.step(ins, &state, nil, 0, arch)
						if accepted != consumer.step(canonical, &want, nil, 0, arch) || !reflect.DeepEqual(state, want) {
							t.Fatalf("%s numerical alias byte/state mismatch: %s %s arch=%s missing=%d", consumer.name, alias, operands, arch, missing)
						}
						if state.flags != x86ByteFlagsAll {
							t.Fatal("source MOVQ alias changed status knowledge")
						}
					}
				}
			}
		}
	}
}

func TestX86MOVQSourceAliasesScalarFPWidthsAndOriginalCallerIdentity(t *testing.T) {
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, row := range []string{alias + " x+0(FP),AX", alias + " AX,ret+8(FP)"} {
			ins := x86PureGPUnknownInstruction(t, row)
			index := 0
			if ins.Args[1].Kind == OpFP {
				index = 1
			}
			if width, write, known := X86FPAccessBytes(ins, index, "amd64"); !known || width != 8 || write != (index == 1) {
				t.Errorf("original alias FP width lost: %s: %d %v %v", row, width, write, known)
			}
			if width := x86ScalarMoveMemoryBytes(ins, index, "amd64"); width != 8 {
				t.Errorf("original source-stack width lost: %s: %d", row, width)
			}
		}
		body := alias + " DI,R11\n" + alias + " R11,DI\nMOVL $7,AX\nMOVL AX,(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", body, 1)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		before, err := x86CallerSourceFingerprint(file.Funcs[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
			t.Errorf("actual source alias lost complete caller/pointer identity: %s: %v", alias, err)
		}
		after, err := x86CallerSourceFingerprint(file.Funcs[0])
		if err != nil || before != after {
			t.Fatal("alias consumer changed the original sealed caller source")
		}
	}
}

func TestX86MOVQSourceAliasesNativeLoadsAndMode32Rejections(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, alias := range x86OriginalMOVQAliases(t) {
			for _, destination := range []string{"X0", "DX"} {
				if target.arch == "386" && destination == "DX" {
					continue
				}
				t.Run(target.triple+"/"+alias+"/"+destination, func(t *testing.T) {
					move, result := "MOVQ", 8
					if target.arch == "386" {
						move, result = "MOVL", 4
					}
					body := fmt.Sprintf("%s p+0(FP),AX\n%s -1(AX)(CX*1),%s\n%s %s,ret+%d(FP)\nRET", move, alias, destination, alias, destination, result)
					body = strings.Replace(body, alias+" -1", "MOVL $1,CX\n"+alias+" -1", 1)
					_, _, _, source := x86ResultInitializationFixture(t, target.arch, "func Value(p *[8]byte) uint64", body)
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[8]byte) uint64\n", target.arch, target.triple, api)
						if err != nil || !strings.Contains(ir, "load volatile i64") {
							t.Fatalf("%s alias lost its exact eight-byte native read: %v\n%s", api, err, ir)
						}
						x86ResultInitializationObject(t, llc, target.triple, ir, api)
					}
				})
			}
		}
	}
	for _, alias := range x86OriginalMOVQAliases(t) {
		for _, operands := range []string{"AX,BX", "(AX),BX", "AX,(BX)", "AX,X0", "X0,AX", "$1,AX", "M0,M1"} {
			source := "TEXT Value(SB),4,$0-0\n" + alias + " " + operands + "\nRET\n"
			goAssemblerOracleOutput(t, "386", source, "", false)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()\n", "386", "i386-unknown-linux-gnu", api)
				if err == nil || errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("%s mode32 alias admitted an actual rejected MOVQ row: %s %s: %v", api, alias, operands, err)
				}
			}
		}
	}
}

func TestX86MOVQSourceAliasesRetainRawIntelAndUnknownState(t *testing.T) {
	for _, body := range []string{
		"MOVDQ2Q CX,X0\nMOVQ X0,ret+0(FP)\nRET",
		"MOVB $1,CX\nMOVDQ2Q CX,X0\nMOVQ X0,ret+0(FP)\nRET",
		"MOVQ $1,CX\nMOVQ CX,X0\nBYTE $0xf2\nBYTE $0x0f\nBYTE $0xd6\nBYTE $0xc8\nMOVQ M1,ret+0(FP)\nRET",
	} {
		_, _, _, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", body)
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint64\n", "amd64", "x86_64-unknown-linux-gnu", api)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Errorf("%s source alias acquired initialized/native MMX state: body=%q: %v", api, body, err)
			}
		}
	}
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nMOVDQ2Q AX,BX\nBYTE $0xf2\nBYTE $0x0f\nBYTE $0xd6\nBYTE $0xc8\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := NormalizeRawFileForTranslation(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x86asm.Decode([]byte{0xf2, 0x0f, 0xd6, 0xc8}, 64)
	if err != nil || raw.Op != x86asm.MOVDQ2Q {
		t.Fatal("independent literal bytes lost physical MOVDQ2Q")
	}
	physical := normalized.Funcs[0].Instrs[2]
	if normalized.Funcs[0].Instrs[1].Op != "MOVDQ2Q" || normalized.Funcs[0].Instrs[1].Raw != "MOVDQ2Q AX,BX" ||
		physical.Op != "MOVDQ2Q" || physical.x86SourceRaw == nil || physical.Args[1].Reg != "M1" || file.Funcs[0].Instrs[1].Op != "MOVDQ2Q" {
		t.Fatalf("named Go alias changed its original spelling or raw Intel physical role: %+v", normalized.Funcs[0].Instrs)
	}
	for _, alias := range x86OriginalMOVQAliases(t) {
		ins := x86PureGPUnknownInstruction(t, alias+" X0,M1")
		state := x86ResultState{}
		state.xmm[0] = 0xffff
		for _, consumer := range x86ResultGPSIMDConsumers {
			if consumer.step(ins, &state, nil, 0, "amd64") {
				t.Fatal("numerical alias observer manufactured native MMX state", alias, consumer.name)
			}
		}
	}
}
