package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type x86ScalarIntegerRawRow struct {
	name, operand string
	code          []byte
	evex, memory  bool
}

func x86ScalarIntegerRawRows(t *testing.T, arch string) []x86ScalarIntegerRawRow {
	t.Helper()
	var rows []x86ScalarIntegerRawRow
	var original strings.Builder
	for _, name := range x86ScalarIntegerNativeNames(arch) {
		operands := []string{"X1", "(BX)"}
		if name == "CVTSS2SL" || name == "VCVTSS2SI" || name == "VCVTSS2USIL" {
			operands = append(operands, "(BX)(CX*1)")
		}
		for _, operand := range operands {
			rows = append(rows, x86ScalarIntegerRawRow{name: name, operand: operand, memory: operand != "X1"})
			original.WriteString(name + " " + operand + ",AX\n")
		}
		if strings.HasPrefix(name, "V") {
			controls := []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}
			if strings.Contains(name, "CVTT") {
				controls = []string{"SAE"}
			}
			for _, control := range controls {
				rows = append(rows, x86ScalarIntegerRawRow{name: name + "." + control, operand: "X1", evex: true})
				original.WriteString(name + "." + control + " X1,AX\n")
			}
		}
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, arch, original.String()+"RET\n")
	if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("actual Go scalar conversion directory lost complete original PCs/RET")
	}
	for index := range rows {
		rows[index].code = append([]byte(nil), code[pcs[index]:pcs[index+1]]...)
		rows[index].evex = rows[index].code[0] == 0x62
	}
	// Independent low-bank EVEX literals overlap the Go encoder's VEX choice.
	// They are not attributed to named Go output; llvm-mc checks them below.
	for _, name := range x86ScalarIntegerNativeNames(arch) {
		if !strings.HasPrefix(name, "V") || strings.Contains(name, "USI") {
			continue
		}
		pp, opcode := byte(2), byte(0x2d)
		if strings.Contains(name, "SD") {
			pp = 3
		}
		if strings.Contains(name, "CVTT") {
			opcode = 0x2c
		}
		p1 := byte(0x7c) | pp
		if strings.HasSuffix(name, "Q") {
			p1 |= 0x80
		}
		for _, memory := range []bool{false, true} {
			operand, modrm := "X1", byte(0xc1)
			if memory {
				operand, modrm = "(BX)", 0x03
			}
			rows = append(rows, x86ScalarIntegerRawRow{name, operand, []byte{0x62, 0xf1, p1, 0x08, opcode, modrm}, true, memory})
		}
		if name == "VCVTSS2SI" {
			rows = append(rows, x86ScalarIntegerRawRow{name, "(BX)(CX*1)", []byte{0x62, 0xf1, p1, 0x08, opcode, 0x04, 0x0b}, true, true})
		}
	}
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required for independent scalar conversion physical prior")
	}
	var physical strings.Builder
	for _, row := range rows {
		for _, b := range row.code {
			fmt.Fprintf(&physical, "0x%02x ", b)
		}
		physical.WriteByte('\n')
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+x86AddressMemoryTargets(arch)[0], "--mattr=+avx,+avx512f,+avx512vl")
	command.Stdin = strings.NewReader(physical.String())
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") || strings.Count(string(output), "2si")+strings.Count(string(output), "2usi") != len(rows) {
		t.Fatalf("independent full scalar conversion physical prior: %v\n%s", err, output)
	}
	want := 108
	if arch == "386" {
		want = 100
	}
	if len(rows) != want {
		t.Fatal("incomplete original scalar conversion generation/control directory", arch, len(rows), want)
	}
	return rows
}

func x86ScalarIntegerRawSource(arch, symbol string, row x86ScalarIntegerRawRow, variant string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	setup := fmt.Sprintf("%s p+0(FP),BX\n%s csr+%d(FP),SI\nLDMXCSR (SI)\nPXOR X0,X0\nPXOR X1,X1\n", move, move, word)
	if strings.Contains(row.operand, "CX") {
		setup += "MOVL $0,CX\n"
	}
	switch variant {
	case "missing-pointer":
		setup = strings.Replace(setup, move+" p+0(FP),BX\n", "", 1)
	case "numeric-pointer":
		setup += move + " $4096,BX\n"
	case "missing-vector":
		setup = strings.Replace(setup, "PXOR X1,X1\n", "", 1)
	case "missing-mxcsr":
		setup = strings.Replace(setup, fmt.Sprintf("%s csr+%d(FP),SI\n", move, word), "", 1)
	case "missing-index":
		setup = strings.Replace(setup, "MOVL $0,CX\n", "", 1)
	case "opaque-index":
		setup += move + " p+0(FP),CX\n"
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s%sMOVL AX,ret+%d(FP)\nRET\n",
			symbol, 2*word+4, setup, x86RawDisplacementDirectives(row.code), 2*word),
		fmt.Sprintf("func %s(p *uint64,csr *uint32) uint32\n", symbol)
}

func TestX86ScalarFloatIntegerInitializedRawCompleteFamilyObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rowsByArch := map[string][]x86ScalarIntegerRawRow{
		"amd64": x86ScalarIntegerRawRows(t, "amd64"),
		"386":   x86ScalarIntegerRawRows(t, "386"),
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := rowsByArch[target.arch]
			for start := 0; start < len(rows); start += 96 {
				t.Run(fmt.Sprintf("batch-%d", start/96), func(t *testing.T) {
					var source, decl strings.Builder
					for index := start; index < len(rows) && index < start+96; index++ {
						body, declaration := x86ScalarIntegerRawSource(target.arch, fmt.Sprintf("raw%d", index), rows[index], "")
						source.WriteString(body)
						decl.WriteString(declaration)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), decl.String(), target.arch, target.triple, api)
							if err != nil {
								t.Fatal("complete initialized original raw conversion lost its native continuation", err)
							}
							for _, input := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
								compileLLVMToObject(t, llc, target.triple, "raw-scalar-native.ll", "raw-scalar-native.o", input)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86ScalarFloatIntegerRawProducerIdentityAndMissingInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := x86AddressMemoryTargets(arch)[0]
		rows := x86ScalarIntegerRawRows(t, arch)
		var original strings.Builder
		for index, row := range rows {
			source, _ := x86ScalarIntegerRawSource(arch, fmt.Sprintf("original%d", index), row, "")
			original.WriteString(source)
		}
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
		for index, row := range rows {
			t.Run(fmt.Sprintf("%s/row-%d", arch, index), func(t *testing.T) {
				source, decl := x86ScalarIntegerRawSource(arch, "value", row, "")
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
				if err != nil {
					t.Fatal(err)
				}
				fn := file.Funcs[0]
				ordinal := len(fn.Instrs) - 3
				instruction := fn.Instrs[ordinal]
				expected := x86ScalarLaneInstruction(t, row.name+" "+row.operand+",AX")
				if instruction.Op != expected.Op || !reflect.DeepEqual(instruction.Args, expected.Args) {
					t.Fatal("original physical conversion lost its exact opcode/operands", instruction, expected)
				}
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{instruction}})
				if instruction.x86ScalarFloatIntegerEVEX != row.evex || strings.Contains(features, "+avx512f") != row.evex {
					t.Error("isolated physical conversion lost its low-bank generation/ISA", row.name, row.evex, features)
				}
				pkg := mustGoPackage(t, "rawconversion", "package rawconversion\n"+decl)
				sigs, err := goSigsForAsmFile(pkg, file, func(s string) string { return strings.TrimPrefix(s, "·") }, arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				check := func(fn Func) error {
					consumer := newX86Ctx(new(strings.Builder), fn, sigs["value"], nil, sigs, arch, triple, false)
					return consumer.checkLoweredScalarFPResultInitialization()
				}
				t.Run("valid-original", func(t *testing.T) {
					if err := check(fn); err != nil {
						t.Fatal("initialized exact original producer rejected", err)
					}
				})
				for _, mutation := range []struct {
					name string
					edit func(*Func)
				}{
					{"missing replay", func(f *Func) { f.x86RawReplay = nil }},
					{"source spelling", func(f *Func) { f.Instrs[1].Raw += " " }},
					{"replay arch", func(f *Func) {
						copy := *f.x86RawReplay
						copy.goarch = "arm64"
						f.x86RawReplay = &copy
					}},
					{"origin only", func(f *Func) { f.Instrs[ordinal].x86SourceRaw = nil }},
					{"origin and encoded", func(f *Func) { f.Instrs[ordinal].x86SourceRaw, f.Instrs[ordinal].x86Encoded = nil, false }},
					{"generation", func(f *Func) {
						f.Instrs[ordinal].x86ScalarFloatIntegerEVEX = !f.Instrs[ordinal].x86ScalarFloatIntegerEVEX
					}},
					{"operand", func(f *Func) { f.Instrs[ordinal].Args[0] = Operand{Kind: OpReg, Reg: "X0"} }},
					{"address mode", func(f *Func) {
						bits := 32
						if f.Instrs[ordinal].x86AddressBits == bits {
							bits = 64
						}
						f.Instrs[ordinal].x86AddressBits = bits
					}},
				} {
					t.Run(mutation.name, func(t *testing.T) {
						changed := fn
						changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
						mutation.edit(&changed)
						if reflect.DeepEqual(changed, fn) {
							t.Fatal("identity negative did not change the original snapshot", mutation.name)
						}
						if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("edited whole producer acquired raw conversion authority", err)
						}
					})
				}
				for _, variant := range []string{"missing-pointer", "numeric-pointer", "missing-vector", "missing-mxcsr", "missing-index", "opaque-index"} {
					if row.memory && variant == "missing-vector" || !row.memory && (variant == "missing-pointer" || variant == "numeric-pointer") ||
						(variant == "missing-index" || variant == "opaque-index") && !strings.Contains(row.operand, "CX") {
						continue
					}
					t.Run(variant, func(t *testing.T) {
						body, decl := x86ScalarIntegerRawSource(arch, "value", row, variant)
						for _, api := range []string{"text", "module", "Go"} {
							if _, err := x86ScalarFPBitViewAPI(t, body, decl, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("raw conversion invented missing native/numerical input", api, variant, err)
							}
						}
					})
				}
				for end := 1; end < len(row.code); end++ {
					prefix := Func{}
					for _, b := range row.code[:end] {
						prefix.Instrs = append(prefix.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(b)}}})
					}
					decoded, err := decodeX86RawDirectives(prefix, arch)
					if err == nil && len(decoded.Instrs) == 1 {
						if _, known, err := x86ScalarFloatIntegerProperties(decoded.Instrs[0], arch); known && err == nil {
							t.Fatal("truncated original conversion acquired a complete typed instruction", end)
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarFloatIntegerOriginalInitializedRawRuntimeObjects(t *testing.T) {
	data, err := os.ReadFile("amd64_raw_scalar_float_to_int_test.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "original.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	constants := make(map[string]string)
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "x86RawScalarFloatToIntegerNativeRuntime" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			value, ok := node.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 || value.Names[0].Name != "source" && value.Names[0].Name != "mainC" {
				return true
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("original initialized runtime lost its complete source/C literals")
			}
			constants[value.Names[0].Name], err = strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			return true
		})
	}
	for name, want := range map[string]string{"source": "1e0a8f59c481dfe0a3df7a72eaa4171724cd987c7e16a43ad79fa5b7b0e9584b", "mainC": "2ed5aa1e438e280875379ed2e027c02fcc826ea2bde65e69939df42d60739b34"} {
		if fmt.Sprintf("%x", sha256.Sum256([]byte(constants[name]))) != want {
			t.Fatal("complete original initialized runtime ASM/C changed", name)
		}
	}
	goAssemblerOracleOutput(t, "amd64", constants["source"], "", true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Original runtime's MOVQ/ABI0 contract is AMD64 only.
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, constants["source"], "func rawfloattointsemantics(input *float64,out *uint32)\n", "amd64", target.triple, api)
				if err != nil {
					t.Fatal("existing initialized raw runtime lost native continuation", err)
				}
				for _, input := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					compileLLVMToObject(t, llc, target.triple, "original-raw-scalar.ll", "original-raw-scalar.o", input)
				}
			})
		}
	}
}

func TestX86ScalarFloatIntegerRawSavedFlagsAndExactPostDomains(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, suffix := 8, "Q"
		if arch == "386" {
			word, suffix = 4, "L"
		}
		rows := x86ScalarIntegerRawRows(t, arch)
		type sample struct{ source, declaration, control string }
		var samples []sample
		var original strings.Builder
		for _, row := range rows {
			if row.operand != "X1" || row.name != "CVTSS2SL" && row.name != "VCVTSS2SI" && row.name != "VCVTSS2USIL" {
				continue
			}
			for _, control := range []string{"named", "raw", "missing-vector"} {
				name := fmt.Sprintf("saved%d", len(samples))
				body, decl := x86ScalarIntegerRawSource(arch, name, row, "")
				code := x86RawDisplacementDirectives(row.code)
				observed := "MOVL $3,DX\nCMPL DX,$3\nSTD\nPUSHF" + suffix + "\n" + code +
					"POP" + suffix + " DX\nANDL $0xcd5,DX\nCLD\n"
				body = strings.Replace(body, code, observed, 1)
				body = strings.Replace(body, fmt.Sprintf("MOVL AX,ret+%d(FP)", 2*word), fmt.Sprintf("MOVL DX,ret+%d(FP)", 2*word), 1)
				if control == "named" {
					body = strings.Replace(body, code, row.name+" X1,AX\n", 1)
				} else if control == "missing-vector" {
					body = strings.Replace(body, "PXOR X1,X1\n", "", 1)
				}
				samples = append(samples, sample{body, decl, control})
				original.WriteString(body)
			}
		}
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
		for index, item := range samples {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/saved-%d/%s", arch, index, api), func(t *testing.T) {
					_, err := x86ScalarFPBitViewAPI(t, item.source, item.declaration, arch, x86AddressMemoryTargets(arch)[0], api)
					if item.control == "missing-vector" && !errors.Is(err, ErrProbeNeedsContext) || item.control != "missing-vector" && err != nil {
						t.Fatal("saved FLAGS/DF changed or supplied a missing conversion input", item.control, err)
					}
				})
			}
		}
		for index, row := range rows {
			t.Run(fmt.Sprintf("%s/post-%d", arch, index), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code)
				for _, direction := range []x86ResultDirection{x86ResultDirectionUnknown, x86ResultDirectionForward, x86ResultDirectionBackward, x86ResultDirectionEither} {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: direction, valueStack: &x86ResultValueStack{id: true}}
					state.writeVector(1, 64, ^uint64(0), false)
					state.pointerGP[3], state.gp[1] = true, 0xff
					state.callerAddressGP[0], state.callerAddressGP[3], state.callerAddressGP[7] = true, true, true
					push := x86ScalarLaneInstruction(t, "PUSHF"+suffix)
					if accepted, known := x86ResultValueStackStep(push, &state, nil, 0, arch); !known || !accepted {
						t.Fatal("independent saved FLAGS prerequisite failed")
					}
					before := state.clone()
					if !x86ResultValueStackContinuation(ins, &state, arch) || x86ResultDirectionAfterSource(ins, direction, arch) != direction || x86PreservesNumericalSourceState(ins) {
						t.Error("raw conversion lost saved bytes/ID/DF or acquired an inert data role")
					}
					want := before.callerAddressGP
					want[0] = false // Every independent physical row writes AX, not BX/DI.
					got := x86ResultCallerAddressesAfterTransfer(ins, before.callerAddressGP, before.callerAddressGP, nil, arch)
					if got != want {
						t.Error("raw scalar output did not revoke exactly its GP caller-address destination", got, want)
					}
					accepted, known := x86ResultScalarFloatIntegerStepWithRead(ins, &state, nil, 0, arch, true)
					if !known || !accepted || state.flags != before.flags || state.direction != before.direction || !reflect.DeepEqual(state.valueStack, before.valueStack) {
						t.Error("raw conversion altered six status flags, DF, saved bytes or ID", known, accepted)
					}
				}
			})
		}
	}
}
