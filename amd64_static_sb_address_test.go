package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
)

// These are independent complete legacy mnemonic families, not a projection
// of the implementation registry. All share Go's NAME_STATIC memory role.
func x86StaticSBReadBodies(arch string) map[string]string {
	bodies := x86ScalarResultDataReadBodies(arch)
	for _, family := range []string{
		"ANDPS ANDPD ANDNPS ANDNPD ORPS ORPD XORPS XORPD PAND PANDN POR PXOR",
		"PAVGB PAVGW",
		"PMULLW PMULHW PMULHUW PMULHRSW",
		"PMULLD PMULDQ PMULULQ",
		"PMADDWL PMADDUBSW",
		"PSADBW",
		"PACKSSLW PACKSSWB PACKUSDW PACKUSWB",
		"PADDB PADDW PADDL PADDQ",
		"PSUBB PSUBW PSUBL PSUBQ PSUBSB PSUBSW PSUBUSB PSUBUSW",
		"PCMPEQB PCMPEQW PCMPEQL PCMPEQQ PCMPGTB PCMPGTW PCMPGTL PCMPGTQ",
		"ADDPS ADDPD SUBPS SUBPD MULPS MULPD DIVPS DIVPD",
		"PHADDW PHADDD PHADDSW PHSUBW PHSUBD PHSUBSW",
		"AESENC AESENCLAST AESDEC AESDECLAST AESIMC",
		"CVTPL2PS CVTPL2PD",
	} {
		for _, name := range strings.Fields(family) {
			bodies[name] = "PXOR X1,X1\n" + name + " table<>+16(SB),X1\n"
		}
	}
	bodies["MPSADBW"] = "PXOR X1,X1\nMPSADBW $5,table<>+16(SB),X1\n"
	bodies["AESKEYGENASSIST"] = "AESKEYGENASSIST $5,table<>+16(SB),X1\n"
	for _, name := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
		bodies[name] = name + " $5,table<>+16(SB),X1\n"
	}
	for _, name := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD"} {
		bodies[name] = "PXOR X1,X1\n" + name + " table<>+16(SB),X1,$5\n"
	}
	for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
		widths := []string{"W", "L"}
		if arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			name := "CMOV" + width + condition
			bodies[name] = "MOVL $0,AX\nCMPL AX,AX\n" + name + " table<>+16(SB),AX\n"
		}
	}
	return bodies
}

func x86StaticSBBodyNames(bodies map[string]string) []string {
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestX86StaticSBAnnotationActualGoRoles(t *testing.T) {
	bodies := x86StaticSBReadBodies("386")
	for _, offset := range []string{"0", "16", "(2*8)", "-16"} {
		var plain, annotated strings.Builder
		plain.WriteString("TEXT roles(SB),4,$0-0\n")
		annotated.WriteString("TEXT roles(SB),4,$0-0\n")
		for _, base := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"} {
			for _, name := range x86StaticSBBodyNames(bodies) {
				body := strings.ReplaceAll(bodies[name], "+16(SB)", "+"+offset+"(SB)")
				plain.WriteString(body)
				annotated.WriteString(strings.ReplaceAll(body, "(SB)", "(SB)("+base+")"))
			}
		}
		plain.WriteString("RET\n")
		annotated.WriteString("RET\n")
		left := x86PackedShiftActualGoBytes(t, "386", plain.String())
		right := x86PackedShiftActualGoBytes(t, "386", annotated.String())
		if !bytes.Equal(left, right) {
			t.Fatalf("Go NAME_STATIC base annotation changed encoded instructions at offset %s", offset)
		}
	}
	for _, base := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"} {
		for _, scale := range []int{1, 2, 4, 8} {
			source := func(operand string) string {
				return "TEXT roles(SB),4,$0-0\nMOVOU " + operand + ",X1\nRET\n"
			}
			index := fmt.Sprintf("(CX*%d)", scale)
			plain := x86PackedShiftActualGoBytes(t, "386", source("table<>+16(SB)"+index))
			annotated := x86PackedShiftActualGoBytes(t, "386", source("table<>+16(SB)("+base+")"+index))
			if !bytes.Equal(plain, annotated) {
				t.Fatalf("base %s displaced actual index %s", base, index)
			}
		}
		goAssemblerOracleOutput(t, "amd64", "TEXT roles(SB),4,$0-0\nMOVOU table<>(SB)("+base+"),X1\nRET\n", "", false)
	}
}

func TestX86StaticSBAnnotationLoweredResults(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		bodies := x86ScalarResultDataReadBodies(target.arch)
		for _, base := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"} {
			if target.arch != "386" && base != "AX" {
				continue // AMD64's unannotated controls still cover every family.
			}
			t.Run(target.triple+"/"+base, func(t *testing.T) {
				var source, declarations strings.Builder
				source.WriteString(x86ScalarResultDataTable)
				for _, name := range x86StaticSBBodyNames(bodies) {
					body := bodies[name]
					if target.arch == "386" {
						body = strings.ReplaceAll(body, "(SB)", "(SB)("+base+")")
					}
					fmt.Fprintf(&source, "TEXT ·view%s(SB),4,$0-4\n%sPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", name, body)
					fmt.Fprintf(&declarations, "func view%s() uint32\n", name)
				}
				goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Errorf("%s: bounded static annotation lost numeric result/native role: %v", api, err)
						continue
					}
					compileLLVMToObject(t, llc, target.triple, "static-sb.ll", "static-sb.o", ir)
				}
			})
		}
	}
}

func TestX86StaticSBAnnotationNativeFamilyMatrix(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		bodies := x86StaticSBReadBodies(target.arch)
		bases := []string{""}
		if target.arch == "386" {
			bases = append(bases, "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI")
		}
		for _, api := range []string{"text", "module", "Go"} {
			nativeCount := 0
			var annotatedIR string
			for _, base := range bases {
				t.Run(target.triple+"/"+api+"/"+base, func(t *testing.T) {
					var source, declarations strings.Builder
					source.WriteString(x86ScalarResultDataTable)
					for _, name := range x86StaticSBBodyNames(bodies) {
						body := bodies[name]
						if base != "" {
							body = strings.ReplaceAll(body, "(SB)", "(SB)("+base+")")
						}
						fmt.Fprintf(&source, "TEXT ·view%s(SB),4,$0-0\n%sRET\n", name, body)
						fmt.Fprintf(&declarations, "func view%s()\n", name)
					}
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("ignored static base changed native-emitter selection:", err)
					}
					count := strings.Count(ir, "asm sideeffect")
					if base == "" {
						nativeCount = count
					}
					// The three APIs allocate distinct temporary module paths.
					// Exclude only their two nonsemantic filename records.
					var comparable strings.Builder
					for _, line := range strings.Split(ir, "\n") {
						if !strings.HasPrefix(line, "; ModuleID = ") && !strings.HasPrefix(line, "source_filename = ") {
							comparable.WriteString(line)
							comparable.WriteByte('\n')
						}
					}
					if base == "AX" {
						annotatedIR = comparable.String()
					}
					if count == 0 || count != nativeCount {
						t.Fatalf("native opcode count changed: %d, want %d", count, nativeCount)
					}
					// OpMem has a pointer/integer bridge unlike plain OpSym.
					// Changing only the ignored Reg must emit identical IR.
					if base != "" && comparable.String() != annotatedIR {
						original, changed := strings.Split(annotatedIR, "\n"), strings.Split(comparable.String(), "\n")
						for line := 0; line < len(original) && line < len(changed); line++ {
							if original[line] != changed[line] {
								t.Logf("first difference at %d: %q / %q", line, original[line], changed[line])
								break
							}
						}
						t.Fatal("ignored base annotation changed emitted LLVM semantics")
					}
					compileLLVMToObject(t, llc, target.triple, "static-native.ll", "static-native.o", ir)
				})
			}
		}
	}
}

func TestX86StaticSBAnnotationNativeSADFeatures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, name := range []string{"PSADBW", "MPSADBW"} {
		t.Run(name, func(t *testing.T) {
			body := x86StaticSBReadBodies("386")[name]
			source := x86ScalarResultDataTable + "TEXT ·view(SB),4,$0-0\n" + body + "RET\n"
			goAssemblerOracleOutput(t, "386", source, "", true)
			ir, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", "386", "i386-unknown-linux-gnu", "text")
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "sad.ll", "sad.o", ir)
		})
	}
}

func TestX86StaticSBAnnotationResultBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "i386-unknown-linux-gnu"
		if arch == "amd64" {
			triple = "x86_64-unknown-linux-gnu"
		}
		for name, body := range x86ScalarResultDataReadBodies(arch) {
			for _, address := range []string{
				"table<>-1(SB)(AX)", "table<>+32(SB)(AX)",
				"table<>+16(SB)(AX*1)", "table<>+16(SB)(SP)(CX*2)",
				"table<>+16(SB)(BP)(DX*4)", "external(SB)(DI)",
			} {
				t.Run(arch+"/"+name+"/"+address, func(t *testing.T) {
					source := x86ScalarResultDataTable + "TEXT ·view(SB),4,$0-4\n" +
						strings.ReplaceAll(body, "table<>+16(SB)", address) +
						"PEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
					for _, api := range []string{"text", "module", "Go"} {
						if _, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", arch, triple, api); err == nil {
							t.Fatalf("%s accepted an unbound static numerical input", api)
						}
					}
				})
			}
		}
	}
	for _, base := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"} {
		for _, offset := range []string{"0", "16", "(2*8)", "17"} {
			address := "table<>+" + offset + "(SB)(" + base + ")"
			source := x86ScalarResultDataTable + "TEXT ·view(SB),4,$0-4\nMOVOU " + address +
				",X1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "386", "i386-unknown-linux-gnu", api)
				if offset == "17" && !errors.Is(err, ErrProbeNeedsContext) || offset != "17" && err != nil {
					t.Fatalf("%s %s complete extent: %v", api, address, err)
				}
			}
		}
	}
}

func TestX86StaticSBAnnotationRawAddressBoundaries(t *testing.T) {
	read, err := parseOperandForArch(ArchAMD64, "table<>+16(SB)(SP)")
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, x86ScalarResultDataTable+"TEXT view(SB),4,$0-0\nMOVOU table<>+16(SB)(SP),X1\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	state := x86ResultState{loweredStaticReads: x86LoweredScalarDataReads(file, resolve, nil, "386")}
	for index := range state.gp {
		state.gp[index] = 0xff // Known indexes still cannot borrow a static extent.
	}
	if !x86ResultRead(read, 16, &state, nil, "386") {
		t.Fatal("valid original static base annotation did not retain complete extent")
	}
	for name, change := range map[string]func(*MemRef){
		"separate offset": func(m *MemRef) { m.Off = 1 },
		"negative offset": func(m *MemRef) { m.Off = -17 },
		"offset overflow": func(m *MemRef) { m.Off = math.MaxInt64 },
		"raw offset":      func(m *MemRef) { m.OffRaw = "unknown" },
		"segment":         func(m *MemRef) { m.Segment = FS },
		"TLS":             func(m *MemRef) { m.Base = TLS },
		"unknown base":    func(m *MemRef) { m.Base = "UNKNOWN" },
		"dynamic index":   func(m *MemRef) { m.Index, m.Scale = AX, 1 },
		"unbound scale":   func(m *MemRef) { m.Scale = 1 },
		"index extension": func(m *MemRef) { m.IndexExt = "SXTW" },
		"FP role":         func(m *MemRef) { m.Sym = "table<>+16(FP)" },
		"AUTO role":       func(m *MemRef) { m.Sym = "table<>+16(SP)" },
		"address value":   func(m *MemRef) { m.Sym = "$table<>+16(SB)" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := read
			change(&mutated.Mem)
			if x86ResultRead(mutated, 16, &state, nil, "386") {
				t.Fatal("mutated operand borrowed another effective address's DATA bytes")
			}
		})
	}
	if x86ResultRead(read, 16, &state, nil, "amd64") {
		t.Fatal("386 base annotation became valid AMD64 RIP-relative memory")
	}
	dynamic := Operand{Kind: OpMem, Mem: MemRef{Sym: "table<>(SB)", Base: SP, Index: BP, Scale: 1}}
	if !x86OrdinaryNativeMemoryOperand(dynamic, "386") || x86ResultRead(dynamic, 16, &state, nil, "386") {
		t.Fatal("ordinary mode32 BP index was either classified as a frame or borrowed an unindexed static extent")
	}
	dynamic.Mem.Index = SP
	if x86OrdinaryNativeMemoryOperand(dynamic, "386") {
		t.Fatal("an actual SP index borrowed permission from an ignored SP annotation")
	}
	for _, copy := range []x86ResultState{state.clone(), state.intersect(state)} {
		if x86ResultRead(read, 16, &copy, nil, "386") {
			t.Fatal("conditional static bytes escaped the current lowering transfer")
		}
	}
}

func TestX86StaticSBAnnotationDoesNotGrantSourceProof(t *testing.T) {
	for _, base := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"} {
		body := "MOVOU table<>+16(SB)(" + base + "),X1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+0(FP)\nRET"
		_, file, sig, _ := x86ResultInitializationFixture(t, "386", "func Value() uint32", body)
		for _, check := range []func(Func, FuncSig, string) error{
			CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
		} {
			if err := check(file.Funcs[0], sig, "386"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s standalone query borrowed the private DATA directory: %v", base, err)
			}
		}
		data := strings.Replace(x86ScalarResultDataTable,
			"DATA table<>+16(SB)/8,$0xfedcba9876543210", "DATA table<>+16(SB)/4,$external(SB)", 1)
		source := data + "TEXT ·Value(SB),4,$0-4\n" + body + "\n"
		goAssemblerOracleOutput(t, "386", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32\n", "386", "i386-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s/%s treated pointer relocations as numeric DATA: %v", base, api, err)
			}
		}
	}
}
