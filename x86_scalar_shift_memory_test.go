package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type x86ShiftMemoryOracle struct {
	text        string
	bits        int
	readOnly    bool
	valueChoice bool // W double shifts include ISA-unspecified low16 results.
}

// One memory witness per independently checked Go encoder row. This directory
// does not use the production grammar or its numerical effect descriptor.
func x86ScalarShiftMemoryRows(arch string) []x86ShiftMemoryOracle {
	widths := []string{"B", "W", "L", "Q"}
	if arch == "386" {
		widths = widths[:3]
	}
	var rows []x86ShiftMemoryOracle
	bits := map[string]int{"B": 8, "W": 16, "L": 32, "Q": 64}
	for _, stem := range x86ScalarShiftTestStems {
		for _, width := range widths {
			counts := []string{"$1", "$0", "CX"}
			if width != "B" {
				counts = append(counts, "CL")
			}
			for _, count := range counts {
				rows = append(rows, x86ShiftMemoryOracle{stem + width + " " + count + ",1(DI)", bits[width], false, false})
			}
		}
	}
	for _, stem := range []string{"SHL", "SHR"} {
		for _, width := range widths[1:] {
			for _, count := range []string{"$1", "CL", "CX"} {
				rows = append(rows, x86ShiftMemoryOracle{stem + width + " " + count + ",AX,1(DI)",
					bits[width], false, width == "W" && count != "$1"})
			}
		}
	}
	for _, stem := range []string{"SARX", "SHLX", "SHRX", "RORX"} {
		for _, width := range []string{"L", "Q"} {
			physical := bits[width]
			if arch == "386" {
				physical = 32 // VEX.W is ignored, including the memory width.
			}
			counts := []string{"CX"}
			if stem == "RORX" {
				counts = []string{"$255", "$-128"}
			}
			for _, count := range counts {
				rows = append(rows, x86ShiftMemoryOracle{stem + width + " " + count + ",1(DI),AX", physical, true, false})
			}
		}
	}
	return rows
}

func x86ScalarShiftMemoryFixture(arch, instruction string, result bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	frame, tail := word*3, ""
	declaration := "func Value(p *[32]byte,value,count uintptr)"
	if result {
		frame += 4
		declaration += " uint32"
		tail = fmt.Sprintf("MOVL AX,ret+%d(FP)\n", word*3)
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),DI\n%s value+%d(FP),AX\n%s count+%d(FP),CX\nCLC\n%s\n%sRET\n",
		frame, move, move, word, move, word*2, instruction, tail), declaration
}

func TestX86ScalarShiftMemoryCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		rows := x86ScalarShiftMemoryRows(target.arch)
		want := 148
		if target.arch == "386" {
			want = 110
		}
		if len(rows) != want {
			t.Fatal("incomplete independent memory-form denominator", target.arch, len(rows), want)
		}
		for first := 0; first < len(rows); first += 80 {
			last := first + 80
			if last > len(rows) {
				last = len(rows)
			}
			t.Run(fmt.Sprintf("%s/batch-%d", target.triple, first/80), func(t *testing.T) {
				var source, declarations strings.Builder
				for index, row := range rows[first:last] {
					assembly, declaration := x86ScalarShiftMemoryFixture(target.arch, row.text, true)
					name := fmt.Sprint("Shift", first+index)
					source.WriteString(strings.ReplaceAll(assembly, "Value", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Error("complete initialized memory family lacks its numerical continuation", api, err)
						continue
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarShiftMemoryEmitterRetainsExactAccess(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ScalarShiftMemoryRows(arch) {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.text)
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				ctx.blocks = []amd64Block{{instrs: []Instr{ins}}}
				if _, err := ctx.lowerInstr(0, 0, ins, nil, nil); err != nil {
					t.Fatal("valid format did not reach its actual emitter", err)
				}
				stores := 1
				if row.readOnly {
					stores = 0
				}
				ir := output.String()
				if strings.Count(ir, fmt.Sprintf("load volatile i%d,", row.bits)) != 1 ||
					strings.Count(ir, fmt.Sprintf("store volatile i%d ", row.bits)) != stores ||
					strings.Contains(ir, "atomicrmw ") {
					t.Error("memory shift lost an exact-width observable access, including count zero")
				}
			})
		}
	}
}

func TestX86ScalarShiftMemoryVoidRequiresInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, word, triple := "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		for _, instruction := range []string{"SHLL CL,AX,1(DI)", "RCLL CX,1(DI)", "SARXL CX,1(DI),AX", "RORXL $0,1(DI),AX"} {
			source, declaration := x86ScalarShiftMemoryFixture(arch, instruction, false)
			variants := map[string]string{
				"complete":          source,
				"missing-address":   strings.Replace(source, move+" p+0(FP),DI\n", "", 1),
				"numerical-address": strings.Replace(source, move+" p+0(FP),DI\n", "MOVL $1,DI\n", 1),
			}
			if !strings.HasPrefix(instruction, "RORX") {
				variants["missing-count"] = strings.Replace(source, fmt.Sprintf("%s count+%d(FP),CX\n", move, word*2), "", 1)
			}
			if strings.HasPrefix(instruction, "SHLL") {
				variants["missing-value"] = strings.Replace(source, fmt.Sprintf("%s value+%d(FP),AX\n", move, word), "", 1)
			}
			if strings.HasPrefix(instruction, "RCL") {
				variants["missing-carry"] = strings.Replace(source, "CLC\n", "", 1)
			}
			for name, assembly := range variants {
				t.Run(arch+"/"+instruction+"/"+name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, arch, triple, assembly)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, assembly, declaration, arch, triple, api)
						if name == "complete" {
							if err != nil || ir == "" {
								t.Error("initialized Void memory shift lost its paired effect", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("Void memory shift invented a missing numerical/address input", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86DoubleShiftOriginalConformanceObjects(t *testing.T) {
	original, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, width := range []int{32, 64} {
		name := fmt.Sprint("doubleShift", width)
		start := strings.Index(string(original), "TEXT ·"+name+"(")
		if start < 0 {
			t.Fatal("original discovering function disappeared", name)
		}
		body := string(original[start:])
		if next := strings.Index(body, "\nTEXT "); next >= 0 {
			body = body[:next+1]
		}
		declaration := fmt.Sprintf("func %s(out *[8]uint%d, src, dst, amount uint%d)", name, width, width)
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(name+"/"+triple, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+body)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, body, declaration, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Error("unchanged discovering memory program failed", api, err)
						continue
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarShiftMemoryContinuationBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarShiftMemoryRows(arch) {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.text)
				state := x86ResultState{flags: x86ByteFlagsAll}
				base, _, _ := x86ResultGP(DI, 4, arch)
				value, _, _ := x86ResultGP(AX, 4, arch)
				count, _, _ := x86ResultGP(CX, 4, arch)
				state.pointerGP[base] = true
				state.gp[value], state.gp[count] = 0xff, 0xff
				for _, consumer := range x86ResultGPSIMDConsumers {
					standalone := state.clone()
					if consumer.step(ins, &standalone, nil, 0, arch) {
						t.Fatal("standalone numerical observer borrowed a native continuation")
					}
				}
				complete := state.clone()
				accepted, known := x86LoweredScalarShiftMemory(ins, &complete, nil, 0, arch)
				if !known || !accepted {
					t.Fatal("paired initialized shift lost its finite ISA outcome", accepted, known)
				}
				if complete.gp != state.gp || complete.pointerGP != state.pointerGP {
					t.Fatal("native shift created unrelated GP or pointer facts")
				}
				for _, mutation := range []string{"missing-address", "numerical-address", "pointer-count", "missing-count",
					"encoded", "raw", "return", "address-size", "unbound-address", "segment"} {
					changed, rejected := ins, state.clone()
					switch mutation {
					case "missing-address":
						rejected.pointerGP[base] = false
					case "numerical-address":
						rejected.pointerGP[base], rejected.gp[base] = false, 0xff
					case "pointer-count", "missing-count":
						if ins.Args[0].Kind != OpReg {
							continue
						}
						rejected.gp[count] = 0
						rejected.pointerGP[count] = mutation == "pointer-count"
					case "encoded":
						changed.x86Encoded = true
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					case "address-size":
						changed.x86AddressBits = 32
					case "unbound-address":
						changed.x86UnboundAddressOverride = true
					case "segment":
						changed.x86SegmentPrefix = 0x64
					}
					before := rejected.clone()
					if accepted, _ := x86LoweredScalarShiftMemory(changed, &rejected, nil, 0, arch); accepted || !reflect.DeepEqual(rejected, before) {
						t.Fatal("missing source or foreign role acquired effects", mutation)
					}
				}
			})
		}
	}
}
