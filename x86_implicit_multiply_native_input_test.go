package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Independent of the production properties. The existing official-table root
// binds all eight rows, while explicit IMUL's two-/three-operand owners remain
// separate. B consumes AL, writes AX16 and does not write DX.
var x86ImplicitMultiplyNativeOracle = []struct {
	op     string
	bits   int
	signed bool
}{
	{"MULB", 8, false}, {"MULW", 16, false},
	{"MULL", 32, false}, {"MULQ", 64, false},
	{"IMULB", 8, true}, {"IMULW", 16, true},
	{"IMULL", 32, true}, {"IMULQ", 64, true},
}

func x86ImplicitMultiplyNativeSource(name, op, arch, address, result string, dead bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	base := "BX"
	if address == "(DX)" {
		base = "DX"
	}
	body := move + " $-1,AX\n" + move + " $0x4321,DX\n" +
		move + " p+0(FP)," + base + "\n" + move + " $3,CX\n" + op + " " + address + "\n"
	extent, declaration := word*2, fmt.Sprintf("func %s(p *byte) uintptr", name)
	if dead {
		extent, declaration = word, fmt.Sprintf("func %s(p *byte)", name)
	} else {
		body += fmt.Sprintf("%s %s,ret+%d(FP)\n", move, result, word)
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%sRET\n", name, extent, body), declaration
}

func TestX86ImplicitMultiplyNativeMemoryIndependentGoEncoding(t *testing.T) {
	if len(x86ImplicitMultiplyNativeOracle) != 8 {
		t.Fatal("complete eight-member implicit multiply directory changed")
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ImplicitMultiplyNativeOracle {
			if arch == "386" && row.bits == 64 {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row.op+" (BX)\nRET\n", "", false)
				continue
			}
			for _, address := range []string{"(BX)", "1(BX)(CX*2)", "(DX)"} {
				t.Run(arch+"/"+row.op+"/"+address, func(t *testing.T) {
					var expected []byte
					if row.bits == 16 {
						expected = append(expected, 0x66)
					} else if row.bits == 64 {
						expected = append(expected, 0x48)
					}
					opcode, extension := byte(0xf7), byte(4<<3)
					if row.bits == 8 {
						opcode = 0xf6
					}
					if row.signed {
						extension = 5 << 3
					}
					expected = append(expected, opcode)
					switch address {
					case "(BX)":
						expected = append(expected, extension|3)
					case "(DX)":
						expected = append(expected, extension|2)
					default:
						expected = append(expected, extension|0x44, 0x4b, 1)
					}
					expected = append(expected, 0xc3)
					actual := x86OrderingHintGoBytes(t, arch, "TEXT format(SB),4,$0-0\n"+row.op+" "+address+"\nRET\n")
					if !bytes.Equal(actual, expected) {
						t.Fatalf("complete original Go memory opcode differs: got=%x want=%x", actual, expected)
					}
				})
			}
		}
	}
}

func TestX86ImplicitMultiplyNativeMemoryInitializedThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := x86AddressMemoryTargets(arch)[0]
		for _, row := range x86ImplicitMultiplyNativeOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			source, declaration := x86ImplicitMultiplyNativeSource("Value", row.op, arch, "(BX)", "AX", false)
			control := strings.Replace(source, row.op+" (BX)", row.op+" CX", 1)
			// A real Go object precedes every public consumer. The same initialized
			// program with only its source changed to a numerical GP must pass first.
			x86LEAActualTargetGoObject(t, arch, triple, source)
			x86LEAActualTargetGoObject(t, arch, triple, control)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.op+"/"+api, func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, control, declaration, arch, triple, api); err != nil || ir == "" {
						t.Fatal("independently initialized register control failed before native memory", err)
					}
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil || ir == "" {
						t.Fatal("real pointer and accumulator lost their exact native multiply continuation", err)
					}
				})
			}
		}
	}
}

func TestX86ImplicitMultiplyNativeMemoryDeadAccessAndExactWidths(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := x86AddressMemoryTargets(arch)[0]
		for _, row := range x86ImplicitMultiplyNativeOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			source, declaration := x86ImplicitMultiplyNativeSource("Value", row.op, arch, "1(BX)(CX*2)", "AX", true)
			// Even an identically zero product with no result must still fault on
			// its exact source bytes. No claim of fault execution follows from IR.
			source = strings.Replace(source, "$-1,AX", "$0,AX", 1)
			x86LEAActualTargetGoObject(t, arch, triple, source)
			move := "MOVQ"
			if arch == "386" {
				move = "MOVL"
			}
			for _, missing := range []string{"", "accumulator", "pointer", "index"} {
				changed := source
				line := map[string]string{
					"accumulator": move + " $0,AX\n", "pointer": move + " p+0(FP),BX\n", "index": move + " $3,CX\n",
				}[missing]
				if missing != "" {
					changed = strings.Replace(changed, line, "", 1)
					if changed == source {
						t.Fatal("dead-input mutation did not change source", missing)
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+row.op+"/missing="+missing+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
						if missing != "" {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("dead product invented an accumulator, address or index", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("initialized dead native access rejected", err)
						}
						for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86ImplicitMultiplyNativeExactReads(t, input, row.bits, 1)
							if strings.Contains(input, "store volatile") {
								t.Fatal("dead product invented a memory write")
							}
						}
					})
				}
			}
		}
	}
}

func x86ImplicitMultiplyNativeExactReads(t *testing.T, ir string, bits, count int) {
	t.Helper()
	needle := fmt.Sprintf("load volatile i%d,", bits)
	if strings.Count(ir, needle) != count {
		t.Fatal("native multiplication lost its exact observable source width", bits, count)
	}
	alignment := regexp.MustCompile(`\balign 1(?:,|$)`)
	for _, line := range strings.Split(ir, "\n") {
		if strings.Contains(line, needle) && !alignment.MatchString(line) {
			t.Fatal("native multiplication asserted unobserved source alignment", line)
		}
	}
}

func TestX86ImplicitMultiplyNativeMemoryInputsStatusAndAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word := "MOVQ", goWordSize(arch)
		if arch == "386" {
			move = "MOVL"
		}
		triple := x86AddressMemoryTargets(arch)[0]
		for _, row := range x86ImplicitMultiplyNativeOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			source, declaration := x86ImplicitMultiplyNativeSource("Value", row.op, arch, "1(BX)(CX*2)", "AX", false)
			x86LEAActualTargetGoObject(t, arch, triple, source)
			for _, change := range []string{"accumulator", "pointer", "index", "numerical address", "pointer accumulator", "unknown upper accumulator", "CF", "OF", "ZF", "SF", "PF", "AF"} {
				changed := source
				valid := change == "CF" || change == "OF"
				switch change {
				case "accumulator":
					changed = strings.Replace(changed, move+" $-1,AX\n", "", 1)
				case "pointer":
					changed = strings.Replace(changed, move+" p+0(FP),BX\n", "", 1)
				case "index":
					changed = strings.Replace(changed, move+" $3,CX\n", "", 1)
				case "numerical address":
					changed = strings.Replace(changed, move+" p+0(FP),BX", move+" $4096,BX", 1)
				case "pointer accumulator":
					changed = strings.Replace(changed, move+" $-1,AX", move+" p+0(FP),AX", 1)
				case "unknown upper accumulator":
					changed = strings.Replace(changed, move+" $-1,AX", "MOVB $-1,AL", 1)
					// B consumes only AL, but returning uintptr still observes the
					// unwritten bytes above AX16. No zeroed implementation slot helps.
				default:
					predicate := map[string]string{"CF": "CS", "OF": "OS", "ZF": "EQ", "SF": "MI", "PF": "PS", "AF": ""}[change]
					observation := "LAHF\nMOVBLZX AH,AX\n"
					if predicate != "" {
						observation = "SET" + predicate + " CX\nMOVBLZX CX,AX\n"
					}
					changed = strings.Replace(changed, row.op+" 1(BX)(CX*2)", "CMPL AX,AX\n"+row.op+" 1(BX)(CX*2)", 1)
					changed = strings.Replace(changed, fmt.Sprintf("%s AX,ret+%d(FP)", move, word), observation+fmt.Sprintf("%s AX,ret+%d(FP)", move, word), 1)
				}
				if changed == source {
					t.Fatal("input/status negative did not change its original program", change)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+row.op+"/"+change+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
						if valid {
							if err != nil || ir == "" {
								t.Fatal("multiply lost its only defined status outputs", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("multiply invented input bytes, address authority or undefined FLAGS", err)
						}
					})
				}
			}

			_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration,
				strings.SplitN(strings.TrimSuffix(source, "\n"), "\n", 2)[1])
			original := file.Funcs[0]
			ordinal := -1
			for index, ins := range original.Instrs {
				if string(ins.Op) == row.op {
					ordinal = index
					state := x86ResultState{}
					accumulator, _, _ := x86ResultGP(AX, int64(word), arch)
					index, _, _ := x86ResultGP(CX, int64(word), arch)
					pointer, _, _ := x86ResultGP(BX, int64(word), arch)
					state.gp[accumulator], state.gp[index], state.pointerGP[pointer] = 255, 255, true
					before := state.clone()
					if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("standalone query borrowed a paired native source or mutated its rejected state")
					}
				}
			}
			if ordinal < 0 {
				t.Fatal("original complete program lost its source ordinal")
			}
			for _, change := range []string{"encoded", "raw", "address size", "segment", "raw entry"} {
				t.Run(arch+"/"+row.op+"/origin/"+change, func(t *testing.T) {
					changed := original
					changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
					ins := &changed.Instrs[ordinal]
					switch change {
					case "encoded":
						ins.x86Encoded = true
					case "raw":
						ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: append([]Operand(nil), ins.Args...)}
					case "address size":
						ins.x86AddressBits = 16
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "raw entry":
						changed.X86RawText = []byte{0xc3}
					}
					consumer := amd64Ctx{fpScalarSource: changed, sig: sig, fpSourceSig: sig, goarch: arch, targetTriple: triple}
					if err := consumer.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("paired multiplication borrowed another raw/physical entry or native source mode", err)
					}
				})
			}
		}
	}
}
