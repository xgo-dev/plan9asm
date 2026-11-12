package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Independent of the implementation's family map. Go uses one complete
// yml_rl row for LAR/LSL and one ydivl row for VERR/VERW. All selector reads
// consume exactly 16 bits, regardless of the destination/register spelling.
var x86SegmentQueryOracle = []struct {
	op, table, prefix, opcode string
	bytes                     int64
}{
	{"LARW", "yml_rl", "Pq", "0x02", 2},
	{"LARL", "yml_rl", "Pm", "0x02", 4},
	{"LARQ", "yml_rl", "Pw", "0x0f, 0x02", 8},
	{"LSLW", "yml_rl", "Pq", "0x03", 2},
	{"LSLL", "yml_rl", "Pm", "0x03", 4},
	{"LSLQ", "yml_rl", "Pw", "0x0f, 0x03", 8},
	{"VERR", "ydivl", "Pm", "0x00, 04", 0},
	{"VERW", "ydivl", "Pm", "0x00, 05", 0},
}

func x86SegmentQueryOracleInstruction(t *testing.T, op string, destination bool) Instr {
	t.Helper()
	text := op + " AX"
	if destination {
		text += ",CX"
	}
	file, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-0\n"+text+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestX86SegmentQueryCompleteGoRowsAndTypedEffects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, grammar := range []string{
		"var yml_rl = []ytab{\n\t{Zm_r, 1, argList{Yml, Yrl}},\n}",
		"var ydivl = []ytab{\n\t{Zm_o, 2, argList{Yml}},\n}",
	} {
		if !strings.Contains(string(data), grammar) {
			t.Fatal("complete original selector encoder row changed", grammar)
		}
	}
	for _, row := range x86SegmentQueryOracle {
		want := fmt.Sprintf("{A%s, %s, %s, opBytes{%s}}", row.op, row.table, row.prefix, row.opcode)
		if !strings.Contains(string(data), want) {
			t.Fatal("independent Go selector opcode attributes changed", want)
		}
		for _, arch := range []string{"amd64", "386"} {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86SegmentQueryOracleInstruction(t, row.op, row.bytes != 0)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if arch == "386" && row.bytes == 8 {
					if !known || err == nil {
						t.Fatal("Go-rejected mode32 qword acquired a numerical effect", known, err)
					}
					return
				}
				wantOperands := 1
				if row.bytes != 0 {
					wantOperands++
				}
				if !known || err != nil || len(effect.operands) != wantOperands ||
					!effect.requiresResultProof || effect.dynamicMemory || effect.flagsRead != 0 ||
					effect.flagsDefined != x86ByteFlagZF || effect.flagsKilled != 0 {
					t.Fatal("missing complete selector/old-destination/ZF effect", effect, known, err)
				}
				selector := effect.operands[0]
				if selector.index != 0 || selector.operand.Reg != AX || selector.width != 2 || !selector.read || selector.write {
					t.Fatal("selector is not an exact read-only low word", selector)
				}
				if row.bytes != 0 {
					destination := effect.operands[1]
					if destination.index != 1 || destination.operand.Reg != CX || destination.width != row.bytes ||
						!destination.read || !destination.write {
						t.Fatal("failed query did not retain its complete old destination", destination)
					}
				}
			})
		}
	}
}

func TestX86SegmentQuerySelectorOldDestinationAndFlagsState(t *testing.T) {
	// Intel SDM 093 Vol.2A LSL 3-575 explicitly preserves CF/OF/SF/AF/PF;
	// Intel XED's four family records modify ZF only. The old STC/VERR/SETCS
	// fixture is legitimate and must not be relabeled as undefined-FLAGS Context.
	// https://cdrdv2.intel.com/v1/dl/getContent/671199
	// https://github.com/intelxed/xed/blob/main/datafiles/xed-isa.txt
	for _, row := range x86SegmentQueryOracle {
		for _, arch := range []string{"amd64", "386"} {
			if arch == "386" && row.bytes == 8 {
				continue // Independent Go mode rejection is checked above.
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86SegmentQueryOracleInstruction(t, row.op, row.bytes != 0)
				oldMask := uint8(1<<uint(row.bytes) - 1)
				for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagsAll &^ x86ByteFlagZF, x86ByteFlagsAll} {
					state := x86ResultState{flags: flags}
					state.gp[0], state.gp[1], state.gp[2] = 3, oldMask, 0x55
					if !x86ResultTransfer(ins, &state, nil, 0, arch) {
						t.Fatal("complete low selector and old destination were rejected", flags)
					}
					if state.flags != flags|x86ByteFlagZF || state.gp[0] != 3 ||
						state.gp[1] != oldMask || state.gp[2] != 0x55 {
						t.Fatal("query invented FLAGS/input bytes or changed unrelated storage", state.flags, state.gp)
					}
				}
				for missing := int64(0); missing < 2+row.bytes; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.gp[1] = 3, oldMask
					if missing < 2 {
						state.gp[0] &^= 1 << uint(missing)
					} else {
						state.gp[1] &^= 1 << uint(missing-2)
					}
					if x86ResultTransfer(ins, &state, nil, 0, arch) {
						t.Fatal("missing selector/failed-query merge byte was invented", missing)
					}
				}
			})
		}
	}
}

func TestX86SegmentQueryInitializedPublicAndMissingInputs(t *testing.T) {
	for _, row := range x86SegmentQueryOracle {
		for _, arch := range []string{"amd64", "386"} {
			if arch == "386" && row.bytes == 8 {
				continue
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.op+"/"+api, func(t *testing.T) {
					move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
					if arch == "386" {
						move, triple = "MOVL", "i386-unknown-linux-gnu"
					}
					query := row.op + " AX"
					if row.bytes != 0 {
						query += ",CX"
					}
					selector := "MOVW $0,AX\n"
					old := move + " $0x12345678,CX\n"
					body := "STC\n" + query + "\nSETEQ DL\nSETCS BL\nMOVBLZX DL,DX\n" +
						"MOVBLZX BL,BX\nSHLL $1,BX\nORL BX,DX\nMOVL DX,ret+0(FP)\nRET\n"
					source := "TEXT ·Value(SB),4,$0-4\n" + selector + old + body
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", arch, triple, api); err != nil || ir == "" {
						t.Fatal("initialized selector and preserved CF/ZF lost their public result", err)
					}
					for _, missing := range []string{selector, old} {
						if missing == old && row.bytes == 0 {
							continue // VERR/VERW do not have an old result register.
						}
						changed := strings.Replace(source, missing, "", 1)
						ir, err := x86ScalarFPBitViewAPI(t, changed, "func Value() uint32", arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("missing native query input borrowed an implementation slot", missing, err)
						}
					}
				})
			}
		}
	}
}
