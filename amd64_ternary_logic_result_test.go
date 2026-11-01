package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86TernaryResultWholeCFGAndUnknownInputs(t *testing.T) {
	for _, fixture := range []struct {
		row  string
		pass bool
	}{
		{"VPTERNLOGD $0,Z0,Z1,Z2", true},
		{"VPTERNLOGQ $255,Z0,Z1,Z2", true},
		{"VPTERNLOGD $60,Z0,Z2,Z2", true},   // A XOR B, A=B.
		{"VPTERNLOGQ $90,Z2,Z1,Z2", true},   // A XOR C, A=C.
		{"VPTERNLOGD $102,Z0,Z0,Z2", true},  // B XOR C, B=C.
		{"VPTERNLOGQ $150,Z2,Z2,Z2", false}, // A XOR A XOR A remains A.
		{"VPTERNLOGD $150,Z0,Z1,Z2", false},
	} {
		source := "TEXT ·view(SB),4,$0-4\n" + fixture.row + "\nPEXTRD $0,X2,AX\nMOVL AX,ret+0(FP)\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			_, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
			if fixture.pass && err != nil || !fixture.pass && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal(fixture.row, api, err)
			}
		}
	}
	for _, other := range []string{"VPTERNLOGD $255,Z0,Z1,Z2", "NOP"} {
		source := `TEXT ·view(SB),4,$0-12
MOVL a+0(FP),AX
CMPL AX,$0
JE other
VPTERNLOGD $255,Z0,Z1,Z2
JMP joined
other:
` + other + `
joined:
VPTERNLOGQ $240,Z0,Z1,Z2
PEXTRD $0,X2,AX
MOVL AX,ret+8(FP)
RET
`
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			_, err := x86ScalarFPBitViewAPI(t, source, "func view(a uint32) uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
			if other == "NOP" && !errors.Is(err, ErrProbeNeedsContext) || other != "NOP" && err != nil {
				t.Fatal("CFG joined an unknown predecessor as initialized", api, err)
			}
		}
	}
	const deadRead = `TEXT ·view(SB),4,$0-4
JMP finish
VPTERNLOGD $0,(AX),Z1,Z2
finish:
MOVL $1,AX
MOVL AX,X2
PEXTRD $0,X2,AX
MOVL AX,ret+0(FP)
RET
`
	goAssemblerOracleOutput(t, "amd64", deadRead, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		if _, err := x86ScalarFPBitViewAPI(t, deadRead, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("constant truth table bypassed dead unbound memory", api, err)
		}
	}
}

// This oracle enumerates physical register assignments independently of the
// production Boolean normal form. Missing bytes may have either bit value.
func ternaryResultBitKnown(immediate int, registers [3]int, unknown int) bool {
	for assignment := 0; assignment < 8; assignment++ {
		truth := func(bits int) int {
			index := 0
			for _, register := range registers {
				index = index*2 + (bits>>uint(register))&1
			}
			return immediate >> uint(index) & 1
		}
		if truth(assignment) != truth(assignment^(1<<uint(unknown))) {
			return false
		}
	}
	return true
}

func TestX86TernaryResultCompleteBooleanDomain(t *testing.T) {
	partitions := [][3]int{{2, 1, 0}, {2, 2, 0}, {2, 1, 2}, {2, 1, 1}, {2, 2, 2}}
	for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for width, bank := range map[int]string{16: "X", 32: "Y", 64: "Z"} {
			for _, registers := range partitions {
				for immediate := 0; immediate < 256; immediate++ {
					for _, mode := range []string{"", "merge", "zero"} {
						suffix, mask := "", ""
						if mode != "" {
							mask = ",K3"
						}
						if mode == "zero" {
							suffix = ".Z"
						}
						row := fmt.Sprintf("%s%s $%d,%s%d,%s%d%s,%s%d", op, suffix, immediate, bank, registers[2], bank, registers[1], mask, bank, registers[0])
						ins := x86ScalarLaneInstruction(t, row)
						for missing := 0; missing < 3; missing++ {
							state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{3: true}}
							for register := 0; register < 3; register++ {
								state.writeVector(register, 64, ^uint64(0), false)
							}
							// Every other byte is unknown; verify byte-local effects.
							state.writeVector(missing, 64, 0x5555555555555555, false)
							before := state.clone()
							if !x86ResultTransfer(ins, &state, nil, 0, "amd64") {
								t.Fatalf("missing complete typed effect: %s", row)
							}
							known := ternaryResultBitKnown(immediate, registers, missing)
							known = known && (mode != "merge" || missing != registers[0])
							want := ^uint64(0)
							if !known {
								want &^= 0xaaaaaaaaaaaaaaaa & x86CallerVectorByteMask(int64(width))
							}
							if state.vectorBytes(registers[0]) != want || state.flags != before.flags {
								t.Fatalf("%s unknown bank%d: got %016x, want %016x", row, missing, state.vectorBytes(registers[0]), want)
							}
							for register := 0; register < 3; register++ {
								if register != registers[0] && state.vectorBytes(register) != before.vectorBytes(register) {
									t.Fatal("unrelated bank changed", row)
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestX86TernaryRejectsNonIntegerAndMalformedMemory(t *testing.T) {
	for _, immediate := range []string{"0.0", "1.5"} {
		row := "VPTERNLOGD $" + immediate + ",X0,X1,X2"
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu"}); err == nil {
			t.Errorf("accepted floating truth table: %s", row)
		}
	}
}

func TestX86TernaryResultMemoryAndMaskBoundaries(t *testing.T) {
	for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for _, source := range []string{"(AX)", "·external(SB)", "0", "a+0(FP)"} {
			for _, suffix := range []string{"", ".BCST"} {
				row := fmt.Sprintf("%s%s $255,%s,Z1,Z2", op, suffix, source)
				ins := x86ScalarLaneInstruction(t, row)
				width := 64
				if suffix != "" {
					width = 4
					if op == "VPTERNLOGQ" {
						width = 8
					}
				}
				for missing := -1; missing < 64; missing++ {
					state := x86ResultState{fp: make([]bool, 64)}
					owned := make([]bool, 64)
					for at := range state.fp {
						state.fp[at] = at != missing
						owned[at] = true
					}
					got := x86ResultTransfer(ins, &state, owned, 0, "amd64")
					want := source == "a+0(FP)" && (missing < 0 || missing >= width)
					if got != want {
						t.Fatalf("memory authority/full envelope: %s missing%d got%t want%t", row, missing, got, want)
					}
				}
			}
		}
	}
	for _, suffix := range []string{"", ".Z"} {
		ins := x86ScalarLaneInstruction(t, "VPTERNLOGD"+suffix+" $255,Z0,Z1,K3,Z2")
		state := x86ResultState{}
		if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
			t.Fatal("constant Boolean value bypassed unknown mask")
		}
	}
}

func TestX86TernaryResultThreeAPIsAndActualGoTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	count := 0
	for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, immediate := range []int{0, 255, 150, 170, 204, 240} {
				fmt.Fprintf(&declarations, "func ternary%d() uint32\n", count)
				fmt.Fprintf(&source, "TEXT ·ternary%d(SB),4,$0-4\n", count)
				// With three equal unknown inputs, XOR3 and projections remain
				// unknown. Initialize those cases through an independent move.
				if immediate != 0 && immediate != 255 {
					fmt.Fprintf(&source, "VPXORQ %[1]s1,%[1]s1,%[1]s1\n", bank)
				}
				fmt.Fprintf(&source, "%s $%d,%s1,%s1,%s1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", op, immediate, bank, bank, bank)
				count++
			}
		}
	}
	for _, target := range x86RawReturnTargets {
		if target.arch == "386" {
			goAssemblerOracleOutput(t, target.arch, source.String(), "", false)
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api); err == nil {
					t.Fatal("mode32 accepted Go's rejected four-operand family", api)
				}
			}
			continue
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
			if err != nil {
				t.Fatal(target.triple, api, err)
			}
			compileLLVMToObject(t, llc, target.triple, "ternary-results.ll", "ternary-results.o", ir)
		}
	}
}
