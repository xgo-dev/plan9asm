package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// This independent inventory records physical byte positions, not renderer
// results. MOVMSKPS/PD use each lane's final sign byte; PMOVMSKB uses every byte.
var x86SelectedMoveMaskRows = []struct {
	op, bank         string
	width, laneBytes int
}{
	{"PMOVMSKB", "X", 16, 1}, {"VPMOVMSKB", "X", 16, 1}, {"VPMOVMSKB", "Y", 32, 1},
	{"MOVMSKPS", "X", 16, 4}, {"VMOVMSKPS", "X", 16, 4}, {"VMOVMSKPS", "Y", 32, 4},
	{"MOVMSKPD", "X", 16, 8}, {"VMOVMSKPD", "X", 16, 8}, {"VMOVMSKPD", "Y", 32, 8},
}

func TestX86MoveMaskSelectedOutputBitsThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple, stack := "x86_64-unknown-linux-gnu", "Q"
		if arch == "386" {
			triple, stack = "i386-unknown-linux-gnu", "L"
		}
		_, _, layout, _ := x86ResultInitializationFixture(t, arch, "func Value(value uint8) uint32", "RET")
		resultOffset := layout.Frame.Results[0].Offset
		for _, row := range x86SelectedMoveMaskRows {
			mask := row.op + " " + row.bank + "0,AX\n"
			seed := fmt.Sprintf("MOVBLZX value+0(FP),BX\nPINSRB $%d,BX,X0\n", row.laneBytes-1)
			for _, control := range []struct {
				name, before, between, observe string
				seed, pass                     bool
			}{
				{name: "and-selected", seed: true, pass: true, observe: "ANDL $1,AX\n"},
				{name: "and-next-unknown", seed: true, observe: "ANDL $3,AX\n"},
				{name: "unknown-escape", seed: true},
				{name: "missing-source", observe: "ANDL $1,AX\n"},
				{name: "constant-zero", pass: true, observe: "ANDL $0,AX\n"},
				{name: "intervening-nop", seed: true, between: "NOP\n", observe: "ANDL $1,AX\n"},
				{name: "changed-source", seed: true, between: "PXOR X0,X0\n", observe: "ANDL $1,AX\n"},
				{name: "overwritten-result", seed: true, between: "MOVL CX,AX\n", observe: "ANDL $1,AX\n"},
				{name: "test-selected", seed: true, pass: true, observe: "TESTL $1,AX\nSETNE AL\nMOVBLZX AL,AX\n"},
				{name: "test-selected-byte", seed: true, pass: true, observe: "TESTB $1,AL\nSETNE AL\nMOVBLZX AL,AX\n"},
				{name: "test-next-unknown", seed: true, observe: "TESTL $3,AX\nSETNE AL\nMOVBLZX AL,AX\n"},
				{name: "high-byte-is-padding", seed: true, pass: row.laneBytes > 1, observe: "MOVBLZX AH,AX\n"},
				{name: "selected-bit-eight", before: "MOVBLZX value+0(FP),BX\nPINSRB $8,BX,X0\n", pass: true, observe: "ANDW $256,AX\nMOVWLZX AX,AX\n"},
				{name: "test-does-not-write-GP", seed: true, observe: "TESTL $1,AX\n"},
				{name: "dynamic-mask-unproved", seed: true, before: "MOVL $1,CX\n", observe: "TESTL AX,CX\nSETNE AL\nMOVBLZX AL,AX\n"},
				{name: "movemask-preserves-CF", seed: true, pass: true, before: "MOVL $0,CX\nCMPL CX,$1\n", observe: "SETCS CL\nMOVBLZX CL,AX\n"},
				{name: "and-defines-CF", seed: true, pass: true, observe: "ANDL $1,AX\nSETCS CL\nMOVBLZX CL,AX\n"},
				{name: "and-does-not-define-AF", seed: true, observe: "ANDL $1,AX\nPUSHF" + stack + "\nPOP" + stack + " DX\nANDL $16,DX\nMOVL DX,AX\n"},
			} {
				t.Run(arch+"/"+row.op+row.bank+"/"+control.name, func(t *testing.T) {
					prefix := control.before
					if control.seed {
						prefix += seed
					}
					body := prefix + mask + control.between + control.observe + fmt.Sprintf("MOVL AX,ret+%d(FP)\nRET", resultOffset)
					_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(value uint8) uint32", body)
					goAssemblerOracleOutput(t, arch, source, "", true)
					t.Run("query", func(t *testing.T) {
						err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
						if control.pass && err != nil || !control.pass && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("selected bits or flags did not retain their exact dependencies", err)
						}
					})
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(value uint8) uint32", arch, triple, api)
							if arch == "amd64" && !control.pass && control.name != "overwritten-result" && control.name != "and-does-not-define-AF" {
								x86VectorScratchCodegenControl(t, source, "func Value(value uint8) uint32", arch, triple, ir, err)
							} else if control.pass && (err != nil || ir == "") || !control.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
								t.Fatal("adjacent observation invented or lost numerical bits", err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86MoveMaskSelectedBitsKeepSourceAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		_, _, layout, _ := x86ResultInitializationFixture(t, arch, "func Value(value uint8) uint32", "RET")
		for _, row := range x86SelectedMoveMaskRows {
			for _, initialize := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s%s/native-input=%t", arch, row.op, row.bank, initialize), func(t *testing.T) {
					prefix := ""
					if initialize {
						prefix = move + " input+0(FP),SI\n"
					}
					body := fmt.Sprintf("%sPINSRB $%d,(SI),X0\n%s %s0,AX\nANDL $1,AX\nMOVL AX,ret+%d(FP)\nRET", prefix, row.laneBytes-1, row.op, row.bank, word)
					_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(input *byte) uint32", body)
					goAssemblerOracleOutput(t, arch, source, "", true)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone query cannot borrow a lowerer's native-read continuation", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(input *byte) uint32", arch, triple, api)
							if initialize && (err != nil || ir == "") || !initialize && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
								t.Fatal("movemask altered the actual byte-read source requirement", err)
							}
						})
					}
				})
			}
			for _, mutation := range []string{"encoded", "raw-source", "address-override"} {
				t.Run(arch+"/"+row.op+row.bank+"/"+mutation, func(t *testing.T) {
					body := fmt.Sprintf("MOVBLZX value+0(FP),BX\nPINSRB $%d,BX,X0\n%s %s0,AX\nANDL $1,AX\nMOVL AX,ret+%d(FP)\nRET", row.laneBytes-1, row.op, row.bank, layout.Frame.Results[0].Offset)
					_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(value uint8) uint32", body)
					for index := range file.Funcs[0].Instrs {
						ins := &file.Funcs[0].Instrs[index]
						if string(ins.Op) != row.op {
							continue
						}
						switch mutation {
						case "encoded":
							ins.x86Encoded = true
						case "raw-source":
							ins.x86SourceRaw = new(x86SourceRawInstruction)
						case "address-override":
							ins.x86AddressBits = 16
						}
					}
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("a physical source borrowed the new named adjacent-bit producer", err)
					}
				})
			}
		}
	}
}

func TestX86MoveMaskSignByteDependenciesAndPreservedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86SelectedMoveMaskRows {
			for missing := -1; missing < row.width; missing++ {
				t.Run(fmt.Sprintf("%s/%s%s/missing=%d", arch, row.op, row.bank, missing), func(t *testing.T) {
					state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagOF}
					state.writeVector(0, 64, ^uint64(0), false)
					if missing >= 0 {
						state.writeVector(0, 64, state.vectorBytes(0)&^(uint64(1)<<uint(missing)), false)
					}
					before := state.clone()
					ins := x86ScalarLaneInstruction(t, row.op+" "+row.bank+"0,AX")
					accepted, known := x86ResultMoveMaskStep(ins, &state, nil, 0, arch)
					if !accepted || !known {
						t.Fatal("legal pure register producer cannot discard partially defined output bits")
					}
					want := uint8(0)
					for byteIndex := 0; byteIndex < 8; byteIndex++ {
						complete := true
						for bit := 8 * byteIndex; bit < 8*byteIndex+8; bit++ {
							if bit < row.width/row.laneBytes && bit*row.laneBytes+row.laneBytes-1 == missing {
								complete = false
							}
						}
						if complete {
							want |= 1 << uint(byteIndex)
						}
					}
					if state.gp[0] != want || state.flags != before.flags ||
						!reflect.DeepEqual(state.xmm, before.xmm) || !reflect.DeepEqual(state.vectorUpper, before.vectorUpper) ||
						!reflect.DeepEqual(state.masks, before.masks) || !reflect.DeepEqual(state.fp, before.fp) {
						t.Fatal("movemask widened a partial byte or altered vector/flags/storage", state.gp[0], want)
					}
				})
			}
		}
	}
}
