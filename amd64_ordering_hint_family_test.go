package plan9asm

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// Independent complete Go ynone rows, not an implementation-spec projection.
var x86OrderingHintOracleRows = []struct {
	op           Op
	registration string
	machine      []byte
}{
	{"LFENCE", "{ALFENCE, ynone, Pm, opBytes{0xae, 0xe8}}", []byte{0x0f, 0xae, 0xe8}},
	{"MFENCE", "{AMFENCE, ynone, Pm, opBytes{0xae, 0xf0}}", []byte{0x0f, 0xae, 0xf0}},
	{"SFENCE", "{ASFENCE, ynone, Pm, opBytes{0xae, 0xf8}}", []byte{0x0f, 0xae, 0xf8}},
	{"PAUSE", "{APAUSE, ynone, Px, opBytes{0xf3, 0x90}}", []byte{0xf3, 0x90}},
}

func TestX86OrderingHintsHaveExactEmptySourceEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86OrderingHintOracleRows {
			t.Run(arch+"/"+string(row.op), func(t *testing.T) {
				ins := Instr{Op: row.op}
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatalf("zero-operand instruction lacks exact no-output/no-flags source effect: %+v/%t/%v", effect, known, err)
				}
				move, suffix := Op("MOVQ"), "Q"
				if arch == "386" {
					move, suffix = "MOVL", "L"
				}
				if !x86SourceStackInstructionKnown(ins, move, suffix, arch) {
					t.Fatal("valid typed instruction has an unregistered source-stack effect")
				}
				result := x86ResultState{flags: x86ByteFlagsAll}
				before := result
				if !x86ResultTransfer(ins, &result, nil, 0, arch) || !reflect.DeepEqual(before, result) {
					t.Fatal("exact no-output instruction changed result initialization/flags")
				}
				caller := x86SourceStackState{numericFlags: true, known: map[Reg]uint8{AX: 0xff}}
				flags, valid := x86CallerScalarStep(&ins, &caller, nil)
				if !valid || flags || !caller.numericFlags || caller.known[AX] != 0xff {
					t.Fatal("exact no-output instruction changed caller facts")
				}
			})
		}
	}
}

func TestX86OrderingHintsActualInstructionsNotNoops(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86OrderingHintOracleRows {
			t.Run(arch+"/"+string(row.op), func(t *testing.T) {
				source := "TEXT fence(SB),4,$0-0\n" + string(row.op) + "\nRET\n"
				actual := x86OrderingHintGoBytes(t, arch, source)
				want := append(append([]byte(nil), row.machine...), 0xc3)
				if !bytes.Equal(actual, want) {
					t.Fatalf("actual Go encoding %x, want %x", actual, want)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				start := output.Len()
				known, terminated, err := ctx.lowerArith(row.op, file.Funcs[0].Instrs[1])
				if !known || terminated || err != nil {
					t.Fatal("accepted complete zero-operand form", err)
				}
				if !strings.Contains(output.String()[start:], "asm sideeffect \""+strings.ToLower(string(row.op))+"\"") {
					t.Fatal("actual ordering/hint instruction became a software no-op")
				}
			})
		}
	}
}

func TestX86OrderingHintsIllegalOperandsRejectBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86OrderingHintOracleRows {
			for _, argument := range []string{"AX", "(AX)", "$1", "AX,DX"} {
				t.Run(arch+"/"+string(row.op)+"/"+argument, func(t *testing.T) {
					source := "TEXT fence(SB),4,$0-0\n" + string(row.op) + " " + argument + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before, temporary := output.String(), ctx.tmp
					known, terminated, err := ctx.lowerArith(row.op, file.Funcs[0].Instrs[1])
					if !known || terminated || err == nil || before != output.String() || temporary != ctx.tmp {
						t.Fatalf("illegal operand did not fail before emission: %t/%t/%v", known, terminated, err)
					}
				})
			}
		}
	}
}
