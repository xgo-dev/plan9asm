package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent GP rows from ymovb/w/l/q. The two Q aliases are source aliases,
// not mode32 GP transports, MMX identities or separate initialized inputs.
type x86OwnedScalarStoreRow struct {
	op, register string
	width, first int64
}

func x86OwnedScalarStoreRows(arch string) []x86OwnedScalarStoreRow {
	rows := []x86OwnedScalarStoreRow{
		{"MOVB", "AL", 1, 0}, {"MOVB", "AH", 1, 1},
		{"MOVW", "AX", 2, 0}, {"MOVL", "AX", 4, 0},
	}
	if arch == "amd64" {
		rows = append(rows, x86OwnedScalarStoreRow{"MOVQ", "AX", 8, 0},
			x86OwnedScalarStoreRow{"MOVD", "AX", 8, 0},
			x86OwnedScalarStoreRow{"MOVDQ2Q", "AX", 8, 0})
	}
	return rows
}

func x86OwnedScalarStoreSource(row x86OwnedScalarStoreRow, arch, body string) string {
	move := "MOVL"
	if arch == "amd64" {
		move = "MOVQ"
	}
	if body == "" {
		body = fmt.Sprintf("%s $0x12345678,AX\nSTC\n%s %s,·storage+3(SB)\nSETCS BX\n",
			move, row.op, row.register)
	}
	return "GLOBL ·storage(SB),16,$32\nTEXT ·Value(SB),4,$0-0\n" + body + "RET\n"
}

func TestX86OwnedScalarStoreCompleteInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source, declarations strings.Builder
		source.WriteString("GLOBL ·storage(SB),16,$32\n")
		count := 0
		for _, row := range x86OwnedScalarStoreRows(arch) {
			for _, immediate := range []bool{false, true} {
				if immediate && row.register == "AH" {
					continue // One immediate row per original opcode, not per register spelling.
				}
				name := fmt.Sprintf("OwnedStore%d", count)
				count++
				input := row.register
				if immediate {
					input = "$7"
				}
				move := "MOVL"
				if arch == "amd64" {
					move = "MOVQ"
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s $0x12345678,AX\nSTC\n%s %s,·storage+3(SB)\nSETCS BX\nRET\n",
					name, move, row.op, input)
				fmt.Fprintf(&declarations, "func %s()\n", name)
			}
		}
		want := 7
		if arch == "amd64" {
			want = 13
		}
		if count != want {
			t.Fatal("complete register/immediate/alias inventory changed", count)
		}
		for _, target := range x86AddressMemoryTargets(arch) {
			t.Run(target, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, arch, target, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, target, api)
						if err != nil || ir == "" {
							t.Fatal("fully initialized GP store to actual module-owned writable bytes", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target, ir, level)
						}
					})
				}
			})
		}
	}
}

func TestX86OwnedScalarStoreCannotInventSourceOrStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86OwnedScalarStoreRows(arch) {
			original := x86OwnedScalarStoreSource(row, arch, "")
			move, word := "MOVL", 4
			if arch == "amd64" {
				move, word = "MOVQ", 8
			}
			for _, mutation := range []string{"external", "readonly", "short", "negative-offset", "past-end",
				"code-symbol", "relocation-payload", "missing-input", "partial-input", "pointer-input", "missing-flags", "raw-return"} {
				if mutation == "partial-input" && row.width == 1 {
					continue // The separate missing-input case removes its sole selected byte.
				}
				t.Run(arch+"/"+row.op+"/"+row.register+"/"+mutation, func(t *testing.T) {
					source, declaration := original, "func Value()\n"
					switch mutation {
					case "external":
						source = strings.TrimPrefix(source, "GLOBL ·storage(SB),16,$32\n")
					case "readonly":
						source = strings.Replace(source, ",16,$32", ",8,$32", 1)
					case "short":
						source = strings.Replace(source, "$32\n", fmt.Sprintf("$%d\n", row.width+2), 1)
					case "negative-offset":
						source = strings.Replace(source, "·storage+3(SB)", "·storage-1(SB)", 1)
					case "past-end":
						source = strings.Replace(source, "·storage+3(SB)", "·storage+32(SB)", 1)
					case "code-symbol":
						source = strings.Replace(source, "·storage+3(SB)", "·Value(SB)", 1)
					case "relocation-payload":
						source = fmt.Sprintf("DATA ·storage+0(SB)/%d,$·other(SB)\nGLOBL ·other(SB),16,$8\n", word) + source
					case "missing-input":
						source = strings.Replace(source, move+" $0x12345678,AX\n", "", 1)
					case "partial-input":
						source = strings.Replace(source, move+" $0x12345678,AX", "MOVB $7,AL", 1)
					case "pointer-input":
						declaration = "func Value(input *byte)\n"
						source = strings.Replace(source, "$0-0\n", fmt.Sprintf("$0-%d\n", word), 1)
						source = strings.Replace(source, move+" $0x12345678,AX", move+" input+0(FP),AX", 1)
					case "missing-flags":
						source = strings.Replace(source, "STC\n", "", 1)
					case "raw-return":
						source = strings.Replace(source, "RET\n", "BYTE $0xc3\nRET\n", 1)
					}
					if source == original {
						t.Fatal("independent negative did not change its source")
					}
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86AddressMemoryTargets(arch)[0], api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("owned store invented source/storage/FLAGS/raw permission", api, err)
						}
					}
				})
			}
		}
	}
}

// This interface lets the test-only revision compile before the independent
// lowering-local consumer exists. Its absence is an explicit effect-owner RED,
// not a compiler error or an invented ambient public source capability.
type x86OwnedScalarStoreConsumer interface {
	scalarStaticMoveTransfer(Instr, *x86ResultState, []bool, string) (bool, bool)
}

func TestX86OwnedScalarStoreEveryByteAndNoEscapingFacts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86OwnedScalarStoreRows(arch) {
			t.Run(arch+"/"+row.op+"/"+row.register, func(t *testing.T) {
				source := x86OwnedScalarStoreSource(row, arch, "")
				goAssemblerOracleOutput(t, arch, source, "", true)
				file := mustParseX86RawReturn(t, source)
				resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
				context := &amd64Ctx{resolve: resolve,
					fpStaticAddressValues: x86LoweredStaticAddressValues(file, resolve, nil, arch),
					fpScalarData:          x86LoweredScalarDataReads(file, resolve, nil, arch)}
				instruction := x86ScalarLaneInstruction(t, row.op+" "+row.register+",·storage+3(SB)")
				consumer, present := any(context).(x86OwnedScalarStoreConsumer)
				if !present {
					t.Fatal("missing lowering-local complete owned scalar MOV consumer")
				}
				for missing := int64(-1); missing < row.width; missing++ {
					for _, flags := range []uint8{0, x86ByteFlagsAll} {
						state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward}
						state.gp[0], state.gp[2], state.canonicalGP[2] = 0xff, 0x55, 0xaa
						state.pointerGP[2], state.callerAddressGP[2] = true, true
						if missing >= 0 {
							state.gp[0] &^= 1 << uint(row.first+missing)
						}
						before := state.clone()
						accepted, known := consumer.scalarStaticMoveTransfer(instruction, &state, nil, arch)
						if !known || accepted != (missing < 0) || !reflect.DeepEqual(state, before) {
							t.Fatal("selected input byte, unchanged FLAGS/DF or rollback contract", missing, accepted, known)
						}
					}
				}
				for _, mutation := range []string{"encoded", "address-size", "segment", "opaque-pointer"} {
					ins := instruction
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.gp[0] = 0xff
					switch mutation {
					case "encoded":
						ins.x86Encoded = true
					case "address-size":
						ins.x86AddressBits = 16
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "opaque-pointer":
						state.pointerGP[0], state.gp[0] = true, 0
					}
					before := state.clone()
					if accepted, _ := consumer.scalarStaticMoveTransfer(ins, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("store borrowed another role or partially mutated rejected state", mutation)
					}
				}
			})
		}
	}
}
