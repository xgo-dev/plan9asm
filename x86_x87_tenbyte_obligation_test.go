package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// A dead ten-byte load remains an actual memory/input effect. FINIT or a
// different typed instruction must not be needed to select its obligation.
// This semantic RED is independent of the original-table formatter feature.
func TestX86OfficialLegacyX87TenByteDeadInputsNeedContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"FMOVB", "FMOVX"} {
			source := "TEXT ·TenByte(SB),4,$0-0\n" + op + " (AX),F0\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+op+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func TenByte()", arch, testTargetTriple("linux", arch), api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("X87_TEN_BYTE_INPUT_NOT_PROVED: dead BCD/extended load borrowed an unknown native address or x87 entry", err)
					}
				})
			}
		}
	}
}

type x86X87TenByteFormat struct {
	op            string
	store         bool
	opcode, digit byte
}

// Independent complete Go table axes: B/X times load versus store-and-pop.
// This is a test oracle, not a production spelling or numerical permission.
func x86X87TenByteFormats() []x86X87TenByteFormat {
	var rows []x86X87TenByteFormat
	for _, format := range []struct {
		suffix        string
		opcode, digit byte
	}{
		{"B", 0xdf, 4}, {"X", 0xdb, 5},
	} {
		for _, store := range []bool{false, true} {
			op, digit := "FMOV"+format.suffix, format.digit
			if store {
				op += "P"
				digit += 2
			}
			rows = append(rows, x86X87TenByteFormat{op, store, format.opcode, digit})
		}
	}
	return rows
}

func (format x86X87TenByteFormat) instruction(address string) string {
	if format.store {
		return format.op + " F0," + address
	}
	return format.op + " " + address + ",F0"
}

func TestX86X87TenByteCompleteGoFormats(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, format := range x86X87TenByteFormats() {
			for _, address := range []string{"(AX)", "7(AX)"} {
				instruction := format.instruction(address)
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					code := []byte{format.opcode, format.digit << 3}
					if address == "7(AX)" {
						code[1] |= 0x40
						code = append(code, 7)
					}
					code = append(code, 0xc3)
					actual := x86OrderingHintGoBytes(t, arch, "TEXT probe(SB),4,$0-0\n"+instruction+"\nRET\n")
					if !reflect.DeepEqual(actual, code) {
						t.Fatal("actual complete Go ten-byte row differs", actual, code)
					}
					form, known, err := x86X87ValueProperties(x86X87ValueInstruction(t, instruction), arch)
					wantPop := uint8(0)
					if format.store {
						wantPop = 1
					}
					if !known || err != nil || form.memoryBytes() != 10 || form.push == format.store ||
						form.spec.pop != wantPop {
						t.Fatal("X87_TEN_BYTE_TYPED_FORMAT_FEATURE_GAP", instruction, known, err)
					}
				})
			}
			reversed := format.op + " F0,(AX)"
			if format.store {
				reversed = format.op + " (AX),F0"
			}
			for _, instruction := range []string{
				reversed,
				format.op + " AX,F0", format.op + " F1,(AX)", format.op + " (AX),F1",
				format.instruction("(AX)") + ",F2", format.instruction("(AX)(CX*3)"),
			} {
				t.Run(arch+"/malformed/"+instruction, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\n"+instruction+"\nRET\n")
					if err != nil {
						return
					}
					if _, known, err := x86X87ValueProperties(file.Funcs[0].Instrs[1], arch); !known || err == nil {
						t.Fatal("malformed ten-byte shape escaped its complete typed family", known, err)
					}
				})
			}
		}
	}
}

// A known pointer and logical F0 do not certify arbitrary packed BCD or
// extended numerical conversion. Reject without revoking the unrelated cells,
// prior control/status knownness, captured bits or the exact old state.
func TestX86X87TenByteUnprovedPrecisionKeepsPriorState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, format := range x86X87TenByteFormats() {
			t.Run(arch+"/"+format.op, func(t *testing.T) {
				state := x86ResultState{x87: &x86ResultX87State{slots: 3, depth: 2, status: 0x4500,
					word: &x86ResultX87WordState{control: 0xffff}}}
				state.pointerGP[0] = true
				state.x87.integer[1], state.x87.gp[3] = 4, 0x4000
				before := state.clone()
				accepted, known := x86ResultX87ValueStepWithMemory(x86X87ValueInstruction(t, format.instruction("(AX)")),
					&state, nil, 0, arch, false, true)
				if accepted || !known || !reflect.DeepEqual(before, state) {
					t.Fatal("X87_TEN_BYTE_UNPROVED_VALUE_OR_STATE_WIDENED", accepted, known)
				}
			})
		}
	}
}

func TestX86X87TenByteDefinedInputsDoNotGrantNumericalPrecision(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word := "MOVQ", 8
		if arch == "386" {
			move, word = "MOVL", 4
		}
		for _, format := range x86X87TenByteFormats() {
			for _, pointer := range []bool{false, true} {
				body := "FINIT\n"
				if pointer {
					body += move + " p+0(FP),AX\n"
				}
				if format.store {
					body += "FLDPI\n"
				}
				body += format.instruction("(AX)") + "\nFINIT\nRET\n"
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word, body)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/pointer=%t/%s", arch, format.op, pointer, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[10]byte)", arch, testTargetTriple("linux", arch), api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("X87_TEN_BYTE_DEFINED_INPUT_IS_NOT_PRECISION", err, source)
						}
					})
				}
			}
		}
	}
}

func TestX86X87TenByteRawAliasObservationAndInputBoundary(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		mode, move, word := 64, "MOVQ", 8
		if arch == "386" {
			mode, move, word = 32, "MOVL", 4
		}
		for _, row := range []struct {
			code  []byte
			store bool
			op    x86asm.Op
		}{
			{[]byte{0xdf, 0x20}, false, x86asm.FBLD}, {[]byte{0xdf, 0x30}, true, x86asm.FBSTP},
			{[]byte{0xdb, 0x28}, false, x86asm.FLD}, {[]byte{0xdb, 0x38}, true, x86asm.FSTP},
		} {
			t.Run(fmt.Sprintf("%s/%x", arch, row.code), func(t *testing.T) {
				decoded, err := x86asm.Decode(row.code, mode)
				// x/arch v0.14.0 omits all M80 forms from its MemBytes table.
				// Preserve that actual metadata; the original opcode/ModRM tuple
				// above establishes the ten-byte format independently.
				base := x86asm.RAX
				if arch == "386" {
					base = x86asm.EAX
				}
				if err != nil || decoded.Op != row.op || decoded.Len != len(row.code) || decoded.MemBytes != 0 ||
					decoded.Args[0] != (x86asm.Mem{Base: base}) || decoded.Args[1] != nil {
					t.Fatalf("original raw decoder observation: %+v, MemBytes=%d, args=%v, err=%v", decoded, decoded.MemBytes, decoded.Args, err)
				}
				var raw strings.Builder
				for _, code := range row.code {
					fmt.Fprintf(&raw, "BYTE $0x%02x\n", code)
				}
				body := fmt.Sprintf("FINIT\n%s p+0(FP),AX\n", move)
				if row.store {
					body += "FLDPI\n"
				}
				body += raw.String()
				body += "FINIT\nRET\n"
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				original, err := Parse(ArchAMD64, "TEXT ·Raw(SB),4,$0-0\n"+raw.String()+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				normalized, err := normalizeX86RawFile(original, arch)
				if err != nil {
					t.Fatal("exact decoded source normalization prerequisite", decoded.Op, err)
				}
				var opcode Op
				found := 0
				for _, ins := range normalized.Funcs[0].Instrs {
					if ins.x86SourceRaw == nil {
						continue
					}
					found++
					opcode = ins.Op
					before := ins
					before.Args = append([]Operand(nil), ins.Args...)
					origin := *ins.x86SourceRaw
					origin.args = append([]Operand(nil), origin.args...)
					before.x86SourceRaw = &origin
					if origin.op != ins.Op || !reflect.DeepEqual(origin.args, ins.Args) || origin.addressBits != ins.x86AddressBits {
						t.Fatal("normalized raw identity differs", row.code, ins)
					}
					t.Run("typed", func(t *testing.T) {
						form, known, err := x86X87ValueProperties(ins, arch)
						if row.op == x86asm.FBLD || row.op == x86asm.FBSTP {
							if len(ins.Args) != 1 {
								t.Fatal("BCD decoder alias lost its single original memory operand", row.code, ins)
							}
							wantPop := uint8(0)
							if row.store {
								wantPop = 1
							}
							if !known || err != nil || form.memoryBytes() != 10 || form.push == row.store || form.spec.pop != wantPop {
								t.Fatal("X87_TEN_BYTE_RAW_TYPED_ALIAS_FEATURE_GAP", row.code, known, err)
							}
							memory, f0 := ins.Args[0], Operand{Kind: OpReg, Reg: "F0"}
							wantSource, wantDestination := memory, f0
							if row.store {
								wantSource, wantDestination = f0, memory
							}
							if !reflect.DeepEqual(form.source, wantSource) || !reflect.DeepEqual(form.destination, wantDestination) {
								t.Fatal("derived typed alias changed exact source/destination", row.code, form)
							}
							if !x86TypedFPResultNeedsProof(normalized.Funcs[0], FuncSig{Name: "Raw", Ret: Void}, arch) {
								t.Fatal("X87_TEN_BYTE_RAW_VOID_OBLIGATION_MISSING", row.code)
							}
						} else if opcode != "FLD" && opcode != "FSTP" {
							t.Fatal("extended decoder boundary acquired an invented source alias", row.code, opcode)
						}
					})
					if !reflect.DeepEqual(before, ins) {
						t.Fatal("typed alias query changed original raw source", row.code)
					}
				}
				if found != 1 {
					t.Fatal("exact two-byte raw source did not retain one decoded instruction", row.code, found)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[10]byte)", arch, testTargetTriple("linux", arch), api)
						unsupported := (opcode == "FLD" || opcode == "FSTP") && err != nil &&
							strings.HasSuffix(err.Error(), "amd64: unsupported instruction "+string(opcode))
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) && !unsupported {
							t.Fatal("X87_TEN_BYTE_RAW_REJECTION_CLASS_DIFFERS", opcode, err)
						}
						t.Logf("raw source retained: code=%x decoder=%s memory=%d; no numerical/native claim: %v", row.code, decoded.Op, decoded.MemBytes, err)
					})
				}
			})
		}
	}
}
