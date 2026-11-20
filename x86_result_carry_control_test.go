package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestX86CarryControlNumericalAvailability(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"CLC", "STC", "CMC"} {
			for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagsAll &^ x86ByteFlagCF, x86ByteFlagsAll} {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, op, flags), func(t *testing.T) {
					state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward}
					state.gp[0] = 0x55
					before := state.clone()
					accepted := x86ResultTransfer(x86ScalarLaneInstruction(t, op), &state, nil, 0, arch)
					if op == "CMC" && flags&x86ByteFlagCF == 0 {
						if accepted || !reflect.DeepEqual(state, before) {
							t.Fatal("CMC invented incoming CF or mutated a rejected state")
						}
						return
					}
					before.flags |= x86ByteFlagCF
					if !accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("carry control lacks exact CF-only effect", accepted)
					}
				})
			}
		}
	}
}

func TestX86CarryControlLogicalFPResultThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		resultOffset := 8
		if target.arch == "386" {
			resultOffset = 4
		}
		for _, row := range []struct{ name, flags string }{
			{"clear", "CLC"}, {"set", "STC"}, {"complement", "CLC\nCMC"}, {"unknown", "CMC"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOVL x+0(FP),AX\n%s"+
						"\nMOVL $3,BX\nCMOVLCC BX,AX\nMOVL AX,ret+%d(FP)\nRET\n", resultOffset+4, row.flags, resultOffset)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(x float32) uint32", target.arch, target.triple, api)
					if row.name == "unknown" {
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unknown CF was consumed as an initialized predicate", err)
						}
						return
					}
					if err != nil || ir == "" {
						t.Fatal("exact logical FP input and carry control rejected", err)
					}
					want := uint64(3)
					if row.name == "set" || row.name == "complement" {
						want = 0
					}
					probe := "\ndefine i32 @Probe() {\n %r = call i32 @Value(float 0.0)\n ret i32 %r\n}\n"
					x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", []uint64{want})
				})
			}
		}
	}
}

// The native runtime fixture must use actual scalar result metadata rather
// than the zero-value aggregate-field index. This all-host translation owner
// keeps that layout and the complete exchange family testable without x86
// execution on the development machine.
func TestX86ExchangeScalarResultPhysicalLayout(t *testing.T) {
	for _, family := range []string{"XADD", "XCHG", "REVERSE"} {
		for _, width := range "BWLQ" {
			t.Run(fmt.Sprintf("%s/%c", family, width), func(t *testing.T) {
				reg := "AX"
				if width == 'B' {
					reg = "AL"
				}
				instruction := fmt.Sprintf("%s%c %s,1(BX)", family, width, reg)
				if family == "REVERSE" {
					instruction = fmt.Sprintf("XCHG%c 1(BX),%s", width, reg)
				}
				source := "TEXT Value(SB),$0-24\nMOVQ p+0(FP),BX\nMOVQ v+8(FP),AX\n" +
					instruction + "\nMOVQ AX,ret+16(FP)\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				sig := FuncSig{Name: "Value", Args: []LLVMType{Ptr, I64}, Ret: I64, Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}},
					Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
				}}
				ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"Value": sig}})
				if err != nil || ir == "" {
					t.Fatal("complete exchange scalar result fixture rejected", err)
				}
			})
		}
	}
}
