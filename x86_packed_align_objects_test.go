package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedAlignCompleteInitializedObjectsFiveTargets(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if word == 4 {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			count, batches, pending := 0, 0, 0
			flush := func() {
				if pending < 1 || pending > 64 {
					t.Fatal("invalid bounded align object batch", pending)
				}
				t.Run(fmt.Sprint("batch", batches), func(t *testing.T) {
					x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
				})
				source.Reset()
				declarations.Reset()
				batches++
				pending = 0
			}
			for _, row := range x86PackedAlignRows() {
				if target.arch == "386" && !row.legacy {
					continue
				}
				banks := []string{"X", "Y", "Z"}
				if row.legacy {
					banks = banks[:1]
				}
				for _, bank := range banks {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if row.legacy && mode != "plain" {
							continue
						}
						inputs := []string{bank + "0", "(SI)"}
						if row.bits != 8 {
							inputs = append(inputs, "broadcast")
						}
						for _, input := range inputs {
							op, operand, mask := row.op, input, ""
							if input == "broadcast" {
								op, operand = op+".BCST", "(SI)"
							}
							if mode != "plain" {
								mask = "K1,"
							}
							if mode == "zero" {
								op += ".Z"
							}
							name := fmt.Sprint("Align", count)
							instruction := x86PackedAlignInstruction(op, operand, bank, mask, 17, 2, row.legacy)
							fmt.Fprintf(&declarations, "func %s(out,a,b,old *[64]byte)\n", name)
							fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n"+
								"%s a+%d(FP),SI\n%s b+%d(FP),BX\n%s old+%d(FP),CX\n"+
								"VMOVUPS (SI),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z2\n"+
								"MOVL $-1431655766,AX\nKMOVD AX,K1\nSTC\n%s\nVMOVUPS Z2,(DI)\nRET\n",
								name, word*4, move, move, word, move, word*2, move, word*3, instruction)
							count++
							pending++
							if pending == 64 {
								flush()
							}
						}
					}
				}
			}
			want := 74
			if target.arch == "386" {
				want = 2
			}
			if count != want {
				t.Fatal("complete family/source/broadcast/mask object union changed", count, want)
			}
			if pending != 0 {
				flush()
			}
			if batches != (want+63)/64 {
				t.Fatal("missing object batch", batches)
			}
		})
	}
}

func TestX86PackedAlignDeadUnknownIsNotObservableNumericalData(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86PackedAlignRows() {
			if target.arch == "386" && !row.legacy {
				continue
			}
			for _, immediate := range []int{0, 255} {
				for _, role := range []string{"void", "unused-bool", "result", "missing-mask", "missing-native-address"} {
					if row.legacy && role == "missing-mask" {
						continue
					}
					t.Run(fmt.Sprintf("%s/%s/%d/%s", target.triple, row.op, immediate, role), func(t *testing.T) {
						declaration, header, tail := "func Value()", "$0-0", "RET\n"
						op, first, mask := row.op, "X0", ""
						want := true
						switch role {
						case "unused-bool":
							declaration, header = "func Value(unused bool)", "$0-1"
						case "result":
							declaration, header = "func Value() uint32", "$0-4"
							tail = "PEXTRD $0,X2,AX\nMOVL AX,ret+0(FP)\nRET\n"
							want = row.bits == 8 && immediate >= 32
						case "missing-mask":
							op, mask, want = op+".Z", "K1,", false
						case "missing-native-address":
							first, want = "(AX)", false
						}
						instruction := x86PackedAlignInstruction(op, first, "X", mask, immediate, 2, row.legacy)
						source := "TEXT ·Value(SB),4," + header + "\n" + instruction + "\n" + tail
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if want && (err != nil || ir == "") || !want && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
								t.Fatal("unknown dead data was rejected or became observable NUM/address/mask data", want, api, err)
							}
						}
					})
				}
			}
		}
	}
}
