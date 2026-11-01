package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestX86VNNIIntegerNativeInputsCannotBorrowMemoryOrFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86VNNIIntegerMembers {
			for _, input := range []string{"register", "full", "broadcast"} {
				mode := "zero"
				if arch == "386" {
					mode = "plain"
				}
				row := x86VNNIOracleRow{member.op, "Z", input, mode}
				original, declaration := row.program(arch, "Value")
				// A memory instruction must establish its own address, not be
				// rejected first by an unnecessary vector seed at that address.
				if input != "register" {
					original = strings.Replace(original, "VMOVUPS (AX),Z2\n", "", 1)
				}
				original = strings.Replace(original, row.instruction(), "STC\n"+row.instruction(), 1)
				original = strings.Replace(original, "RET\n", "SETCS 64(DI)\nRET\n", 1)
				for _, control := range []string{"initialized", "old", "second", "first", "mask", "address", "numeric-address", "index", "FLAGS"} {
					if control == "mask" && mode == "plain" || input == "register" && (control == "address" || control == "numeric-address" || control == "index") {
						continue // These inputs are absent from this independent format.
					}
					changed := original
					switch control {
					case "old":
						changed = strings.Replace(changed, "VMOVUPS (CX),Z0\n", "", 1)
					case "second":
						changed = strings.Replace(changed, "VMOVUPS (BX),Z1\n", "", 1)
					case "first":
						if input == "register" {
							changed = strings.Replace(changed, "VMOVUPS (AX),Z2\n", "", 1)
						} else {
							changed = strings.Replace(changed, "(AX),Z1", "(SI),Z1", 1)
						}
					case "mask":
						line := fmt.Sprintf("KMOVQ mask+%d(FP),K1\n", 4*goWordSize(arch))
						changed = strings.Replace(changed, line, "", 1)
					case "address", "numeric-address":
						line := fmt.Sprintf("MOVQ a+%d(FP),AX\n", goWordSize(arch))
						if arch == "386" {
							line = strings.Replace(line, "MOVQ", "MOVL", 1)
						}
						replacement := ""
						if control == "numeric-address" {
							replacement = "MOVL $42,AX\n"
						}
						changed = strings.Replace(changed, line, replacement, 1)
					case "index":
						changed = strings.Replace(changed, "(AX),Z1", "(AX)(SI*2),Z1", 1)
					case "FLAGS":
						changed = strings.Replace(changed, "STC\n", "", 1)
					}
					if control != "initialized" && changed == original {
						t.Fatal("independent missing-input mutation did not change its actual source", control)
					}
					t.Run(arch+"/"+row.instruction()+"/"+control, func(t *testing.T) {
						x86LEAActualTargetGoObject(t, arch, testTargetTriple("linux", arch), changed)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, testTargetTriple("linux", arch), api)
							if control == "initialized" {
								if err != nil || ir == "" {
									t.Fatal("real initialized integer-dot native read lost its paired source owner", api, err)
								}
								_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration, strings.Join(strings.Split(changed, "\n")[1:], "\n"))
								if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("standalone declaration query borrowed native backing", err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("integer-dot borrowed absent accumulator/mask/source/FLAGS/address permission", api, err)
							}
						}
					})
				}
			}
		}
	}
}

// Direct private emitter units are independent of the public source proof.
// A dead arithmetic result still owns every required native access, but none
// of these units is a public numerical or original-VNNI runtime certificate.
func TestX86VNNIIntegerDeadAccessRetainsExactNativeTuple(t *testing.T) {
	var original strings.Builder
	var rows []x86VNNIOracleRow
	for _, row := range x86VNNIOracleRows("amd64") {
		if row.input != "register" {
			fmt.Fprintf(&original, "TEXT DotAccess%d(SB),4,$0-0\n%s\nRET\n", len(rows), row.instruction())
			rows = append(rows, row)
		}
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", original.String())
	for _, row := range rows {
		t.Run(row.instruction(), func(t *testing.T) {
			file := mustParseX86RawReturn(t, "TEXT DotAccess(SB),4,$0-0\n"+row.instruction()+"\nRET\n")
			ir := x86SingleInstructionFormatObjectUnits(t, file, map[string]FuncSig{"DotAccess": {Name: "DotAccess", Ret: Void}},
				"amd64", "x86_64-unknown-linux-gnu", func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerPackedDotProduct(ins.Op, ins)
				})
			_, body, found := strings.Cut(ir, "define void @InstructionFormat0(")
			body, _, ended := strings.Cut(body, "\n}")
			if !found || !ended || strings.Count(ir, "\ndefine ") != 1 {
				t.Fatal("dead VNNI access lost its sole complete instruction body")
			}
			if strings.Contains(body, "asm sideeffect") && strings.Contains(body, strings.ToLower(row.op)) && strings.Contains(body, "~{memory}") {
				return // An original native opcode may own the complete access.
			}
			width := amd64VectorByteWidth(Reg(row.bank + "0"))
			loadType, count := "(?:i32|<4 x i8>)", 1
			if row.mode == "plain" && row.input != "broadcast" {
				loadType = fmt.Sprintf("(?:<%d x i32>|<%d x i8>)", width/4, width)
			} else if row.input != "broadcast" {
				loadType, count = "i32", width/4
			}
			// This unit contains exactly one operation, no parameters and
			// no producer loads. Every observed volatile load belongs to its
			// actual source: m32 has either a scalar or byte-vector bit view.
			// The common prelude declares unrelated masked-load intrinsics;
			// only this complete owned body can execute a source read.
			load := regexp.MustCompile(`(?m)^\s+%[^\n]+ = load volatile ` + loadType + `, [^\n]*, align 1$`)
			reads := load.FindAllString(body, -1)
			volatile := strings.Count(body, "load volatile ")
			masked := strings.Contains(body, "@llvm.masked.load")
			conditional := strings.Contains(body, "br i1")
			if len(reads) != count || volatile != count || masked || row.mode != "plain" && !conditional {
				t.Fatalf("dead VNNI access lost its exact volatile tuple/fault suppression: want=%d matched=%q volatile=%d masked=%t conditional=%t", count, reads, volatile, masked, conditional)
			}
		})
	}
}
