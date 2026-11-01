package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type x86Permute128OracleRow struct {
	member, immediate, first, second, destination int
	memory, raw                                   bool
}

func (row x86Permute128OracleRow) instruction() string {
	input := fmt.Sprint("Y", row.first)
	if row.memory {
		input = "(AX)"
	}
	return fmt.Sprintf("%s $%d,%s,Y%d,Y%d", x86Permute128Members[row.member].op,
		row.immediate, input, row.second, row.destination)
}

func (row x86Permute128OracleRow) code() []byte {
	first := row.first
	if row.memory {
		first = 0 // ModRM memory base is AX, not the register-form source bank.
	}
	code := encodeX86RawVPERM2X128(x86Permute128Members[row.member].opcode,
		byte(row.immediate), first, row.second, row.destination)
	if row.memory {
		code[4] &= 0x38
	}
	return code
}

func (row x86Permute128OracleRow) program(arch, name string) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s first+%d(FP),AX\n%s second+%d(FP),BX\n",
		name, 3*word, move, move, word, move, 2*word)
	if !row.memory {
		fmt.Fprintf(&source, "VMOVDQU (AX),Y%d\n", row.first)
	}
	fmt.Fprintf(&source, "VMOVDQU (BX),Y%d\nSTC\n", row.second)
	if row.raw {
		source.WriteString(x86RawDisplacementDirectives(row.code()))
	} else {
		source.WriteString(row.instruction() + "\n")
	}
	fmt.Fprintf(&source, "VMOVDQU Y%d,(DI)\nSETCS 32(DI)\nRET\n", row.destination)
	return source.String(), "func " + name + "(out,first,second *byte)\n"
}

func TestX86Permute128NativeInputsAndAddressRoles(t *testing.T) {
	for member := range x86Permute128Members {
		for _, memory := range []bool{false, true} {
			row := x86Permute128OracleRow{member: member, immediate: 0x21, second: 1, destination: 2, memory: memory}
			source, declaration := row.program("amd64", "Value")
			for _, control := range []string{"initialized", "zero", "first", "second", "numeric-address", "index", "FLAGS", "FP-write"} {
				changed := source
				switch control {
				case "zero":
					changed = strings.ReplaceAll(changed, "VMOVDQU (AX),Y0\n", "")
					changed = strings.ReplaceAll(changed, "VMOVDQU (BX),Y1\n", "")
					changed = strings.Replace(changed, "$33,", "$136,", 1)
				case "first":
					seed := "VMOVDQU (AX),Y0\n"
					if memory {
						seed = "MOVQ first+8(FP),AX\n"
					}
					changed = strings.Replace(changed, seed, "", 1)
				case "second":
					changed = strings.Replace(changed, "VMOVDQU (BX),Y1\n", "", 1)
				case "numeric-address":
					changed = strings.Replace(changed, "MOVQ first+8(FP),AX", "MOVQ $42,AX", 1)
				case "index":
					changed = strings.Replace(changed, "(AX)", "(AX)(SI*2)", 1)
				case "FLAGS":
					changed = strings.Replace(changed, "STC\n", "", 1)
				case "FP-write":
					changed = strings.Replace(changed, "Y2,(DI)", "Y2,first+8(FP)", 1)
				}
				if control != "initialized" && changed == source {
					t.Fatal("independent input mutation did not change source", control)
				}
				t.Run(row.instruction()+"/"+control, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", changed)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
						if control == "initialized" || control == "zero" {
							if err != nil || ir == "" {
								t.Fatal("real initialized permute128 lost its source owner", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("permute128 borrowed absent source/address/FLAGS/frame authority", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86Permute128DeadZeroStillReadsCompleteNativeTuple(t *testing.T) {
	for _, member := range x86Permute128Members {
		for _, immediate := range []int{0, 0x21, 0x88, 255} {
			row := fmt.Sprintf("%s $%d,-1(AX)(CX*4),Y1,Y2", member.op, immediate)
			t.Run(row, func(t *testing.T) {
				source := "TEXT PermuteAccess(SB),4,$0-0\n" + row + "\nRET\n"
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
				file := mustParseX86RawReturn(t, source)
				ir := x86SingleInstructionFormatObjectUnits(t, file,
					map[string]FuncSig{"PermuteAccess": {Name: "PermuteAccess", Ret: Void}},
					"amd64", "x86_64-unknown-linux-gnu", func(c *amd64Ctx, ins Instr) (bool, bool, error) {
						return c.lowerVec(ins.Op, ins)
					})
				_, body, found := strings.Cut(ir, "define void @InstructionFormat0(")
				body, _, ended := strings.Cut(body, "\n}")
				load := regexp.MustCompile(`(?m)^\s+%[^\n]+ = load volatile <32 x i8>, [^\n]*, align 1$`)
				if !found || !ended || strings.Count(ir, "\ndefine ") != 1 ||
					len(load.FindAllString(body, -1)) != 1 || strings.Count(body, "load volatile ") != 1 ||
					strings.Contains(body, "@llvm.masked.load") || strings.Contains(body, "br i1") {
					t.Fatal("Type6 m256 access was narrowed, masked, conditional or removable for a dead/zero result", body)
				}
			})
		}
	}
}

// Each target owns 32 initialized AMD64 or 16 raw mode32 witnesses. Member,
// r/m, ignored/zero selector bits and aliases are orthogonal representatives;
// the full 256 selectors and every source byte live in cheap independent roots.
func TestX86Permute128InitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var names []string
			for member := range x86Permute128Members {
				for axis, immediate := range []int{0, 0x21, 0x88, 255} {
					for _, memory := range []bool{false, true} {
						for _, raw := range []bool{false, true} {
							if target.arch == "386" && !raw {
								continue // Named four-operand Go syntax remains rejected.
							}
							row := x86Permute128OracleRow{member: member, immediate: immediate,
								first: 0, second: 1, destination: []int{2, 0, 1, 7}[axis], memory: memory, raw: raw}
							if target.arch == "amd64" && axis == 3 {
								row.first, row.second, row.destination = 13, 15, 14
							}
							name := fmt.Sprint("Permute", len(names))
							names = append(names, name)
							body, declaration := row.program(target.arch, name)
							source.WriteString(body)
							declarations.WriteString(declaration)
						}
					}
				}
			}
			want := 32
			if target.arch == "386" {
				want = 16
			}
			if len(names) != want {
				t.Fatal("complete orthogonal object denominator changed", len(names), want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized named/raw permute128 witnesses rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}

// This executes the unchanged ordinary ASM/C as portable LLVM on the actual
// host. It is not an original-Go AVX/AVX2 or native instruction certificate.
func TestX86Permute128OriginalActualHostLLVMCompanion(t *testing.T) {
	source, reference := x86Permute128OriginalRuntime(t)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, x86Permute128OriginalDeclarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("original initialized permute128 program rejected", err)
			}
			if strings.Contains(ir, " asm ") || strings.Contains(ir, "target-features") {
				t.Fatal("portable bit-permute companion contains native execution or an ISA constraint")
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "original_permute128_portable", triple, ir, reference)
		})
	}
}
