package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86NativeMXCSRPointerFamilyFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
				for _, result := range []bool{false, true} {
					name, args := fmt.Sprintf("%s%v", op, result), word
					declaration, finish := "", ""
					if result {
						declaration, args = " uint32", word+4
						finish = fmt.Sprintf("MOVL $7,ret+%d(FP)\n", word)
					}
					fmt.Fprintf(&declarations, "func %s(p *[8]byte)%s\n", name, declaration)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s 1(AX)\n%sRET\n",
						name, args, move, op, finish)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete original native m32 control operations lost their paired emitter", api, err)
				}
				for _, op := range []string{"ldmxcsr", "vldmxcsr", "stmxcsr", "vstmxcsr"} {
					if strings.Count(ir, "asm sideeffect \""+op+" $0\"") != 2 {
						t.Fatal("original native opcode/fault identity was not retained", api, op)
					}
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86NativeMXCSRPointerFamilyRetainsCompleteInputObligation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, triple, word := "MOVL", "i386-unknown-linux-gnu", 4
		if arch == "amd64" {
			move, triple, word = "MOVQ", "x86_64-unknown-linux-gnu", 8
		}
		for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
			for _, body := range []string{
				op + " (AX)",
				"MOVW p+0(FP),AX\n" + op + " (AX)",
				move + " p+0(FP),AX\n" + op + " (AX)(CX*1)",
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+op+"/"+body+"/"+api, func(t *testing.T) {
						source := fmt.Sprintf("TEXT ·State(SB),4,$0-%d\n%s\nRET\n", word, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func State(p *uint32)", arch, triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("native MXCSR operation borrowed undefined address/index bytes", err)
						}
					})
				}
			}
		}
	}
}

func TestX86LockRuntimeCompleteSourcesTranslateAllAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		declarations, source, _, _, count := x86LockScalarRuntimeFixture(arch)
		want, triple := 174, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			want, triple = 129, "i386-unknown-linux-gnu"
		}
		if count != want {
			t.Fatal("complete native LOCK source denominator changed", count)
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				if _, err := x86OrderingHintTranslateAPI(t, api, source, declarations, arch, triple); err != nil {
					t.Fatal("original complete native LOCK source rejected", err)
				}
			})
		}
	}
}

func TestX86LockRuntimeSavedStatusNeedsOriginalSourceRefinement(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		declarations, source, _, _, count := x86LockScalarRuntimeFixture(arch)
		file, err := Parse(ArchAMD64, source)
		if err != nil || len(file.Funcs) != count {
			t.Fatal("complete original LOCK observation inventory changed", err)
		}
		rows := x86LockScalarRuntimeCases(arch)
		for index, function := range file.Funcs {
			observations := 0
			for offset, ins := range function.Instrs {
				if ins.Op != "PUSHFQ" && ins.Op != "PUSHFL" {
					continue
				}
				if offset+2 >= len(function.Instrs) {
					t.Fatal("saved status has no complete following refinement")
				}
				mask := function.Instrs[offset+2]
				if (mask.Op != "ANDQ" && mask.Op != "ANDL") || len(mask.Args) != 2 ||
					mask.Args[0].Kind != OpImm || mask.Args[0].Imm != int64(x86ScalarRuntimeStatusMask(rows[index].stem)) ||
					mask.Args[1].Kind != OpReg || mask.Args[1].Reg != AX {
					t.Fatal("LOCK status output borrowed undefined architecture bits", function.Sym, mask)
				}
				observations++
			}
			if observations != 1 {
				t.Fatal("complete LOCK kernel lost its one saved-status observation", function.Sym)
			}
		}
		// Preserve the original complete source as a negative control. Logical
		// and bit-string status bits cannot be materialized merely because a
		// separate reference would discard them later.
		original := source
		for _, mask := range []int{0x41, 0x8c5, 0x8d5} {
			for _, suffix := range []string{"L", "Q"} {
				original = strings.ReplaceAll(original, fmt.Sprintf("AND%s $%d,AX\n", suffix, mask), "")
			}
		}
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, original, declarations, arch, triple)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("the original unrefined LOCK source gained undefined numerical bits", err)
				}
			})
		}
	}
}
