package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86OfficialMMXObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	register := regexp.MustCompile(`\bM[0-7]\b`)
	for _, mode := range []struct {
		arch, triple string
		want         int
	}{
		{"386", "i386-unknown-linux-gnu", 5},
		{"amd64", "x86_64-unknown-linux-gnu", 398},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			var source, declarations strings.Builder
			var names, locations []string
			for _, path := range x86OfficialAssemblerSourcePaths(t, mode.arch) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for line, raw := range strings.Split(string(data), "\n") {
					code, _, _ := strings.Cut(raw, "//")
					if !register.MatchString(code) {
						continue
					}
					location := fmt.Sprintf("%s:%d: %s", filepath.Base(path), line+1, strings.TrimSpace(code))
					name := fmt.Sprintf("Value%d", len(names))
					ins := x86ScalarLaneInstruction(t, code)
					source.WriteString(x86OfficialMMXFunction(t, ins, mode.arch, name, location))
					fmt.Fprintf(&declarations, "func %s(memory *uint64, seed uint64)\n", name)
					names = append(names, name)
					locations = append(locations, location)
				}
			}
			version := runtime.Version()
			stableCorpus := strings.HasPrefix(version, "go1.20.") || strings.HasPrefix(version, "go1.27.")
			if len(names) == 0 || stableCorpus && len(names) != mode.want {
				t.Fatalf("%s: Go MMX source occurrences %d, expected %d", version, len(names), mode.want)
			}
			assembly := source.String()
			x86LEAActualTargetGoObject(t, mode.arch, mode.triple, assembly)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations.String(), mode.arch, mode.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Count(ir, "asm sideeffect") != len(names) || strings.Count(ir, "emms") != len(names) {
						t.Fatal("an original MMX region or its EMMS disappeared during translation")
					}
					object := compileLLVMToObject(t, llc, mode.triple, "mmx.ll", "mmx.o", ir)
					requireX86ELFTestFunctions(t, mode.arch, object, names, locations)
				})
			}
			t.Logf("compiled %d original Go %s MMX occurrences with all three APIs", len(names), mode.arch)
		})
	}
}

func x86OfficialMMXFunction(t *testing.T, ins Instr, arch, name, location string) string {
	t.Helper()
	site, known, err := x86NativeMMXInstruction(ins, arch)
	if err != nil || !known {
		t.Fatalf("%s: missing original MMX grammar: %v", location, err)
	}
	operands := site.frameOperands()
	if site.maskStore != nil {
		for _, operand := range ins.Args {
			operands = append(operands, x86TypedByteOperand{operand: operand, read: true})
		}
		operands = append(operands, x86TypedByteOperand{operand: Operand{Kind: OpMem, Mem: MemRef{Base: DI}}, write: true})
	}
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	frame := 0
	var prefix, region strings.Builder
	seeded := make(map[Reg]bool)
	for _, effect := range operands {
		operand := effect.operand
		switch operand.Kind {
		case OpMem:
			if operand.Mem.Base == SP {
				if arch != "386" || operand.Mem != (MemRef{Base: SP, Off: 8}) {
					t.Fatalf("%s: unexpected MMX stack operand %+v", location, operand.Mem)
				}
				frame = 16
				if effect.read {
					prefix.WriteString("MOVL seed+4(FP),AX\nMOVL AX,8(SP)\nMOVL seed+8(FP),AX\nMOVL AX,12(SP)\n")
				}
			} else {
				fmt.Fprintf(&prefix, "%s memory+0(FP),%s\n", move, operand.Mem.Base)
				if operand.Mem.Index != "" {
					fmt.Fprintf(&prefix, "%s $1,%s\n", move, operand.Mem.Index)
				}
			}
		case OpReg:
			if !effect.read || seeded[operand.Reg] {
				continue
			}
			seeded[operand.Reg] = true
			if _, mmx := amd64ParseMReg(operand.Reg); mmx {
				fmt.Fprintf(&region, "MOVQ seed+%d(FP),%s\n", word, operand.Reg)
			} else if _, vector := amd64ParseXReg(operand.Reg); vector {
				fmt.Fprintf(&prefix, "MOVQ seed+%d(FP),%s\n", word, operand.Reg)
			} else if gp, valid := x86CallerGP(operand.Reg); valid {
				fmt.Fprintf(&prefix, "%s $0x1020304,%s\n", move, gp)
			} else {
				t.Fatalf("%s: unexpected MMX register role %s", location, operand.Reg)
			}
		}
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$%d-%d\n%s%s%s\nEMMS\nRET\n",
		name, frame, word+8, prefix.String(), region.String(), ins.Raw)
}
