package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func x86NativeMMXNonTemporalFixture(arch string, register int, address string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	return fmt.Sprintf("TEXT ·Store(SB),4,$0-%d\nMOVL value+0(FP),AX\n%s out+%d(FP),DI\n"+
			"MOVL $1,DX\nMOVL AX,M%d\nMOVNTQ M%d,%s\nEMMS\nSFENCE\nRET\n",
			word*2, move, word, register, register, address),
		"func Store(value uint32,out *[128]byte)"
}

func TestX86NativeMMXNonTemporalCompleteObjects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := strings.Join(strings.Fields(string(data)), "")
	for _, expected := range []string{
		"varymr_ml=[]ytab{{Zr_m_xm,1,argList{Ymr,Yml}},}",
		"{AMOVNTQ,ymr_ml,Pm,opBytes{0xe7}}",
	} {
		if !strings.Contains(table, expected) {
			t.Fatal("complete original Go MOVNTQ encoder row changed", expected)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var assembly, declarations strings.Builder
			var names []string
			for register := 0; register < 8; register++ {
				for _, address := range []string{"0(DI)", "3(DI)(DX*2)"} {
					source, declaration := x86NativeMMXNonTemporalFixture(target.arch, register, address)
					name := fmt.Sprintf("Stream%d", len(names))
					names = append(names, name)
					assembly.WriteString(strings.ReplaceAll(source, "Store", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Store", name) + "\n")
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized complete MMX store lost its native region", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86CompactExpandRequireAllDefinitions(t, text, names)
						if strings.Count(text, "movntq") != len(names) || strings.Count(text, "emms") != len(names) {
							t.Fatal("native streaming opcode or actual tag cleanup disappeared")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86NativeMMXNonTemporalCannotBorrowInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		source, declaration := x86NativeMMXNonTemporalFixture(arch, 0, "3(DI)(DX*2)")
		move, word, triple := "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		for name, original := range map[string]string{
			"source": "MOVL AX,M0\n", "pointer": fmt.Sprintf("%s out+%d(FP),DI\n", move, word),
			"index": "MOVL $1,DX\n", "tag cleanup": "EMMS\n",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				changed := strings.Replace(source, original, "", 1)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("streaming store acquired unknown data, address or physical tag state", api, err)
					}
				}
			})
		}
	}
}

func TestX86NativeMMXNonTemporalFPNeedsNativeBacking(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, triple := 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, triple = 4, "i386-unknown-linux-gnu"
		}
		source, declaration := x86NativeMMXNonTemporalFixture(arch, 0, fmt.Sprintf("ret+%d(FP)", word*2))
		source = strings.Replace(source, fmt.Sprintf("$0-%d", word*2), fmt.Sprintf("$0-%d", word*2+8), 1)
		declaration += " uint64"
		x86LEAActualTargetGoObject(t, arch, triple, source)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("streaming FP store borrowed the emitter's private byte image", arch, api, err)
			}
		}
	}
}
