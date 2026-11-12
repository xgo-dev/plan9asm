package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86FloatingMinMaxInitializedObjects(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete initialized MIN/MAX objects require LLVM22 llc")
	}
	rows := x86FloatingMinMaxFormats(arch)
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	for start := 0; start < len(rows); start += 48 {
		end := start + 48
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint("batch-", start/48), func(t *testing.T) {
			var source, declarations strings.Builder
			for index := start; index < end; index++ {
				ins := x86ScalarLaneInstruction(t, rows[index])
				f, known, err := x86FloatMinMaxProperties(ins, arch)
				if !known || err != nil {
					t.Fatal(rows[index], err)
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[f.byteWidth]
				fmt.Fprintf(&source, "TEXT ·MinMax%d(SB),4,$0-%d\n%s p+0(FP),AX\n%s out+%d(FP),BX\n",
					index, 2*word, move, move, word)
				for register := 0; register < 3; register++ {
					if f.legacy {
						fmt.Fprintf(&source, "XORPS X%d,X%d\n", register, register)
					} else {
						fmt.Fprintf(&source, "VXORPS %s%d,%s%d,%s%d\n", bank, register, bank, register, bank, register)
					}
				}
				if f.mask >= 0 {
					source.WriteString("MOVL $85,CX\nKMOVW CX,K1\n")
				}
				store := "VMOVUPS"
				if f.legacy {
					store = "MOVUPS"
				}
				fmt.Fprintf(&source, "%s\n%s %s,(BX)\nRET\n", rows[index], store, ins.Args[f.destination].Reg)
				fmt.Fprintf(&declarations, "func MinMax%d(p,out *byte)\n", index)
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized MIN/MAX format lost its actual inputs", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						for index := start; index < end; index++ {
							marker := fmt.Sprintf("@MinMax%d(", index)
							at := strings.Index(pipeline.ir, marker)
							if at < 0 {
								t.Fatal("missing initialized function", marker)
							}
							body := strings.SplitN(pipeline.ir[at:], "\n}", 2)[0]
							op := strings.ToLower(strings.Split(strings.Fields(rows[index])[0], ".")[0])
							found := 0
							for _, line := range strings.Split(body, "\n") {
								if strings.Contains(line, "asm sideeffect") &&
									(strings.Contains(line, "\""+op+" ") || strings.Contains(line, " "+op+" ")) {
									found++
									if !strings.Contains(line, "~{fpsr}") || !strings.Contains(line, "~{memory}") || strings.Contains(line, "~{flags}") {
										t.Fatal("MIN/MAX lost MXCSR/access effects or changed integer FLAGS", rows[index], line)
									}
								}
							}
							if found != 1 {
								t.Fatal("original whole MIN/MAX opcode missing or duplicated", rows[index], found)
							}
							if strings.Contains(body, " fcmp ") {
								t.Fatal("native MIN/MAX was replaced by a pure numerical relation", rows[index])
							}
						}
						x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}

func TestX86FloatingMinMaxInitializedLinuxAMD64Objects(t *testing.T) {
	x86FloatingMinMaxInitializedObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86FloatingMinMaxInitializedDarwinAMD64Objects(t *testing.T) {
	x86FloatingMinMaxInitializedObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86FloatingMinMaxInitializedWindowsAMD64Objects(t *testing.T) {
	x86FloatingMinMaxInitializedObjects(t, "amd64", "x86_64-pc-windows-msvc")
}

func TestX86FloatingMinMaxInitializedLinux386Objects(t *testing.T) {
	x86FloatingMinMaxInitializedObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86FloatingMinMaxInitializedWindows386Objects(t *testing.T) {
	x86FloatingMinMaxInitializedObjects(t, "386", "i686-pc-windows-msvc")
}
