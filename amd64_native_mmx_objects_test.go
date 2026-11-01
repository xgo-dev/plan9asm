package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent operation and operand axes are checked separately from the
// exhaustive byte-definedness matrix. Each LLVM unit has at most 64 TEXTs.
func x86NativeMMXIntegerObjects(t *testing.T, triple, source string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	names := strings.Fields(x86NativeMMXTestIntegerNames)
	t.Run(source, func(t *testing.T) {
		var assembly, declarations strings.Builder
		for index, opcode := range names {
			name := fmt.Sprintf("mmx%d", index)
			fmt.Fprintf(&declarations, "func %s(input *byte,a,b uint64) uint64\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-32\nMOVQ input+0(FP),AX\n", name)
			assembly.WriteString("MOVQ a+8(FP),M0\nMOVQ b+16(FP),M1\nMOVQ b+16(FP),M3\n")
			if opcode == "PSHUFW" {
				fmt.Fprintf(&assembly, "%s $27,%s,M0\n", opcode, source)
			} else {
				fmt.Fprintf(&assembly, "%s %s,M0\n", opcode, source)
			}
			assembly.WriteString("MOVQ M0,ret+24(FP)\nEMMS\nRET\n")
		}
		x86LEAActualTargetGoObject(t, "amd64", triple, assembly.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), "amd64", triple, api)
				if err != nil {
					t.Fatal("complete initialized MMX family lacks its actual source-bound instruction region", err)
				}
				if strings.Count(ir, "asm sideeffect") != len(names) || strings.Count(ir, "emms") != len(names) {
					t.Fatal("MMX body or physical tag continuation disappeared")
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			})
		}
	})
}

func TestX86NativeMMXIntegerRegisterObjectsLinuxAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-unknown-linux-gnu", "M1")
}

func TestX86NativeMMXIntegerAliasObjectsLinuxAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-unknown-linux-gnu", "BX")
}

func TestX86NativeMMXIntegerFPObjectsLinuxAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-unknown-linux-gnu", "b+16(FP)")
}

func TestX86NativeMMXIntegerMemoryObjectsLinuxAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-unknown-linux-gnu", "(AX)")
}

func TestX86NativeMMXIntegerRegisterObjectsDarwinAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-apple-darwin", "M1")
}

func TestX86NativeMMXIntegerAliasObjectsDarwinAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-apple-darwin", "BX")
}

func TestX86NativeMMXIntegerFPObjectsDarwinAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-apple-darwin", "b+16(FP)")
}

func TestX86NativeMMXIntegerMemoryObjectsDarwinAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-apple-darwin", "(AX)")
}

func TestX86NativeMMXIntegerRegisterObjectsWindowsAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-pc-windows-msvc", "M1")
}

func TestX86NativeMMXIntegerAliasObjectsWindowsAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-pc-windows-msvc", "BX")
}

func TestX86NativeMMXIntegerFPObjectsWindowsAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-pc-windows-msvc", "b+16(FP)")
}

func TestX86NativeMMXIntegerMemoryObjectsWindowsAMD64(t *testing.T) {
	x86NativeMMXIntegerObjects(t, "x86_64-pc-windows-msvc", "(AX)")
}

func x86NativeMMXWordObjects(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	t.Run(triple, func(t *testing.T) {
		// The original named integer Py1 rows do not exist in Go mode32.
		// Word transfers, the distinct PHADDD row and PSHUFW do exist.
		bodies := []string{
			"MOVQ a+0(FP),M0\nMOVQ M0,ret+8(FP)",
			"MOVL a+0(FP),AX\nMOVL AX,M0\nMOVQ M0,ret+8(FP)",
			"MOVQ a+0(FP),X0\nMOVQ X0,M0\nMOVQOZX M0,X1\nEMMS\nMOVQ X1,ret+8(FP)",
			"MOVQ a+0(FP),M0\nPSHUFW $27,M0,M1\nMOVQ M1,ret+8(FP)",
			"MOVQ a+0(FP),M0\nMOVQ a+0(FP),M1\nPHADDD M1,M0\nMOVQ M0,ret+8(FP)",
		}
		var assembly, declarations strings.Builder
		for index, body := range bodies {
			name := fmt.Sprintf("word%d", index)
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			if !strings.Contains(body, "EMMS") {
				body += "\nEMMS"
			}
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\n%s\nRET\n", name, body)
		}
		x86LEAActualTargetGoObject(t, arch, triple, assembly.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, triple, api)
				if err != nil {
					t.Fatal("Go-mode-valid initialized MMX word source lost its native continuation", err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			})
		}
	})
}

func TestX86NativeMMXWordObjectsLinux386(t *testing.T) {
	x86NativeMMXWordObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86NativeMMXWordObjectsWindows386(t *testing.T) {
	x86NativeMMXWordObjects(t, "386", "i686-pc-windows-msvc")
}

func TestX86NativeMMXWordObjectsLinuxAMD64(t *testing.T) {
	x86NativeMMXWordObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86NativeMMXWordObjectsDarwinAMD64(t *testing.T) {
	x86NativeMMXWordObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86NativeMMXWordObjectsWindowsAMD64(t *testing.T) {
	x86NativeMMXWordObjects(t, "amd64", "x86_64-pc-windows-msvc")
}
