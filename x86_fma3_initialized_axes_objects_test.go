package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// These are orthogonal initialized witnesses, not the full member x format
// Cartesian product. The original complete 1,836/612 format objects remain in
// their own tests, and all 60 register/memory/live/dead programs retain their
// independent source/input proof in TestX86FMA3InitializedRegisterMemoryAndDeadPrograms.
func x86FMA3InitializedAxisRows(arch string) []string {
	var rows []string
	seen := make(map[string]bool)
	add := func(row string) {
		if !seen[row] {
			seen[row] = true
			rows = append(rows, row)
		}
	}
	for _, op := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
		add(op + " X0,X1,X2")
	}
	representatives := map[string]bool{
		"VFMADD132PS": true, "VFMSUB213PD": true,
		"VFNMADD231SS": true, "VFNMSUB132SD": true,
	}
	for _, row := range x86FMA3NamedFormats(arch) {
		if representatives[strings.Split(strings.Fields(row)[0], ".")[0]] {
			add(row)
		}
	}
	if arch == "amd64" {
		for _, row := range []string{
			"VFMADD132PS X28,X29,X30", "VFMADD132PS Y28,Y29,Y30", "VFMADD132PS Z28,Z29,Z30",
			"VFMSUB213PD X28,X29,X30", "VFMSUB213PD Y28,Y29,Y30", "VFMSUB213PD Z28,Z29,Z30",
			"VFNMADD231SS X28,X29,X30", "VFNMSUB132SD X28,X29,X30",
		} {
			add(row)
		}
	}
	return rows
}

func x86FMA3InitializedAxisSource(arch, name, row string) (string, string) {
	operands := strings.Split(strings.Fields(row)[1], ",")
	destination := operands[len(operands)-1]
	index, _ := strconv.Atoi(destination[1:])
	// Both owners use consecutive arithmetic registers: 0/1/2, 16/17/18
	// for official physical rows, or 28/29/30 for the existing axis owner.
	var lower, raise []string
	for _, bank := range []string{"X", "Y", "Z"} {
		for register := 0; register < 3; register++ {
			original := fmt.Sprintf("%s%d", bank, index-2+register)
			canonical := fmt.Sprintf("%s%d", bank, register)
			lower = append(lower, original, canonical)
			raise = append(raise, canonical, original)
		}
	}
	low := strings.NewReplacer(lower...).Replace(row)
	source, declaration := x86FMA3InitializedSource(arch, name, low, false)
	if !strings.Contains(row, "K1") {
		// A plain VEX witness must not borrow an unrelated mask's AVX512 ISA.
		source = strings.Replace(source, "MOVL $85,CX\nKMOVW CX,K1\n", "", 1)
	}
	if low != row {
		source = strings.NewReplacer(raise...).Replace(source)
		// High X registers need the original EVEX input/output transports,
		// not an impossible legacy SSE MOVUPS/MOVD encoding.
		source = strings.ReplaceAll(source, "\nMOVUPS ", "\nVMOVUPS ")
		source = strings.Replace(source, fmt.Sprintf("MOVL X%d,AX\n", index), fmt.Sprintf("VMOVD X%d,AX\n", index), 1)
	}
	return source, declaration
}

func x86FMA3CheckInitializedNativeAxes(t *testing.T, ir string, rows []string) {
	t.Helper()
	wanted := make(map[string]int)
	for _, row := range rows {
		wanted[strings.ToLower(strings.Split(strings.Fields(row)[0], ".")[0])]++
	}
	for op, count := range wanted {
		found := 0
		for _, line := range strings.Split(ir, "\n") {
			if strings.Contains(line, "asm sideeffect") && strings.Contains(line, op+" ") {
				found++
				if !strings.Contains(line, "~{memory}") || !strings.Contains(line, "~{fpsr}") || strings.Contains(line, "~{flags}") {
					t.Fatal("initialized FMA3 lost native access/MXCSR or changed integer FLAGS", op, line)
				}
			}
		}
		if found != count {
			t.Fatal("initialized FMA3 lost or duplicated original whole native opcodes", op, found, count)
		}
	}
}

func x86FMA3InitializedAxesObjects(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("initialized FMA3 axes require LLVM22 llc")
	}
	rows := x86FMA3InitializedAxisRows(arch)
	wanted := 178
	if arch == "386" {
		wanted = 94
	}
	if len(rows) != wanted {
		t.Fatal("independent initialized FMA3 axis inventory changed", arch, len(rows), wanted)
	}
	for start := 0; start < len(rows); start += 48 {
		end := start + 48
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch%d", start/48), func(t *testing.T) {
			var source, declarations strings.Builder
			for index := start; index < end; index++ {
				entry, declaration := x86FMA3InitializedAxisSource(arch, fmt.Sprintf("FMAAxis%d", index), rows[index])
				source.WriteString(entry)
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized FMA3 axis source lost actual inputs or public continuation", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86FMA3CheckInitializedNativeAxes(t, pipeline.ir, rows[start:end])
						x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
	t.Logf("%s: %d initialized orthogonal FMA3 entries; all 60 members and independent physical axes, not every Cartesian format", triple, len(rows))
}

func TestX86FMA3InitializedAxesLinuxAMD64Objects(t *testing.T) {
	x86FMA3InitializedAxesObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86FMA3InitializedAxesDarwinAMD64Objects(t *testing.T) {
	x86FMA3InitializedAxesObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86FMA3InitializedAxesWindowsAMD64Objects(t *testing.T) {
	x86FMA3InitializedAxesObjects(t, "amd64", "x86_64-pc-windows-msvc")
}

func TestX86FMA3InitializedAxesLinux386Objects(t *testing.T) {
	x86FMA3InitializedAxesObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86FMA3InitializedAxesWindows386Objects(t *testing.T) {
	x86FMA3InitializedAxesObjects(t, "386", "i686-pc-windows-msvc")
}
