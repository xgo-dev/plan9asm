package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86PackedShiftPhysicalWitness struct {
	row x86PackedShiftRawCase
	w   bool
}

func x86PackedShiftPhysicalWitnesses() []x86PackedShiftPhysicalWitness {
	var witnesses []x86PackedShiftPhysicalWitness
	for _, row := range x86PackedShiftRawCases() {
		witnesses = append(witnesses, x86PackedShiftPhysicalWitness{row: row})
		if row.wig() {
			witnesses = append(witnesses, x86PackedShiftPhysicalWitness{row: row, w: true})
		}
	}
	return witnesses
}

func x86PackedShiftCompletePublicObjects(t *testing.T, arch, triple, source, declarations string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete initialized packed-shift objects require LLVM22 llc")
	}
	x86LEAActualTargetGoObject(t, arch, triple, source)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("initialized complete packed-shift source lost its public object consumer", err)
			}
			for _, pipeline := range []struct{ name, input, level string }{
				{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
				{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					x86PackedStringCompileObject(t, llc, triple, pipeline.input, pipeline.level)
				})
			}
		})
	}
}

func x86PackedShiftCompletePhysicalObjectPart(t *testing.T, arch, triple string, part int) {
	t.Helper()
	rows := x86PackedShiftPhysicalWitnesses()
	if len(rows) != 850 || part < 0 || part >= 4 {
		t.Fatal("complete physical object partition changed", len(rows), part)
	}
	first, last := len(rows)*part/4, len(rows)*(part+1)/4
	for start := first; start < last; start += 48 {
		end := start + 48
		if end > last {
			end = last
		}
		t.Run(fmt.Sprintf("rows_%d_%d", start, end), func(t *testing.T) {
			var source, declarations strings.Builder
			for index := start; index < end; index++ {
				witness := rows[index]
				program, declaration, _ := witness.row.program(arch, true)
				if witness.w {
					program = strings.Replace(program, x86RawDisplacementDirectives(witness.row.code(false)),
						x86RawDisplacementDirectives(witness.row.code(true)), 1)
				}
				name := fmt.Sprint("PhysicalShift", index)
				source.WriteString(strings.Replace(program, "·Shift(SB)", "·"+name+"(SB)", 1))
				declarations.WriteString(strings.Replace(declaration, "func Shift(", "func "+name+"(", 1) + "\n")
			}
			x86PackedShiftCompletePublicObjects(t, arch, triple, source.String(), declarations.String())
		})
	}
	// This proves initialized public LLVM objects, not execution of original
	// Go code or positive LLVM-MC recognition of the 54 documented W1 gaps.
	t.Logf("complete physical interval [%d,%d)/850; <=48 initialized functions/capture; three public APIs and pipelines", first, last)
}

func TestX86PackedShiftRawCompleteLinux386Part0(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i386-unknown-linux-gnu", 0)
}

func TestX86PackedShiftRawCompleteLinux386Part1(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i386-unknown-linux-gnu", 1)
}

func TestX86PackedShiftRawCompleteLinux386Part2(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i386-unknown-linux-gnu", 2)
}

func TestX86PackedShiftRawCompleteLinux386Part3(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i386-unknown-linux-gnu", 3)
}

func TestX86PackedShiftRawCompleteWindows386Part0(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i686-pc-windows-msvc", 0)
}

func TestX86PackedShiftRawCompleteWindows386Part1(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i686-pc-windows-msvc", 1)
}

func TestX86PackedShiftRawCompleteWindows386Part2(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i686-pc-windows-msvc", 2)
}

func TestX86PackedShiftRawCompleteWindows386Part3(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "386", "i686-pc-windows-msvc", 3)
}

func TestX86PackedShiftRawCompleteLinuxAMD64Part0(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-unknown-linux-gnu", 0)
}

func TestX86PackedShiftRawCompleteLinuxAMD64Part1(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-unknown-linux-gnu", 1)
}

func TestX86PackedShiftRawCompleteLinuxAMD64Part2(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-unknown-linux-gnu", 2)
}

func TestX86PackedShiftRawCompleteLinuxAMD64Part3(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-unknown-linux-gnu", 3)
}

func TestX86PackedShiftRawCompleteDarwinAMD64Part0(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-apple-darwin", 0)
}

func TestX86PackedShiftRawCompleteDarwinAMD64Part1(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-apple-darwin", 1)
}

func TestX86PackedShiftRawCompleteDarwinAMD64Part2(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-apple-darwin", 2)
}

func TestX86PackedShiftRawCompleteDarwinAMD64Part3(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-apple-darwin", 3)
}

func TestX86PackedShiftRawCompleteWindowsAMD64Part0(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-pc-windows-msvc", 0)
}

func TestX86PackedShiftRawCompleteWindowsAMD64Part1(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-pc-windows-msvc", 1)
}

func TestX86PackedShiftRawCompleteWindowsAMD64Part2(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-pc-windows-msvc", 2)
}

func TestX86PackedShiftRawCompleteWindowsAMD64Part3(t *testing.T) {
	x86PackedShiftCompletePhysicalObjectPart(t, "amd64", "x86_64-pc-windows-msvc", 3)
}

func x86PackedShiftOriginal396Objects(t *testing.T, triple string) {
	t.Helper()
	kernels := x86PackedShiftOriginalRuntimeDirectory(t, "")
	if len(kernels) != 396 {
		t.Fatal("original complete initialized object denominator changed", len(kernels))
	}
	for start := 0; start < len(kernels); start += 36 {
		end := start + 36
		if end > len(kernels) {
			end = len(kernels)
		}
		t.Run(fmt.Sprintf("kernels_%d_%d", start, end), func(t *testing.T) {
			var source strings.Builder
			for _, kernel := range kernels[start:end] {
				source.WriteString(kernel.source)
			}
			x86PackedShiftCompletePublicObjects(t, "amd64", triple, source.String(),
				x86PackedShiftOriginalDeclarations(kernels[start:end], false))
		})
	}
}

func TestX86PackedShiftOriginal396ObjectsLinuxAMD64(t *testing.T) {
	x86PackedShiftOriginal396Objects(t, "x86_64-unknown-linux-gnu")
}

func TestX86PackedShiftOriginal396ObjectsDarwinAMD64(t *testing.T) {
	x86PackedShiftOriginal396Objects(t, "x86_64-apple-darwin")
}

func TestX86PackedShiftOriginal396ObjectsWindowsAMD64(t *testing.T) {
	x86PackedShiftOriginal396Objects(t, "x86_64-pc-windows-msvc")
}
