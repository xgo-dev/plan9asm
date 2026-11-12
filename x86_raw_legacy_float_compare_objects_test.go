package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86RawLegacyFloatCompareObjectRow struct {
	op, source, destination string
	code                    []byte
	selector                byte
	register                bool
}

func x86RawLegacyFloatCompareObjectRows(arch string) []x86RawLegacyFloatCompareObjectRow {
	var rows []x86RawLegacyFloatCompareObjectRow
	for _, oracle := range x86RawLegacyFloatCompareOracles {
		forms := []struct {
			source, destination string
			address             []byte
			rex                 byte
			register            bool
		}{
			{"X1", "X0", []byte{0xc1}, 0, true},
			{"X0", "X0", []byte{0xc0}, 0, true},
			{"(BX)", "X0", []byte{0x03}, 0, false},
			{"-7(BX)(CX*4)", "X0", []byte{0x44, 0x8b, 0xf9}, 0, false},
			{"128(BX)(CX*4)", "X0", []byte{0x84, 0x8b, 0x80, 0, 0, 0}, 0, false},
		}
		if arch == "amd64" {
			forms = append(forms, struct {
				source, destination string
				address             []byte
				rex                 byte
				register            bool
			}{"X15", "X14", []byte{0xf7}, 0x45, true})
		}
		for _, form := range forms {
			// Immediate exhaustiveness belongs to the orthogonal 256-selector
			// unit and original runtime, not another object Cartesian product.
			for _, selector := range []byte{0, 128, 255} {
				row := x86RawLegacyFloatCompareObjectRow{op: oracle.op, source: form.source,
					destination: form.destination, selector: selector, register: form.register}
				if oracle.prefix != 0 {
					row.code = append(row.code, oracle.prefix)
				}
				if form.rex != 0 {
					row.code = append(row.code, form.rex)
				}
				row.code = append(row.code, 0x0f, 0xc2)
				row.code = append(row.code, form.address...)
				row.code = append(row.code, selector)
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func x86RawLegacyFloatCompareInitializedObjects(t *testing.T, arch, triple string) {
	t.Helper()
	x86RawLegacyFloatCompareOriginalProgramsUnchanged(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows, expected, move, word := x86RawLegacyFloatCompareObjectRows(arch), 72, "MOVQ", 8
	if arch == "386" {
		expected, move, word = 60, "MOVL", 4
	}
	if len(rows) != expected {
		t.Fatal("complete independent legacy compare object directory changed", len(rows), expected)
	}
	for start := 0; start < len(rows); start += 36 {
		end := start + 36
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%03d", start), func(t *testing.T) {
			var named, raw, declarations strings.Builder
			var names []string
			for index, row := range rows[start:end] {
				name := fmt.Sprintf("Compare%d", index)
				names = append(names, name)
				prefix := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s left+%d(FP),AX\n%s right+%d(FP),BX\nMOVL $2,CX\nMOVOU (AX),%s\n",
					name, 3*word, move, move, word, move, 2*word, row.destination)
				if row.register {
					prefix += "MOVOU (BX)," + row.source + "\n"
				}
				suffix := "MOVOU " + row.destination + ",(DI)\nRET\n"
				named.WriteString(prefix + fmt.Sprintf("%s %s,%s,$%d\n", row.op, row.source, row.destination, int8(row.selector)) + suffix)
				raw.WriteString(prefix + x86RawDisplacementDirectives(row.code) + suffix)
				fmt.Fprintf(&declarations, "func %s(out,left,right *byte)\n", name)
			}
			for _, spelling := range []struct{ name, source string }{{"named", named.String()}, {"raw", raw.String()}} {
				t.Run(spelling.name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, arch, triple, spelling.source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations.String(), arch, triple, api)
							if err != nil {
								t.Fatal("complete initialized legacy compare source rejected", err)
							}
							for _, pipeline := range []struct{ name, text, level string }{
								{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
								{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
							} {
								t.Run(pipeline.name, func(t *testing.T) {
									x86CompactExpandRequireAllDefinitions(t, pipeline.text, names)
									for index, row := range rows[start:end] {
										_, body, found := strings.Cut(pipeline.text, "define void @"+names[index]+"(")
										body, _, ended := strings.Cut(body, "\n}")
										original := fmt.Sprintf("asm sideeffect \"%s $$%d,", strings.ToLower(row.op), row.selector)
										if !found || !ended || strings.Count(body, original) != 1 || !strings.Contains(body, "~{memory},~{fpsr}") {
											t.Fatal("actual function lost its original opcode, full immediate or native effect", names[index], row.selector)
										}
									}
									x86PackedStringCompileObject(t, llc, triple, pipeline.text, pipeline.level)
								})
							}
						})
					}
				})
			}
		})
	}
}

func TestX86RawLegacyFloatingCompareInitializedLinuxAMD64Objects(t *testing.T) {
	x86RawLegacyFloatCompareInitializedObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86RawLegacyFloatingCompareInitializedDarwinAMD64Objects(t *testing.T) {
	x86RawLegacyFloatCompareInitializedObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86RawLegacyFloatingCompareInitializedWindowsAMD64Objects(t *testing.T) {
	x86RawLegacyFloatCompareInitializedObjects(t, "amd64", "x86_64-pc-windows-msvc")
}

func TestX86RawLegacyFloatingCompareInitializedLinux386Objects(t *testing.T) {
	x86RawLegacyFloatCompareInitializedObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86RawLegacyFloatingCompareInitializedWindows386Objects(t *testing.T) {
	x86RawLegacyFloatCompareInitializedObjects(t, "386", "i686-pc-windows-msvc")
}
