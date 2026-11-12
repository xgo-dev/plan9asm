package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

type armConversionMatrixRow struct {
	function int
	input    [8]uint32
}

func armConversionMatrixOriginal(forms []armConversionMatrixForm, rows []armConversionMatrixRow) string {
	var source strings.Builder
	source.WriteString("package main\nimport (\"bufio\"; \"fmt\"; \"os\")\n")
	for index := range forms {
		fmt.Fprintf(&source, "func matrix%d(input *[8]uint32, output *[10]uint32)\n", index)
	}
	source.WriteString("var functions = [...]func(*[8]uint32,*[10]uint32){\n")
	for index := range forms {
		fmt.Fprintf(&source, "matrix%d,\n", index)
	}
	source.WriteString("}\nvar rows = []struct { function int; input [8]uint32 }{\n")
	for _, row := range rows {
		fmt.Fprintf(&source, "{%d,[8]uint32{", row.function)
		for _, value := range row.input {
			fmt.Fprintf(&source, "%#x,", value)
		}
		source.WriteString("}},\n")
	}
	source.WriteString(`}
func main() {
    writer := bufio.NewWriter(os.Stdout)
    for _, row := range rows {
        out := [10]uint32{0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,
            0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0x12345678,0x87654321}
        functions[row.function](&row.input,&out)
        for _, value := range out { fmt.Fprintf(writer,"%08x",value) }
        fmt.Fprintln(writer)
    }
    if err := writer.Flush(); err != nil { panic(err) }
}
`)
	return source.String()
}

func armConversionMatrixDriver(t *testing.T, forms []armConversionMatrixForm, rows []armConversionMatrixRow, original []byte) string {
	t.Helper()
	// One fixed-size record per input, with no hashes or partial observations.
	// The final two words are untouched neighboring-memory canaries.
	if len(original) != len(rows)*81 {
		t.Fatalf("original Go observation extent: got %d bytes, want %d", len(original), len(rows)*81)
	}
	var source strings.Builder
	source.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range forms {
		fmt.Fprintf(&source, "extern void matrix%d(uint32_t*,uint32_t*);\n", index)
	}
	source.WriteString("static void (*functions[])(uint32_t*,uint32_t*)={\n")
	for index := range forms {
		fmt.Fprintf(&source, "matrix%d,\n", index)
	}
	source.WriteString("};\nstatic const struct { unsigned function; uint32_t input[8], want[10]; } rows[]={\n")
	for index, row := range rows {
		fmt.Fprintf(&source, "{%d,{", row.function)
		for _, value := range row.input {
			fmt.Fprintf(&source, "%#x,", value)
		}
		source.WriteString("},{")
		line := string(original[index*81 : (index+1)*81])
		if line[80] != '\n' {
			t.Fatalf("unterminated original Go observation %d", index)
		}
		for word := 0; word < 10; word++ {
			value, err := strconv.ParseUint(line[word*8:(word+1)*8], 16, 32)
			if err != nil {
				t.Fatalf("original Go row %d word %d: %v", index, word, err)
			}
			if word == 8 && value != 0x12345678 || word == 9 && value != 0x87654321 {
				t.Fatalf("original Go row %d corrupted neighbor %d: %#x", index, word, value)
			}
			fmt.Fprintf(&source, "%#x,", value)
		}
		source.WriteString("}},\n")
	}
	source.WriteString(`};
int main(void) {
    unsigned failures = 0;
    for (unsigned row=0; row<sizeof(rows)/sizeof(rows[0]); row++) {
        uint32_t input[8];
        for (unsigned word=0; word<8; word++) input[word]=rows[row].input[word];
        uint32_t out[10]={0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,
            0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0x12345678,0x87654321};
        functions[rows[row].function](input,out);
        for (unsigned word=0; word<10; word++) {
            if (out[word] != rows[row].want[word]) {
                if (failures<20) fprintf(stderr,"row %u function %u word %u got %08x want %08x\n",
                    row,rows[row].function,word,out[word],rows[row].want[word]);
                failures++;
            }
        }
    }
    printf("ARM_CONVERSION_MATRIX rows=%zu failures=%u\n",sizeof(rows)/sizeof(rows[0]),failures);
    return failures != 0;
}
`)
	return source.String()
}

func runARMConversionMatrix(t *testing.T, forms []armConversionMatrixForm, rows []armConversionMatrixRow) {
	t.Helper()
	llc := requireARMScalarRuntime(t)
	source, sigs := armConversionMatrixSource(forms)
	original := armConversionGoObservations(t, source, armConversionMatrixOriginal(forms, rows))
	driver := armConversionMatrixDriver(t, forms, rows, original)
	t.Logf("actual original Go: %d forms, %d result/FPSCR/full-register/canary rows", len(forms), len(rows))
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"unoptimized", ir}, {"optimized", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
					"arm_conversion_matrix", "armv7-unknown-linux-gnueabihf", variant.ir, driver,
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
				t.Logf("LLVM22 matched original Go: %d rows, %d observed words", len(rows), len(rows)*10)
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixARMWordFloatAllPhysicalEndpoints(t *testing.T) {
	forms := armConversionRawMatrixForms()
	var rows []armConversionMatrixRow
	for index, form := range forms {
		values := []uint64{0x01000001, 0xfeffffff}
		if !form.toFloat {
			values = []uint64{0x3fc00000, 0x7fc12345}
			if form.double {
				values = []uint64{0x3ff8000000000000, 0x7ff8123456789abc}
			}
		}
		for i, bits := range values {
			control := uint32(i)<<22 | 0xa0000000 // Keep native NZCV canaries.
			rows = append(rows, armConversionMatrixRow{index, armConversionMatrixInput(form, bits, control)})
		}
	}
	runARMConversionMatrix(t, forms, rows)
}

func TestCrossLinuxRuntimeMatrixARMWordFloatDynamicStatus(t *testing.T) {
	forms := armConversionStatusMatrixForms()
	if len(forms) != 56 {
		t.Fatalf("incomplete R/F/S and conditional status matrix: %d", len(forms))
	}
	var rows []armConversionMatrixRow
	for index, form := range forms {
		for _, bits := range armConversionStatusMatrixValues(form) {
			for rounding := 0; rounding < 4; rounding++ {
				for flush := 0; flush < 2; flush++ {
					for defaultNaN := 0; defaultNaN < 2; defaultNaN++ {
						control := uint32(rounding)<<22 | uint32(flush)<<24 | uint32(defaultNaN)<<25 | 0xa0000000
						// Seed an unrelated cumulative exception on half the rows.
						// Newly raised IOC/IXC/IDC must not erase it.
						if rounding&1 != 0 {
							control |= 2
						}
						rows = append(rows, armConversionMatrixRow{index, armConversionMatrixInput(form, bits, control)})
					}
				}
			}
		}
	}
	runARMConversionMatrix(t, forms, rows)
}
