package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

type armNEONConversionObservation struct {
	function int
	input    [65]uint32
	want     [68]uint32
}

func armNEONConversionKnownObservation(index int, fixture armNEONConversionFixture, control uint32) armNEONConversionObservation {
	row := armNEONConversionObservation{function: index}
	for word := 0; word < 64; word++ {
		row.input[word] = 0x98760000 + uint32(word)*0x0101
	}
	values := [4]uint32{0x3fc00000, 0x7fc12345, 0x4f800000, 1}
	results := [4]uint32{1, 0, 0x7fffffff, 0}
	flags := uint32(0x11) // Fractional input and qNaN: IXC | IOC.
	if fixture.unsigned {
		results[2] = 0xffffffff
	}
	if fixture.quad {
		flags |= 0x80 // Advanced SIMD flushes the subnormal input: IDC.
	}
	if fixture.toFloat {
		values = [4]uint32{0x01000001, 0xfeffffff, 0x80000001, 0xffffffff}
		for lane, value := range values {
			floating := float32(int32(value))
			if fixture.unsigned {
				floating = float32(value)
			}
			results[lane] = math.Float32bits(floating)
		}
		flags = 0x10 // Advanced SIMD always uses nearest, independent of FPSCR.
	}
	lanes := 2
	if fixture.quad {
		lanes = 4
	}
	copy(row.input[fixture.source*2:], values[:lanes])
	copy(row.want[:64], row.input[:64])
	if !fixture.dead {
		copy(row.want[fixture.target*2:], results[:lanes])
	}
	row.input[64] = control
	row.want[64] = control | flags
	row.want[65], row.want[66], row.want[67] = 0x12345678, 0x87654321, 0xfedcba98
	return row
}

// This bounded independent oracle follows A2.7 FPToFixed/FixedToFP with the
// Advanced SIMD standard controls: nearest int->float, truncating float->int,
// flushed input denormals, saturating invalid results, and cumulative flags.
// It is test-only; production must execute native VCVT, not synthesize FPSCR.
func armNEONConversionReference(fixture armNEONConversionFixture, bits uint32) (uint32, uint32) {
	if fixture.toFloat {
		integer := float64(int32(bits))
		if fixture.unsigned {
			integer = float64(bits)
		}
		value := float32(integer)
		flags := uint32(0)
		if float64(value) != integer {
			flags = 0x10
		}
		return math.Float32bits(value), flags
	}
	if bits&0x7f800000 == 0 && bits&0x007fffff != 0 {
		return 0, 0x80
	}
	value := float64(math.Float32frombits(bits))
	if math.IsNaN(value) {
		return 0, 1
	}
	minimum, maximum := -2147483648.0, 2147483647.0
	if fixture.unsigned {
		minimum, maximum = 0, 4294967295.0
	}
	truncated := math.Trunc(value)
	if truncated < minimum {
		if fixture.unsigned {
			return 0, 1
		}
		return 0x80000000, 1
	}
	if truncated > maximum {
		if fixture.unsigned {
			return 0xffffffff, 1
		}
		return 0x7fffffff, 1
	}
	flags := uint32(0)
	if truncated != value {
		flags = 0x10
	}
	if fixture.unsigned {
		return uint32(truncated), flags
	}
	return uint32(int32(truncated)), flags
}

func armNEONConversionDynamicObservation(index int, fixture armNEONConversionFixture, values [4]uint32, control uint32) armNEONConversionObservation {
	row := armNEONConversionObservation{function: index}
	for word := 0; word < 64; word++ {
		row.input[word] = 0x87650000 + uint32(word)*0x0101
	}
	lanes := 2
	if fixture.quad {
		lanes = 4
	}
	copy(row.input[fixture.source*2:], values[:lanes])
	copy(row.want[:64], row.input[:64])
	flags := uint32(0)
	for lane := 0; lane < lanes; lane++ {
		result, exceptions := armNEONConversionReference(fixture, values[lane])
		flags |= exceptions
		if !fixture.dead {
			row.want[fixture.target*2+lane] = result
		}
	}
	row.input[64], row.want[64] = control, control|flags
	row.want[65], row.want[66], row.want[67] = 0x12345678, 0x87654321, 0xfedcba98
	return row
}

func armNEONConversionOraclePrograms(fixtures []armNEONConversionFixture, rows []armNEONConversionObservation) (string, string) {
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range fixtures {
		fmt.Fprintf(&original, "func neonStatus%d(input *[65]uint32, output *[68]uint32)\n", index)
		fmt.Fprintf(&driver, "extern void neonStatus%d(uint32_t*,uint32_t*);\n", index)
	}
	original.WriteString("var functions = [...]func(*[65]uint32,*[68]uint32){\n")
	driver.WriteString("static void (*functions[])(uint32_t*,uint32_t*)={\n")
	for index := range fixtures {
		fmt.Fprintf(&original, "neonStatus%d,\n", index)
		fmt.Fprintf(&driver, "neonStatus%d,\n", index)
	}
	original.WriteString("}\nvar rows = []struct { function int; input [65]uint32; want [68]uint32 }{\n")
	driver.WriteString("};\nstatic const struct { unsigned function; uint32_t input[65], want[68]; } rows[]={\n")
	for _, row := range rows {
		fmt.Fprintf(&original, "{%d,[65]uint32{", row.function)
		fmt.Fprintf(&driver, "{%d,{", row.function)
		for _, value := range row.input {
			fmt.Fprintf(&original, "%#x,", value)
			fmt.Fprintf(&driver, "%#x,", value)
		}
		original.WriteString("},[68]uint32{")
		driver.WriteString("},{")
		for _, value := range row.want {
			fmt.Fprintf(&original, "%#x,", value)
			fmt.Fprintf(&driver, "%#x,", value)
		}
		original.WriteString("}},\n")
		driver.WriteString("}},\n")
	}
	original.WriteString(`}
func main() {
    for index, row := range rows {
        var out [68]uint32
        for word := range out { out[word] = 0xa5a5a5a5 }
        out[65],out[66],out[67] = 0x12345678,0x87654321,0xfedcba98
        functions[row.function](&row.input,&out)
        if out != row.want { panic(fmt.Sprintf("original row %d got %x want %x",index,out,row.want)) }
    }
    fmt.Printf("ORIGINAL_NEON_CONVERSION_STATUS %d\n",len(rows))
}
`)
	driver.WriteString(`};
int main(void) {
    unsigned failures=0;
    for(unsigned row=0;row<sizeof(rows)/sizeof(rows[0]);row++) {
        uint32_t input[65],out[68];
        for(unsigned word=0;word<65;word++) input[word]=rows[row].input[word];
        for(unsigned word=0;word<68;word++) out[word]=0xa5a5a5a5;
        out[65]=0x12345678; out[66]=0x87654321; out[67]=0xfedcba98;
        functions[rows[row].function](input,out);
        for(unsigned word=0;word<68;word++) {
            if(out[word]!=rows[row].want[word]) {
                if(failures<16) fprintf(stderr,"row %u function %u word %u got %08x want %08x\n",
                    row,rows[row].function,word,out[word],rows[row].want[word]);
                failures++;
            }
        }
    }
    printf("NEON_CONVERSION_STATUS failures=%u\n",failures);
    return failures!=0;
}
`)
	return original.String(), driver.String()
}

func TestCrossLinuxRuntimeMatrixARMNEONConversionNativeStatus(t *testing.T) {
	fixtures := armNEONConversionStatusFixtures()
	var rows []armNEONConversionObservation
	for index, fixture := range fixtures {
		for rounding := 0; rounding < 4; rounding++ {
			for flush := 0; flush < 2; flush++ {
				for defaultNaN := 0; defaultNaN < 2; defaultNaN++ {
					control := uint32(rounding)<<22 | uint32(flush)<<24 | uint32(defaultNaN)<<25 | 0xa0000002
					rows = append(rows, armNEONConversionKnownObservation(index, fixture, control))
				}
			}
		}
	}
	runARMNEONConversionObservations(t, fixtures, rows)
}

func runARMNEONConversionObservations(t *testing.T, fixtures []armNEONConversionFixture, rows []armNEONConversionObservation) {
	t.Helper()
	llc := requireARMScalarRuntime(t)
	source, sigs := armNEONConversionFixtureSource(fixtures)
	original, driver := armNEONConversionOraclePrograms(fixtures, rows)
	runARMConversionGoOracle(t, source, original, fmt.Sprintf("ORIGINAL_NEON_CONVERSION_STATUS %d", len(rows)))
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
					"arm_neon_conversion_status", "armv7-unknown-linux-gnueabihf", variant.ir, driver,
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
				t.Logf("matched original Go: %d full-bank/result/FPSCR/canary rows", len(rows))
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixARMNEONConversionFullBanks(t *testing.T) {
	fixtures := armNEONConversionEndpointFixtures()
	var rows []armNEONConversionObservation
	for index, fixture := range fixtures {
		for _, control := range []uint32{0xa0000002, 0xabc00002} {
			rows = append(rows, armNEONConversionKnownObservation(index, fixture, control))
		}
	}
	runARMNEONConversionObservations(t, fixtures, rows)
}

func TestCrossLinuxRuntimeMatrixARMNEONConversionExceptionalInputs(t *testing.T) {
	fixtures := armNEONConversionStatusFixtures()
	var rows []armNEONConversionObservation
	for index, fixture := range fixtures {
		inputs := armConversionStatusMatrixValues(armConversionMatrixForm{toFloat: fixture.toFloat})
		// Each important input appears in every D/Q lane at least once. Pair
		// different exception classes rather than hiding them in splats.
		for first := range inputs {
			var values [4]uint32
			for lane := range values {
				values[lane] = uint32(inputs[(first+lane)%len(inputs)])
			}
			for rounding := 0; rounding < 4; rounding++ {
				for flush := 0; flush < 2; flush++ {
					for defaultNaN := 0; defaultNaN < 2; defaultNaN++ {
						control := uint32(rounding)<<22 | uint32(flush)<<24 | uint32(defaultNaN)<<25 | 0xa8000002
						rows = append(rows, armNEONConversionDynamicObservation(index, fixture, values, control))
					}
				}
			}
		}
	}
	runARMNEONConversionObservations(t, fixtures, rows)
}
