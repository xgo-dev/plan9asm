package plan9asm

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// Inputs and reference observations remain compact. The original Go program
// and C driver independently reconstruct and verify the entire D bank; only
// FPSCR/APSR need per-row reference storage. No software fcmp is the oracle.
type armCompareMatrixRow struct {
	function      int
	lhs, rhs      uint64
	control, apsr uint32
	want          [2]uint32
}

func armCompareMatrixValues(bits int) [][2]uint64 {
	if bits == 32 {
		return [][2]uint64{
			{0, 0x80000000}, {0x80000000, 0},
			{0x3f800000, 0x40000000}, {0xc0000000, 0xbf800000},
			{0x7f800000, 0xff800000}, {0xff800000, 0x7f800000},
			{1, 0}, {0x80000001, 0}, {0x007fffff, 0x00800000},
			{0x00800000, 0x007fffff}, {0x7fc12345, 0x3f800000},
			{0x3f800000, 0xffc54321}, {0x7f812345, 0x3f800000},
			{0x3f800000, 0xff812345}, {0x7fc12345, 0x7f812345},
		}
	}
	return [][2]uint64{
		{0, 0x8000000000000000}, {0x8000000000000000, 0},
		{0x3ff0000000000000, 0x4000000000000000}, {0xc000000000000000, 0xbff0000000000000},
		{0x7ff0000000000000, 0xfff0000000000000}, {0xfff0000000000000, 0x7ff0000000000000},
		{1, 0}, {0x8000000000000001, 0}, {0x000fffffffffffff, 0x0010000000000000},
		{0x0010000000000000, 0x000fffffffffffff}, {0x7ff8123456789abc, 0x3ff0000000000000},
		{0x3ff0000000000000, 0xfff854321abcdef0}, {0x7ff0123456789abc, 0x3ff0000000000000},
		{0x3ff0000000000000, 0xfff0123456789abc}, {0x7ff8123456789abc, 0x7ff0123456789abc},
	}
}

func armCompareMatrixControls() []uint32 {
	var controls []uint32
	for _, flush := range []uint32{0, 1 << 24} {
		for _, defaultNaN := range []uint32{0, 1 << 25} {
			for _, cumulative := range []uint32{0, 1, 0x80, 0x81} {
				// Seed unequal NZCV and an unrelated cumulative exception to
				// distinguish overwrite, preservation and inactive conditions.
				controls = append(controls, 0xa0000002|flush|defaultNaN|cumulative)
			}
		}
	}
	return controls
}

func armCompareMatrixRows(forms []armCompareMatrixForm, scope string) []armCompareMatrixRow {
	var rows []armCompareMatrixRow
	for index, form := range forms {
		values := armCompareMatrixValues(form.bits)
		controls := armCompareMatrixControls()
		statuses := []uint32{0x60000000}
		if scope == "banks" {
			// The full exceptional/state product is a separate required root.
			// Rotate finite, subnormal and NaN data through every bank/role.
			values = [][2]uint64{values[index%len(values)]}
			controls = []uint32{0xa0000002, 0xa3000083}
		}
		if scope == "conditions" {
			values = [][2]uint64{values[2], values[12]}
			controls = []uint32{0xa0000002, 0xa3000083}
			statuses = nil
			for flags := 0; flags < 16; flags++ {
				statuses = append(statuses, uint32(flags)<<28)
			}
		}
		for _, values := range values {
			for _, control := range controls {
				for _, apsr := range statuses {
					rows = append(rows, armCompareMatrixRow{function: index, lhs: values[0], rhs: values[1], control: control, apsr: apsr})
				}
			}
		}
	}
	return rows
}

func armCompareMatrixPrograms(forms []armCompareMatrixForm, rows []armCompareMatrixRow) (string, string) {
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range forms {
		fmt.Fprintf(&original, "func matrixCompare%d(input *[65]uint32, output *[69]uint32, apsr uint32)\n", index)
		fmt.Fprintf(&driver, "extern void matrixCompare%d(uint32_t*,uint32_t*,uint32_t);\n", index)
	}
	original.WriteString("var functions = [...]func(*[65]uint32,*[69]uint32,uint32){\n")
	driver.WriteString("static void (*functions[])(uint32_t*,uint32_t*,uint32_t)={\n")
	for index := range forms {
		fmt.Fprintf(&original, "matrixCompare%d,\n", index)
		fmt.Fprintf(&driver, "matrixCompare%d,\n", index)
	}
	original.WriteString("}\nvar forms = [...]struct { bits, lhs, rhs int; zero bool }{\n")
	driver.WriteString("};\nstatic const struct { unsigned bits,lhs,rhs,zero; } forms[]={\n")
	for _, form := range forms {
		zero := 0
		if form.zero {
			zero = 1
		}
		fmt.Fprintf(&original, "{%d,%d,%d,%t},\n", form.bits, form.lhs, form.rhs, form.zero)
		fmt.Fprintf(&driver, "{%d,%d,%d,%d},\n", form.bits, form.lhs, form.rhs, zero)
	}
	original.WriteString("}\nvar rows = [...]struct { function int; lhs,rhs uint64; control,apsr uint32 }{\n")
	driver.WriteString("};\nstatic const struct { unsigned function; uint64_t lhs,rhs; uint32_t control,apsr,want[2]; } rows[]={\n")
	for _, row := range rows {
		fmt.Fprintf(&original, "{%d,%#x,%#x,%#x,%#x},\n", row.function, row.lhs, row.rhs, row.control, row.apsr)
		fmt.Fprintf(&driver, "{%d,UINT64_C(%#x),UINT64_C(%#x),%#x,%#x,{%#x,%#x}},\n", row.function, row.lhs, row.rhs, row.control, row.apsr, row.want[0], row.want[1])
	}
	original.WriteString(`}
func put(input *[65]uint32, bits, register int, value uint64) {
    if bits == 64 {
        input[register*2],input[register*2+1] = uint32(value),uint32(value>>32)
    } else {
        input[register] = uint32(value)
    }
}
func main() {
    for index,row := range rows {
        form := forms[row.function]
        var input [65]uint32
        for word:=0;word<64;word++ { input[word]=0x98760000+uint32(word)*0x0101 }
        put(&input,form.bits,form.lhs,row.lhs)
        if !form.zero && form.lhs!=form.rhs { put(&input,form.bits,form.rhs,row.rhs) }
        input[64]=row.control
        before:=input
        var output [69]uint32
        for word:=range output { output[word]=0xa5a5a5a5 }
        output[65],output[66],output[67],output[68]=0x12345678,0x87654321,0xfedcba98,0x10203040
        functions[row.function](&input,&output,row.apsr)
        if input!=before { panic(fmt.Sprintf("original input changed at row %d",index)) }
        for word:=0;word<64;word++ {
            if output[word]!=input[word] {
                panic(fmt.Sprintf("original row %d bank word %d got %08x want %08x",index,word,output[word],input[word]))
            }
        }
        if output[66]!=0x87654321 || output[67]!=0xfedcba98 || output[68]!=0x10203040 {
            panic(fmt.Sprintf("original output canary changed at row %d",index))
        }
        fmt.Printf("%08x %08x\n",output[64],output[65])
    }
}
`)
	driver.WriteString(`};
static void put(uint32_t *input,unsigned bits,unsigned reg,uint64_t value) {
    if(bits==64) { input[reg*2]=(uint32_t)value; input[reg*2+1]=(uint32_t)(value>>32); }
    else input[reg]=(uint32_t)value;
}
int main(void) {
    unsigned failures=0;
    for(unsigned row=0;row<sizeof(rows)/sizeof(rows[0]);row++) {
        unsigned function=rows[row].function;
        uint32_t input[65],before[65],output[69];
        for(unsigned word=0;word<64;word++) input[word]=0x98760000+word*0x0101;
        put(input,forms[function].bits,forms[function].lhs,rows[row].lhs);
        if(!forms[function].zero && forms[function].lhs!=forms[function].rhs)
            put(input,forms[function].bits,forms[function].rhs,rows[row].rhs);
        input[64]=rows[row].control;
        for(unsigned word=0;word<65;word++) before[word]=input[word];
        for(unsigned word=0;word<69;word++) output[word]=0xa5a5a5a5;
        output[65]=0x12345678; output[66]=0x87654321;
        output[67]=0xfedcba98; output[68]=0x10203040;
        functions[function](input,output,rows[row].apsr);
        for(unsigned word=0;word<65;word++) {
            if(input[word]!=before[word]) {
                if(failures<16) fprintf(stderr,"row %u input word %u changed\n",row,word);
                failures++;
            }
        }
        for(unsigned word=0;word<69;word++) {
            uint32_t expected=word<64?before[word]:word<66?rows[row].want[word-64]:
                word==66?0x87654321:word==67?0xfedcba98:0x10203040;
            if(output[word]!=expected) {
                if(failures<16) fprintf(stderr,"row %u function %u word %u got %08x want %08x\n",
                    row,function,word,output[word],expected);
                failures++;
            }
        }
    }
    printf("ARM_COMPARE_MATRIX rows=%zu failures=%u\n",sizeof(rows)/sizeof(rows[0]),failures);
    return failures!=0;
}
`)
	return original.String(), driver.String()
}

func runARMCompareMatrixBatch(t *testing.T, forms []armCompareMatrixForm, scope string) {
	t.Helper()
	llc := requireARMScalarRuntime(t)
	source, sigs := armCompareMatrixSource(forms, true)
	rows := armCompareMatrixRows(forms, scope)
	original, _ := armCompareMatrixPrograms(forms, rows)
	observed := armConversionGoObservations(t, source, original)
	reader := strings.NewReader(string(observed))
	for index := range rows {
		if _, err := fmt.Fscanf(reader, "%x %x\n", &rows[index].want[0], &rows[index].want[1]); err != nil {
			t.Fatalf("original Go row %d of %d: %v\n%s", index, len(rows), err, observed)
		}
		form := forms[rows[index].function]
		if !form.live && rows[index].want[1] != 0x12345678 {
			t.Fatalf("dead APSR observation was unexpectedly written at original row %d", index)
		}
	}
	if extra, err := io.ReadAll(reader); err != nil || strings.TrimSpace(string(extra)) != "" {
		t.Fatalf("original Go returned extra/invalid observations: %q: %v", extra, err)
	}
	t.Logf("original Go: %d rows with all 32 D banks, input and output canaries", len(rows))
	_, driver := armCompareMatrixPrograms(forms, rows)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(api, func(t *testing.T) {
			ir, err := armCompareMatrixTranslate(t, file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs}, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR_%s/backend_O%d", variant.name, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
							"arm_compare_matrix", "armv7-unknown-linux-gnueabihf", variant.ir, driver,
							[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
					})
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARMScalarCompareFullMatrix(t *testing.T) {
	requireARMScalarRuntime(t)
	for _, group := range []struct {
		name  string
		forms []armCompareMatrixForm
	}{
		{"banks", armCompareMatrixBanks()},
		{"states", armCompareMatrixStates()},
		{"conditions", armCompareMatrixConditions()},
	} {
		for first := 0; first < len(group.forms); first += 32 {
			last := first + 32
			if last > len(group.forms) {
				last = len(group.forms)
			}
			t.Run(fmt.Sprintf("%s/%03d_%03d", group.name, first, last), func(t *testing.T) {
				runARMCompareMatrixBatch(t, group.forms[first:last], group.name)
			})
		}
	}
}
