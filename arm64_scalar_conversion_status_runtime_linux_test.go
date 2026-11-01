package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type arm64ScalarConversionObservation struct {
	function int
	input    [68]uint64
	want     [70]uint64
}

func arm64ScalarConversionKnownObservation(index int, fixture arm64ScalarConversionFixture, control uint64) arm64ScalarConversionObservation {
	row := arm64ScalarConversionObservation{function: index}
	for i := 0; i < 66; i++ {
		row.input[i] = 0x9876543200000000 + uint64(i)*0x01010101
	}
	value, result, flags := uint64(0x3ff8000000000000), uint64(1), uint64(0x10)
	if fixture.floatBits == 32 {
		value = 0x3fc00000
	} else if fixture.floatBits == 16 {
		value = 0x3e00
	}
	if fixture.rounding < 3 {
		result = 2 // N/A/P of positive 1.5; M/Z produce 1.
	}
	if fixture.toFloat {
		value, result = 1<<24|1, 0x4b800000
		if fixture.floatBits == 16 {
			value, result = 2049, 0x6800
		} else if fixture.floatBits == 64 {
			if fixture.integerBits == 64 {
				value, result = 1<<53|1, 0x4340000000000000
			} else {
				value, result, flags = 1<<24|1, 0x4170000010000000, 0
			}
		}
		if control>>22&3 == 1 && flags != 0 {
			result++ // Round toward positive infinity; other modes round down here.
		}
	}
	row.input[fixture.sourceWord()] = value
	if fixture.zero && fixture.toFloat {
		result, flags = 0, 0
	}
	copy(row.want[:66], row.input[:66])
	if !fixture.dead {
		if fixture.toFloat || fixture.simd {
			word := fixture.resultWord()
			row.want[word], row.want[word+1] = result, 0
		} else if !fixture.zero {
			row.want[65] = result
		}
	}
	row.input[66], row.input[67] = control, 0x08000002
	row.want[66], row.want[67] = control, row.input[67]|flags
	row.want[68], row.want[69] = 0x123456789abcdef0, 0xfedcba9876543210
	return row
}

func arm64ScalarConversionPrograms(fixtures []arm64ScalarConversionFixture, rows []arm64ScalarConversionObservation) (string, string) {
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range fixtures {
		fmt.Fprintf(&original, "func scalarStatus%d(*[68]uint64,*[70]uint64)\n", index)
		fmt.Fprintf(&driver, "extern void scalarStatus%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("var functions = [...]func(*[68]uint64,*[70]uint64){\n")
	driver.WriteString("static void (*functions[])(uint64_t*,uint64_t*)={\n")
	for index := range fixtures {
		fmt.Fprintf(&original, "scalarStatus%d,\n", index)
		fmt.Fprintf(&driver, "scalarStatus%d,\n", index)
	}
	original.WriteString("}\ntype change struct { index int; value uint64 }\nvar rows = []struct { function int; input,want [4]change }{\n")
	driver.WriteString("};\nstruct change { int index; uint64_t value; };\nstatic const struct { unsigned function; struct change input[4],want[4]; } rows[]={\n")
	for _, row := range rows {
		// Lossless sparse encoding keeps generated compiler inputs bounded;
		// every runtime still compares all 70 words, never just the changes.
		var baseline [68]uint64
		for index := 0; index < 66; index++ {
			baseline[index] = 0x9876543200000000 + uint64(index)*0x01010101
		}
		var expected [70]uint64
		copy(expected[:68], row.input[:])
		expected[68], expected[69] = 0x123456789abcdef0, 0xfedcba9876543210
		fmt.Fprintf(&original, "{%d,", row.function)
		fmt.Fprintf(&driver, "{%d,", row.function)
		for _, pair := range []struct{ base, actual []uint64 }{{baseline[:], row.input[:]}, {expected[:], row.want[:]}} {
			original.WriteString("[4]change{")
			driver.WriteString("{")
			count := 0
			for index, value := range pair.actual {
				if value != pair.base[index] {
					fmt.Fprintf(&original, "{%d,%#x},", index, value)
					fmt.Fprintf(&driver, "{%d,%#xULL},", index, value)
					count++
				}
			}
			if count > 4 {
				panic("scalar conversion fixture exceeds its lossless sparse row encoding")
			}
			for ; count < 4; count++ {
				original.WriteString("{-1,0},")
				driver.WriteString("{-1,0},")
			}
			original.WriteString("},")
			driver.WriteString("},")
		}
		original.WriteString("},\n")
		driver.WriteString("},\n")
	}
	original.WriteString(`}
func main() {
    for index, row := range rows {
        var input [68]uint64
        for word:=0;word<66;word++ { input[word]=0x9876543200000000+uint64(word)*0x01010101 }
        for _,change:=range row.input { if change.index>=0 { input[change.index]=change.value } }
        var out,want [70]uint64
        copy(want[:68],input[:])
        out[68],out[69] = 0x123456789abcdef0,0xfedcba9876543210
        want[68],want[69] = out[68],out[69]
        for _,change:=range row.want { if change.index>=0 { want[change.index]=change.value } }
        functions[row.function](&input,&out)
        if out != want { panic(fmt.Sprintf("original row %d function %d got %x want %x",index,row.function,out,want)) }
    }
    fmt.Printf("ORIGINAL_ARM64_SCALAR_STATUS %d\n",len(rows))
}
`)
	driver.WriteString(`};
int main(void) {
    unsigned failures=0;
    for(unsigned row=0;row<sizeof(rows)/sizeof(rows[0]);row++) {
        uint64_t input[68]={0},out[70]={0},want[70]={0};
        for(unsigned word=0;word<66;word++) input[word]=0x9876543200000000ULL+(uint64_t)word*0x01010101;
        for(unsigned i=0;i<4;i++) {
            struct change change=rows[row].input[i];
            if(change.index>=0) input[change.index]=change.value;
        }
        for(unsigned word=0;word<68;word++) want[word]=input[word];
        out[68]=want[68]=0x123456789abcdef0ULL;
        out[69]=want[69]=0xfedcba9876543210ULL;
        for(unsigned i=0;i<4;i++) {
            struct change change=rows[row].want[i];
            if(change.index>=0) want[change.index]=change.value;
        }
        functions[rows[row].function](input,out);
        for(unsigned word=0;word<70;word++) {
            if(out[word]!=want[word]) {
                if(failures<16) fprintf(stderr,"row %u function %u word %u got %016llx want %016llx\n",
                    row,rows[row].function,word,(unsigned long long)out[word],(unsigned long long)want[word]);
                failures++;
            }
        }
    }
    printf("ARM64_SCALAR_STATUS failures=%u\n",failures);
    return failures!=0;
}
`)
	return original.String(), driver.String()
}

func runARM64ScalarConversionObservations(t *testing.T, fixtures []arm64ScalarConversionFixture, rows []arm64ScalarConversionObservation) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("native FPCR/FPSR execution belongs to the required Linux/QEMU matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("ARM64 conversion runtime requires the Linux/amd64 cross executor")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"qemu-aarch64", "aarch64-linux-gnu-gcc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("QEMU_CPU", "max")
	source, sigs := arm64ScalarConversionSource(fixtures)
	original, driver := arm64ScalarConversionPrograms(fixtures, rows)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module scalarstatusoracle\n\ngo 1.20\n", "main.go": original,
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT scalarStatus", "TEXT ·scalarStatus"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "-p=1", "-exec=qemu-aarch64", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || !strings.Contains(string(output), fmt.Sprintf("ORIGINAL_ARM64_SCALAR_STATUS %d", len(rows))) {
		t.Fatalf("actual Go object / independent values and flags: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR_%s/backend_O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-no-pie"},
					"arm64_scalar_status", triple, variant.ir, driver,
					[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"}, level)
				t.Logf("matched original Go: %d whole-vector/GP/FPCR/FPSR/canary observations", len(rows))
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64ScalarConversionNativeStatus(t *testing.T) {
	fixtures := arm64ScalarConversionFixtures()
	for _, fixture := range append([]arm64ScalarConversionFixture(nil), fixtures...) {
		fixture.dead = true
		fixtures = append(fixtures, fixture)
	}
	var rows []arm64ScalarConversionObservation
	for index, fixture := range fixtures {
		for rounding := 0; rounding < 4; rounding++ {
			for flush := 0; flush < 2; flush++ {
				for defaultNaN := 0; defaultNaN < 2; defaultNaN++ {
					control := uint64(rounding)<<22 | uint64(flush)<<24 | uint64(defaultNaN)<<25
					rows = append(rows, arm64ScalarConversionKnownObservation(index, fixture, control))
				}
			}
		}
	}
	runARM64ScalarConversionObservations(t, fixtures, rows)
}

func TestCrossLinuxRuntimeMatrixARM64ScalarConversionBanksAliasesAndZR(t *testing.T) {
	requireARM64ScalarConversionBankPartition(t)
	totalRows := 0
	for batch, fixtures := range arm64ScalarConversionBankPartitions() {
		t.Run(fmt.Sprintf("batch_%d", batch), func(t *testing.T) {
			var rows []arm64ScalarConversionObservation
			for index, fixture := range fixtures {
				for _, control := range []uint64{0, 0x03400000} {
					rows = append(rows, arm64ScalarConversionKnownObservation(index, fixture, control))
				}
			}
			totalRows += len(rows)
			// Each child closes its temporary Go/LLVM/native files before the
			// next batch. The IR optimizer already disposes module then context.
			runARM64ScalarConversionObservations(t, fixtures, rows)
		})
	}
	if totalRows != 1712 {
		t.Fatalf("bank runtime omitted rows: %d, want 1712", totalRows)
	}
}
