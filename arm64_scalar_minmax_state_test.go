package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type arm64MinMaxStateCase struct {
	arm64MinMaxCase
	first, second, destination int
	destructive, dead          bool
}

type arm64MinMaxSample struct {
	a, b, control, status uint64
}

func arm64MinMaxStateCases(banks bool) []arm64MinMaxStateCase {
	var cases []arm64MinMaxStateCase
	for _, row := range arm64MinMaxCases() {
		if !banks {
			for _, dead := range []bool{false, true} {
				cases = append(cases, arm64MinMaxStateCase{row, 0, 1, 2, false, dead})
			}
			continue
		}
		// Independent axes: every physical register in every operand position;
		// all aliases additionally at low/middle/high banks, not a huge product.
		for bank := 0; bank < 32; bank++ {
			cases = append(cases, arm64MinMaxStateCase{row, bank, (bank + 1) % 32, (bank + 2) % 32, false, false})
		}
		for _, bank := range []int{0, 15, 31} {
			other := (bank + 1) % 32
			cases = append(cases,
				arm64MinMaxStateCase{row, bank, other, bank, row.word == 0, false},
				arm64MinMaxStateCase{row, bank, other, other, false, false},
				arm64MinMaxStateCase{row, bank, bank, bank, false, false},
			)
		}
	}
	return cases
}

func arm64MinMaxSamples(bits int, banks bool) []arm64MinMaxSample {
	values := arm64CompareValues(bits) // Independent integer IEEE input patterns.
	if banks {
		return []arm64MinMaxSample{{values[2], values[3], 0, 0x08000082}, {values[2], values[3], 4, 0x08000082}}
	}
	pairs := [][2]int{{0, 1}, {1, 0}, {2, 3}, {3, 2}, {4, 5}, {5, 4},
		{6, 2}, {2, 6}, {8, 2}, {2, 8}, {6, 8}, {8, 6}, {7, 9}, {9, 7},
		{10, 0}, {0, 10}, {11, 1}, {1, 11}, {12, 13}, {13, 12}}
	var result []arm64MinMaxSample
	for _, pair := range pairs {
		for controls := 0; controls < 16; controls++ {
			control := uint64(controls&1)<<24 | uint64((controls>>1)&1)<<25 |
				uint64((controls>>2)&1)<<2 | uint64((controls>>3)&1)<<1
			if bits == 16 && controls&1 != 0 {
				control |= 1 << 19
			}
			status := uint64(0x08000002)
			if controls&1 != 0 {
				status |= 0x81
			}
			result = append(result, arm64MinMaxSample{values[pair[0]], values[pair[1]], control, status})
		}
	}
	for rounding := 0; rounding < 4; rounding++ {
		result = append(result, arm64MinMaxSample{values[10], values[11], uint64(rounding)<<22 | 7, 0x08000082})
	}
	return result
}

func arm64MinMaxStateSource(cases []arm64MinMaxStateCase) (string, map[string]FuncSig) {
	var source strings.Builder
	signatures := make(map[string]FuncSig)
	for index, row := range cases {
		name := fmt.Sprintf("minmaxState%d", index)
		signatures[name] = arm64SM3Signature(name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.B16]\n", bank)
		}
		source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMOVD (R0),R12\nMSR R12,FPCR\nMOVD 8(R0),R12\nMSR R12,FPSR\nCMP R0,R0\n")
		source.WriteString(row.instruction(row.first, row.second, row.destination, row.destructive) + "\n")
		if row.dead {
			fmt.Fprintf(&source, "VEOR V%d.B16,V%d.B16,V%d.B16\n", row.destination, row.destination, row.destination)
		}
		// Consume the source NZCV bank through CSET, as the existing compare
		// oracle does. Native MRS NZCV has a separate physical-state contract.
		source.WriteString("CSET MI,R4\nLSL $31,R4,R4\nCSET EQ,R5\nLSL $30,R5,R5\nORR R5,R4,R4\nCSET CS,R5\nLSL $29,R5,R5\nORR R5,R4,R4\nCSET VS,R5\nLSL $28,R5,R5\nORR R5,R4,R4\nMRS FPCR,R2\nMRS FPSR,R3\n")
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "VST1.P [V%d.B16],16(R1)\n", bank)
		}
		source.WriteString("MOVD R3,(R1)\nMOVD R2,8(R1)\nMOVD R4,16(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return source.String(), signatures
}

func arm64MinMaxOriginalOutput(t *testing.T, source, program, goos string, runner []string) []byte {
	t.Helper()
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module minmaxoracle\n\ngo 1.20\n", "main.go": program,
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT minmaxState", "TEXT ·minmaxState"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	arguments := []string{"run", "-p=1"}
	if len(runner) != 0 {
		arguments = append(arguments, "-exec="+strings.Join(runner, " "))
	}
	command := exec.CommandContext(ctx, "go", append(arguments, ".")...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual original min/max program: %v\n%s", err, output)
	}
	return output
}

func arm64MinMaxStatePrograms(cases []arm64MinMaxStateCase, banks bool, expectedPath string) (string, string, int) {
	var original, driver strings.Builder
	original.WriteString("package main\nimport (\"encoding/binary\";\"os\")\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range cases {
		fmt.Fprintf(&original, "func minmaxState%d(*[66]uint64,*[69]uint64)\n", index)
		fmt.Fprintf(&driver, "extern void minmaxState%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("var functions = [...]func(*[66]uint64,*[69]uint64){\n")
	driver.WriteString("static void (*functions[])(uint64_t*,uint64_t*)={\n")
	for index := range cases {
		fmt.Fprintf(&original, "minmaxState%d,\n", index)
		fmt.Fprintf(&driver, "minmaxState%d,\n", index)
	}
	original.WriteString("}\nvar forms=[]struct{ bits,first,second int }{\n")
	driver.WriteString("};\nstatic const struct{unsigned bits,first,second;} forms[]={\n")
	for _, row := range cases {
		fmt.Fprintf(&original, "{%d,%d,%d},\n", row.bits, row.first, row.second)
		fmt.Fprintf(&driver, "{%d,%d,%d},\n", row.bits, row.first, row.second)
	}
	original.WriteString("}\nvar samples=[]struct{bits int;a,b,control,status uint64}{\n")
	driver.WriteString("};\nstatic const struct{unsigned bits;uint64_t a,b,control,status;} samples[]={\n")
	for _, bits := range []int{16, 32, 64} {
		for _, sample := range arm64MinMaxSamples(bits, banks) {
			fmt.Fprintf(&original, "{%d,%#x,%#x,%#x,%#x},\n", bits, sample.a, sample.b, sample.control, sample.status)
			fmt.Fprintf(&driver, "{%d,%#xULL,%#xULL,%#xULL,%#xULL},\n", bits, sample.a, sample.b, sample.control, sample.status)
		}
	}
	original.WriteString(`}
func main() {
    for index,form:=range forms {
        for _,sample:=range samples {
            if sample.bits!=form.bits { continue }
            var input [66]uint64
            for word:=0;word<64;word++ { input[word]=0x123456789abcdef0+uint64(word)*0x0102030405060708 }
            mask:=^uint64(0)
            if form.bits<64 { mask=(uint64(1)<<form.bits)-1 }
            input[2*form.first]=input[2*form.first]&^mask|sample.a
            if form.first!=form.second { input[2*form.second]=input[2*form.second]&^mask|sample.b }
            input[64],input[65]=sample.control,sample.status
            before:=input
            var output [69]uint64
            output[67],output[68]=0x123456789abcdef0,0xfedcba9876543210
            functions[index](&input,&output)
            if input!=before { panic("original modified input") }
            if err:=binary.Write(os.Stdout,binary.LittleEndian,output);err!=nil { panic(err) }
        }
    }
}
`)
	fmt.Fprintf(&driver, "};\nint main(void) { FILE* expected=fopen(%q,\"rb\"); if(!expected)return 2;unsigned count=0;\n", expectedPath)
	driver.WriteString(`
    for(unsigned index=0;index<sizeof(forms)/sizeof(forms[0]);index++) {
        for(unsigned sample=0;sample<sizeof(samples)/sizeof(samples[0]);sample++) {
            if(samples[sample].bits!=forms[index].bits) continue;
            uint64_t input[66]={0},output[69]={0},before[66],want[69];
            for(unsigned word=0;word<64;word++) input[word]=0x123456789abcdef0ULL+(uint64_t)word*0x0102030405060708ULL;
            uint64_t mask=UINT64_MAX;
            if(forms[index].bits<64) mask=(UINT64_C(1)<<forms[index].bits)-1;
            unsigned first=2*forms[index].first,second=2*forms[index].second;
            input[first]=(input[first]&~mask)|samples[sample].a;
            if(first!=second) input[second]=(input[second]&~mask)|samples[sample].b;
            input[64]=samples[sample].control;input[65]=samples[sample].status;
            for(unsigned word=0;word<66;word++) before[word]=input[word];
            output[67]=0x123456789abcdef0ULL;output[68]=0xfedcba9876543210ULL;
            if(fread(want,sizeof(uint64_t),69,expected)!=69) return 3;
            functions[index](input,output);
            for(unsigned word=0;word<66;word++) if(input[word]!=before[word]) return 4;
            for(unsigned word=0;word<69;word++) {
                if(output[word]!=want[word]) {
                    fprintf(stderr,"form=%u sample=%u word=%u got=%llx want=%llx\n",index,sample,word,(unsigned long long)output[word],(unsigned long long)want[word]);
                    return 1;
                }
            }
            count++;
        }
    }
    if(fgetc(expected)!=EOF || fclose(expected)) return 5;
    printf("ARM64_MINMAX_TRANSLATED_PASS %u\n",count);
    return 0;
}
`)
	count := 0
	for _, row := range cases {
		count += len(arm64MinMaxSamples(row.bits, banks))
	}
	return original.String(), driver.String(), count
}

func arm64MinMaxCheckOriginalState(t *testing.T, cases []arm64MinMaxStateCase, banks bool, output []byte) (nep, ah int) {
	t.Helper()
	position := 0
	for _, row := range cases {
		for _, sample := range arm64MinMaxSamples(row.bits, banks) {
			if len(output)-position < 69*8 {
				t.Fatal("original min/max output is truncated")
			}
			var got [69]uint64
			for index := range got {
				got[index] = binary.LittleEndian.Uint64(output[position : position+8])
				position += 8
			}
			if got[66] != 0x60000000 || got[67] != 0x123456789abcdef0 || got[68] != 0xfedcba9876543210 || got[64]&sample.status != sample.status {
				t.Fatalf("original min/max changed NZCV/canary/cumulative status: %x", got[64:])
			}
			mask := ^uint64(0)
			if row.bits < 64 {
				mask = uint64(1)<<uint(row.bits) - 1
			}
			for word := 0; word < 64; word++ {
				want := uint64(0x123456789abcdef0) + uint64(word)*0x0102030405060708
				if word == 2*row.first {
					want = want&^mask | sample.a
				} else if word == 2*row.second {
					want = want&^mask | sample.b
				}
				if word/2 != row.destination && got[word] != want {
					t.Fatalf("original min/max corrupted non-destination bank %d: got=%x want=%x", word, got[word], want)
				}
			}
			if row.dead {
				if got[2*row.destination] != 0 || got[2*row.destination+1] != 0 {
					t.Fatal("original dead-destination fixture did not overwrite the complete vector")
				}
				continue
			}
			upperLow, upperHigh := uint64(0), uint64(0)
			if got[65]&4 != 0 {
				upperLow = (uint64(0x123456789abcdef0) + uint64(2*row.first)*0x0102030405060708) &^ mask
				upperHigh = uint64(0x123456789abcdef0) + uint64(2*row.first+1)*0x0102030405060708
				nep++ // Actual nonzero first-source merge, checked below.
			}
			if got[2*row.destination]&^mask != upperLow || got[2*row.destination+1] != upperHigh {
				t.Fatalf("original NEP result is not first-source merge: %+v ctrl=%x result=%x", row, got[65], got[2*row.destination:2*row.destination+2])
			}
			isNumeric := strings.Contains(row.name, "NM")
			sign := uint64(1) << uint(row.bits-1)
			if !isNumeric && sample.a&^sign == 0 && sample.b&^sign == 0 && row.first != row.second {
				want := sample.a & sample.b // FMAX prefers positive zero.
				if strings.HasPrefix(row.name, "FMIN") {
					want = sample.a | sample.b
				}
				if got[65]&2 != 0 {
					if want != sample.b {
						ah++ // Exact AH result differs from the standard rule.
					}
					want = sample.b
				}
				if got[2*row.destination]&mask != want {
					t.Fatalf("original AH/zero behavior mismatch: %+v ctrl=%x got=%x want=%x", row, got[65], got[2*row.destination]&mask, want)
				}
			}
		}
	}
	if position != len(output) {
		t.Fatal("unexpected extra original min/max transcript bytes")
	}
	return nep, ah
}

func arm64MinMaxFamilyStateCases(banks bool, family string) []arm64MinMaxStateCase {
	var selected []arm64MinMaxStateCase
	for _, row := range arm64MinMaxStateCases(banks) {
		name := strings.TrimSuffix(strings.TrimSuffix(row.name, "S"), "D")
		if family == "" || name == family {
			selected = append(selected, row)
		}
	}
	return selected
}

func arm64MinMaxStateRuntimeFamily(t *testing.T, triple, goos string, compiler, runner []string, family string, requireAFP bool) {
	t.Helper()
	if family != "FMAX" && family != "FMIN" && family != "FMAXNM" && family != "FMINNM" {
		t.Fatal("unknown min/max runtime partition", family)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	total, nep, ah := 0, 0, 0
	for _, banks := range []bool{true, false} {
		cases := arm64MinMaxFamilyStateCases(banks, family)
		for first := 0; first < len(cases); first += 32 {
			last := first + 32
			if last > len(cases) {
				last = len(cases)
			}
			t.Run(fmt.Sprintf("banks=%t/batch%d", banks, first/32), func(t *testing.T) {
				batch := cases[first:last]
				source, signatures := arm64MinMaxStateSource(batch)
				path := filepath.Join(t.TempDir(), "original.bin")
				original, driver, count := arm64MinMaxStatePrograms(batch, banks, path)
				started := time.Now()
				output := arm64MinMaxOriginalOutput(t, source, original, goos, runner)
				t.Logf("phase=original-Go elapsed=%s", time.Since(started))
				if len(output) != count*69*8 {
					t.Fatalf("actual Go output bytes=%d want=%d", len(output), count*69*8)
				}
				newNEP, newAH := arm64MinMaxCheckOriginalState(t, batch, banks, output)
				nep, ah = nep+newNEP, ah+newAH
				total += count
				t.Logf("actual original Go rows=%d NEP-merges=%d AH-differences=%d", count, newNEP, newAH)
				if err := os.WriteFile(path, output, 0600); err != nil {
					t.Fatal(err)
				}
				started = time.Now()
				irs := arm64MinMaxIRs(t, source, triple, signatures)
				t.Logf("phase=three-API-IR elapsed=%s", time.Since(started))
				for api, ir := range irs {
					for _, optimized := range []bool{false, true} {
						if optimized {
							started = time.Now()
							ir = armFloatEffectOptimizedIR(t, ir)
							t.Logf("phase=IR-O2 API=%d elapsed=%s", api, time.Since(started))
						}
						for _, level := range []int{0, 2} {
							t.Run(fmt.Sprintf("API%d/IR_O2=%t/backend_O%d", api, optimized, level), func(t *testing.T) {
								compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "minmax_state", triple, ir, driver, runner, level)
							})
						}
					}
				}
			})
		}
	}
	if total != 3650 {
		t.Fatal("changed complete min/max runtime denominator", total)
	}
	if requireAFP {
		if err := arm64MinMaxAFPObservationError(family, nep, ah); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("ARM64_MINMAX_FULL_STATE_PASS family=%q original=%d LLVM=%d NEP=%d AH=%d", family, total, total*12, nep, ah)
}

func arm64MinMaxAFPObservationError(family string, nep, ah int) error {
	// AH counts the ordinary FMAX/FMIN signed-zero witness, not every row
	// with AH enabled. Numeric partitions must still execute their complete
	// AH matrix and compare every result/status byte with the original Go.
	needsAH := family == "" || family == "FMAX" || family == "FMIN"
	if !needsAH && family != "FMAXNM" && family != "FMINNM" {
		return fmt.Errorf("unknown min/max AFP witness partition %q", family)
	}
	if nep <= 0 || ah < 0 || (needsAH && ah == 0) {
		return fmt.Errorf("required actual AFP semantic effects missing for %q: NEP=%d AH=%d", family, nep, ah)
	}
	return nil
}

// Keep the same complete native denominator as the Linux owners, split into
// independently schedulable roots rather than one 45-minute package occupant.
func TestARM64ScalarMinMaxNativeRuntimeFMAX(t *testing.T) {
	arm64MinMaxDarwinFamilyRuntime(t, "FMAX")
}

func TestARM64ScalarMinMaxNativeRuntimeFMIN(t *testing.T) {
	arm64MinMaxDarwinFamilyRuntime(t, "FMIN")
}

func TestARM64ScalarMinMaxNativeRuntimeFMAXNM(t *testing.T) {
	arm64MinMaxDarwinFamilyRuntime(t, "FMAXNM")
}

func TestARM64ScalarMinMaxNativeRuntimeFMINNM(t *testing.T) {
	arm64MinMaxDarwinFamilyRuntime(t, "FMINNM")
}

func arm64MinMaxDarwinFamilyRuntime(t *testing.T, family string) {
	t.Helper()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin native counterpart; required Linux/QEMU owner covers other hosts")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang required")
	}
	arm64MinMaxStateRuntimeFamily(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil, family, false)
}
