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
)

type arm64BinaryStateCase struct {
	kind, bits, first, second, destination int
	raw, destructive, dead, full           bool
}

func (row arm64BinaryStateCase) instruction() string {
	if row.raw {
		return fmt.Sprintf("WORD $%#08x", arm64BinaryTestWord(row.kind, row.bits, row.first, row.second, row.destination))
	}
	op := arm64BinaryTestKinds[row.kind].name + map[int]string{32: "S", 64: "D"}[row.bits]
	if row.destructive {
		return fmt.Sprintf("%s F%d,F%d", op, row.second, row.destination)
	}
	return fmt.Sprintf("%s F%d,F%d,F%d", op, row.second, row.first, row.destination)
}

func arm64BinaryStateCases() []arm64BinaryStateCase {
	var cases []arm64BinaryStateCase
	for kind := range arm64BinaryTestKinds {
		for _, bits := range []int{16, 32, 64} {
			for _, raw := range []bool{false, true} {
				if bits == 16 && !raw {
					continue
				}
				for _, dead := range []bool{false, true} {
					cases = append(cases, arm64BinaryStateCase{kind, bits, 0, 31, 15, raw, false, dead, true})
				}
				cases = append(cases,
					arm64BinaryStateCase{kind, bits, 15, 31, 15, raw, !raw, false, false},
					arm64BinaryStateCase{kind, bits, 15, 31, 31, raw, false, false, false},
					arm64BinaryStateCase{kind, bits, 15, 15, 15, raw, !raw, false, false},
				)
			}
		}
	}
	// Bank axes are shared across the typed family. Do not compile a separate
	// 32^3 Cartesian set for every spelling; the raw decoder covers it above.
	for bank := 0; bank < 32; bank++ {
		cases = append(cases, arm64BinaryStateCase{bank % 5, []int{16, 32, 64}[bank%3], bank, (bank + 1) % 32, (bank + 2) % 32, true, false, false, false})
	}
	return cases
}

type arm64BinarySample struct{ a, b, control, status uint64 }

func arm64BinarySamples(bits int, full bool) []arm64BinarySample {
	values := arm64CompareValues(bits)
	if !full {
		return []arm64BinarySample{{values[2], values[3], 0, 0x08000080}, {values[2], values[3], 4, 0x08000080}}
	}
	var pairs [][2]uint64
	for _, pair := range [][2]int{{0, 1}, {1, 0}, {2, 3}, {3, 2}, {2, 0}, {0, 0}, {4, 5}, {4, 4}, {4, 0},
		{6, 2}, {2, 6}, {8, 2}, {2, 8}, {6, 8}, {8, 6}, {7, 9}, {9, 7},
		{10, 2}, {2, 10}, {11, 2}, {12, 13}, {13, 12}, {14, 14}, {15, 14}} {
		pairs = append(pairs, [2]uint64{values[pair[0]], values[pair[1]]})
	}
	fraction, bias := uint(23), uint64(127)
	if bits == 16 {
		fraction, bias = 10, 15
	} else if bits == 64 {
		fraction, bias = 52, 1023
	}
	pairs = append(pairs, [2]uint64{values[2], (bias - uint64(fraction) - 1) << fraction}, // halfway addition
		[2]uint64{values[2], (bias + 1) << fraction},  // two: quotient/multiply
		[2]uint64{values[14], (bias + 1) << fraction}, // overflow
		[2]uint64{values[13], (bias + 1) << fraction}) // underflow edge
	var controls []uint64
	for rounding := 0; rounding < 4; rounding++ {
		for mode := 0; mode < 4; mode++ {
			control := uint64(rounding)<<22 | uint64(mode&1)<<24 | uint64(mode>>1)<<25
			if bits == 16 && mode&1 != 0 {
				control |= 1 << 19
			}
			controls = append(controls, control)
		}
	}
	controls = append(controls, 2, 4, 6, 1<<19) // AH, NEP, their combination, independent FZ16
	var samples []arm64BinarySample
	for _, pair := range pairs {
		for index, control := range controls {
			status := uint64(0x08000000)
			if index&1 != 0 {
				status |= 0x80
			}
			samples = append(samples, arm64BinarySample{pair[0], pair[1], control, status})
		}
	}
	return samples
}

func arm64BinaryStateSource(cases []arm64BinaryStateCase) (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("package compare\n")
	for index, row := range cases {
		name := fmt.Sprintf("compareBinaryState%d", index)
		fmt.Fprintf(&declarations, "func %s(*[66]uint64,*[69]uint64)\n", name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.B16]\n", bank)
		}
		source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMOVD (R0),R12\nMSR R12,FPCR\nMOVD 8(R0),R12\nMSR R12,FPSR\n")
		source.WriteString([]string{
			"CMP R0,R0\n", "MOVD $0,R2\nCMP $1,R2\n", "MOVD $2,R2\nCMP $1,R2\n",
			"MOVD $0x8000000000000000,R2\nCMP $1,R2\n",
		}[row.kind%4])
		source.WriteString(row.instruction() + "\n")
		if row.dead {
			fmt.Fprintf(&source, "VEOR V%d.B16,V%d.B16,V%d.B16\n", row.destination, row.destination, row.destination)
		}
		source.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET CS,R4\nCSET VS,R5\nLSL $3,R2,R2\nLSL $2,R3,R3\nLSL $1,R4,R4\nORR R3,R2,R2\nORR R4,R2,R2\nORR R5,R2,R2\nMRS FPSR,R3\nMRS FPCR,R4\n")
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "VST1.P [V%d.B16],16(R1)\n", bank)
		}
		source.WriteString("MOVD R3,(R1)\nMOVD R4,8(R1)\nMOVD R2,16(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return source.String(), declarations.String()
}

func arm64BinaryOriginalOutput(t *testing.T, source, program, goos string, runner []string) []byte {
	t.Helper()
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module binaryoracle\n\ngo 1.20\n", "main.go": program,
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT compare", "TEXT ·compare"),
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
		t.Fatalf("actual original scalar binary: %v\n%s", err, output)
	}
	return output
}

func arm64BinaryStatePrograms(cases []arm64BinaryStateCase, declarations, path string) (string, string, int) {
	var original, driver strings.Builder
	original.WriteString(strings.Replace(declarations, "package compare", "package main\nimport (\"encoding/binary\";\"os\")", 1))
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range cases {
		fmt.Fprintf(&driver, "extern void compareBinaryState%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("var functions=[]func(*[66]uint64,*[69]uint64){\n")
	driver.WriteString("static void (*functions[])(uint64_t*,uint64_t*)={\n")
	for index := range cases {
		fmt.Fprintf(&original, "compareBinaryState%d,\n", index)
		fmt.Fprintf(&driver, "compareBinaryState%d,\n", index)
	}
	original.WriteString("}\nvar forms=[]struct{bits,first,second,full int}{\n")
	driver.WriteString("};\nstatic const struct{unsigned bits,first,second,full;} forms[]={\n")
	for _, row := range cases {
		full := 0
		if row.full {
			full = 1
		}
		fmt.Fprintf(&original, "{%d,%d,%d,%d},\n", row.bits, row.first, row.second, full)
		fmt.Fprintf(&driver, "{%d,%d,%d,%d},\n", row.bits, row.first, row.second, full)
	}
	original.WriteString("}\nvar samples=[]struct{bits,full int;a,b,control,status uint64}{\n")
	driver.WriteString("};\nstatic const struct{unsigned bits,full;uint64_t a,b,control,status;} samples[]={\n")
	for _, bits := range []int{16, 32, 64} {
		for full := 0; full < 2; full++ {
			for _, sample := range arm64BinarySamples(bits, full == 1) {
				fmt.Fprintf(&original, "{%d,%d,%#x,%#x,%#x,%#x},\n", bits, full, sample.a, sample.b, sample.control, sample.status)
				fmt.Fprintf(&driver, "{%d,%d,%#xULL,%#xULL,%#xULL,%#xULL},\n", bits, full, sample.a, sample.b, sample.control, sample.status)
			}
		}
	}
	original.WriteString(`}
func main() {
    for index,form:=range forms {
        for _,sample:=range samples {
            if sample.bits!=form.bits || sample.full!=form.full { continue }
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
	fmt.Fprintf(&driver, "};\nint main(void) { FILE* expected=fopen(%q,\"rb\");if(!expected)return 2;unsigned count=0;\n", path)
	driver.WriteString(`
    for(unsigned index=0;index<sizeof(forms)/sizeof(forms[0]);index++) {
        for(unsigned sample=0;sample<sizeof(samples)/sizeof(samples[0]);sample++) {
            if(samples[sample].bits!=forms[index].bits || samples[sample].full!=forms[index].full) continue;
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
    printf("ARM64_BINARY_TRANSLATED_PASS %u\n",count);
    return 0;
}
`)
	count := 0
	for _, row := range cases {
		count += len(arm64BinarySamples(row.bits, row.full))
	}
	return original.String(), driver.String(), count
}

func arm64BinaryCheckOriginal(t *testing.T, cases []arm64BinaryStateCase, output []byte) (nep, ah int) {
	t.Helper()
	position := 0
	for _, row := range cases {
		baseline := make(map[[2]uint64][2]uint64)
		for _, sample := range arm64BinarySamples(row.bits, row.full) {
			if len(output)-position < 69*8 {
				t.Fatal("truncated original binary transcript")
			}
			var got [69]uint64
			for index := range got {
				got[index] = binary.LittleEndian.Uint64(output[position : position+8])
				position += 8
			}
			if got[66] != []uint64{6, 8, 2, 3}[row.kind%4] || got[67] != 0x123456789abcdef0 || got[68] != 0xfedcba9876543210 || got[64]&sample.status != sample.status {
				t.Fatalf("original changed NZCV/canary/cumulative status: %x", got[64:])
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
					t.Fatalf("original corrupted bank %d: got=%x want=%x", word, got[word], want)
				}
			}
			if row.dead {
				if got[2*row.destination] != 0 || got[2*row.destination+1] != 0 {
					t.Fatal("dead fixture did not erase the destination")
				}
				continue
			}
			upperLow, upperHigh := uint64(0), uint64(0)
			if got[65]&4 != 0 {
				upperLow = (uint64(0x123456789abcdef0) + uint64(2*row.first)*0x0102030405060708) &^ mask
				upperHigh = uint64(0x123456789abcdef0) + uint64(2*row.first+1)*0x0102030405060708
				nep++
			}
			if got[2*row.destination]&^mask != upperLow || got[2*row.destination+1] != upperHigh {
				t.Fatalf("original first-source NEP merge mismatch: %+v ctrl=%x result=%x", row, got[65], got[2*row.destination:2*row.destination+2])
			}
			key := [2]uint64{sample.a, sample.b}
			value := [2]uint64{got[2*row.destination] & mask, got[64] & 0x1f}
			if sample.control == 0 {
				baseline[key] = value
			} else if sample.control == 2 && got[65]&2 != 0 && value != baseline[key] {
				ah++
			}
		}
	}
	if position != len(output) {
		t.Fatal("extra original transcript bytes")
	}
	return nep, ah
}

func arm64BinaryStateRuntime(t *testing.T, triple, goos string, compiler, runner []string, requireAFP bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	cases := arm64BinaryStateCases()
	total, nep, ah := 0, 0, 0
	seen := make(map[arm64BinaryStateCase]bool)
	for first := 0; first < len(cases); first += 32 {
		last := first + 32
		if last > len(cases) {
			last = len(cases)
		}
		t.Run(fmt.Sprintf("batch%d", first/32), func(t *testing.T) {
			batch := cases[first:last]
			for _, row := range batch {
				if seen[row] {
					t.Fatalf("duplicate runtime form: %+v", row)
				}
				seen[row] = true
			}
			source, declarations := arm64BinaryStateSource(batch)
			path := filepath.Join(t.TempDir(), "original.bin")
			original, driver, count := arm64BinaryStatePrograms(batch, declarations, path)
			output := arm64BinaryOriginalOutput(t, source, original, goos, runner)
			if len(output) != count*69*8 {
				t.Fatalf("original bytes=%d want=%d", len(output), count*69*8)
			}
			newNEP, newAH := arm64BinaryCheckOriginal(t, batch, output)
			total, nep, ah = total+count, nep+newNEP, ah+newAH
			t.Logf("actual original Go rows=%d NEP-merges=%d AH-differences=%d", count, newNEP, newAH)
			if err := os.WriteFile(path, output, 0600); err != nil {
				t.Fatal(err)
			}
			for api, ir := range arm64BinaryMatrixIRs(t, source, declarations, triple) {
				for _, optimized := range []bool{false, true} {
					if optimized {
						ir = armFloatEffectOptimizedIR(t, ir)
					}
					for _, level := range []int{0, 2} {
						t.Run(fmt.Sprintf("API%d/IR_O2=%t/backend_O%d", api, optimized, level), func(t *testing.T) {
							compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "binary_state", triple, ir, driver, runner, level)
						})
					}
				}
			}
		})
	}
	if total != 28214 || len(seen) != 157 {
		t.Fatalf("changed complete runtime denominator: rows=%d forms=%d", total, len(seen))
	}
	if requireAFP && (nep == 0 || ah == 0) {
		t.Fatalf("required actual AFP effects missing: NEP=%d AH=%d", nep, ah)
	}
	t.Logf("ARM64_BINARY_FULL_STATE_PASS original=%d LLVM=%d NEP=%d AH=%d", total, total*16, nep, ah)
}

func TestARM64ScalarBinaryFullStateNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin native counterpart; required Linux/QEMU owner covers other hosts")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang required")
	}
	arm64BinaryStateRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil, false)
}
