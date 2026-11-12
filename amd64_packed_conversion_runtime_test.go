//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86PackedConversionRuntimeRow struct {
	instruction string
	rawOverride string
	wide, dead  bool
	inputBits   int
	mask        bool
	sae         bool
}

func x86PackedConversionRuntimeRows(wide bool) []x86PackedConversionRuntimeRow {
	var rows []x86PackedConversionRuntimeRow
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
	for _, spec := range x86PackedConversionOracleSpecs() {
		if !wide && !spec.legacy {
			continue
		}
		for _, shape := range spec.shapes() {
			destination := bank[shape.destination] + "1"
			for _, input := range []string{bank[shape.source] + "0", "(SI)"} {
				rows = append(rows, x86PackedConversionRuntimeRow{instruction: spec.name + " " + input + "," + destination, wide: wide, inputBits: spec.input})
			}
			rows = append(rows, x86PackedConversionRuntimeRow{instruction: spec.name + " " + bank[shape.source] + "1," + destination, wide: wide, inputBits: spec.input},
				x86PackedConversionRuntimeRow{instruction: spec.name + " " + bank[shape.source] + "0," + destination, wide: wide, dead: true, inputBits: spec.input})
			if !spec.legacy {
				for _, spelling := range []string{
					spec.name + " " + bank[shape.source] + "0,K1," + destination,
					spec.name + ".Z (SI),K1," + destination,
					spec.name + ".BCST (SI),K1," + destination,
					spec.name + ".BCST.Z (SI),K1," + destination,
				} {
					rows = append(rows, x86PackedConversionRuntimeRow{instruction: spelling, wide: wide, mask: true, inputBits: spec.input})
				}
			}
			if (shape.source == 64 || shape.destination == 64) && spec.control != "" {
				controls := []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}
				if spec.control == "sae" {
					controls = []string{"SAE"}
				}
				for _, control := range controls {
					rows = append(rows, x86PackedConversionRuntimeRow{
						instruction: spec.name + "." + control + ".Z " + bank[shape.source] + "0,K1," + destination,
						wide:        wide, mask: true, sae: true, inputBits: spec.input,
					})
				}
			}
		}
	}
	return rows
}

func x86PackedConversionRuntimeFixture(rows []x86PackedConversionRuntimeRow) (assembly, declarations, original, driver string) {
	var asm, decl, goCalls, cDecl, cCalls strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("packed%d", index)
		fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$8-24\nSTMXCSR saved-4(SP)\nMOVQ out+0(FP),DI\nMOVQ in+8(FP),SI\n", name)
		if row.wide {
			asm.WriteString("VMOVDQU64 (SI),Z0\nVMOVDQU64 (DI),Z1\nMOVL mask+20(FP),CX\nKMOVW CX,K1\n")
		} else {
			asm.WriteString("MOVOU (SI),X0\nMOVOU (DI),X1\n")
		}
		asm.WriteString("LDMXCSR csr+16(FP)\nMOVQ $-1,DX\nCMPQ DX,$-1\n")
		asm.WriteString(row.instruction + "\n")
		if !row.dead {
			if row.wide {
				asm.WriteString("VMOVDQU64 Z1,(DI)\n")
			} else {
				asm.WriteString("MOVOU X1,(DI)\n")
			}
		}
		asm.WriteString("STMXCSR 72(DI)\nSETEQ 64(DI)\nSETCS 65(DI)\nSETOS 66(DI)\nSETMI 67(DI)\nSETPC 68(DI)\nLDMXCSR saved-4(SP)\nRET\n")
		fmt.Fprintf(&decl, "func %s(out *[12]uint64,in *[8]uint64,csr,mask uint32)\n", name)
		masks, sae := 1, 0
		if row.mask {
			masks = 4
		}
		if row.sae {
			sae = 1
		}
		fmt.Fprintf(&goCalls, "check(%d,%d,%d,%d,%s)\n", index, row.inputBits, masks, sae, name)
		fmt.Fprintf(&cDecl, "extern void %s(uint64_t*,const uint64_t*,uint32_t,uint32_t);\n", name)
		fmt.Fprintf(&cCalls, "check(%d,%d,%d,%d,%s);\n", index, row.inputBits, masks, sae, name)
	}
	var gValues, cValues strings.Builder
	values := append(append([]uint64{}, x86ScalarFloatIntegerSSInputs...), x86ScalarFloatIntegerSDInputs...)
	values = append(values, 0xffffff, 0x1000001, 0xffffffff, 0x1fffffffffffff, 0x20000000000001, 0x7fffffffffffffff, 0xffffffffffffffff)
	for _, value := range values {
		fmt.Fprintf(&gValues, "%#x,", value)
		fmt.Fprintf(&cValues, "UINT64_C(%#x),", value)
	}
	original = `package main
import ("fmt";"unsafe")
var values=[]uint64{` + gValues.String() + `}
var masks=[]uint32{0xffff,0,1,0xaaaa}
func check(index,bits,maskCount,sae int,fn func(*[12]uint64,*[8]uint64,uint32,uint32)) {
    hash:=uint64(1469598103934665603); count:=0
    for n:=range values { for rc:=0;rc<4;rc++ { for controls:=0;controls<8;controls++ { for m:=0;m<maskCount;m++ {
        var backing [10]uint64
        address:=unsafe.Pointer(&backing[0])
        input:=(*[8]uint64)(unsafe.Add(address,(-uintptr(address))&15))
        for lane:=range input {
            if bits==32 {input[lane]=uint64(uint32(values[(n+2*lane)%len(values)]))|uint64(uint32(values[(n+2*lane+1)%len(values)]))<<32
            } else {input[lane]=values[(n+lane)%len(values)]}
        }
        var out [12]uint64
        for lane:=range out {out[lane]=uint64(lane+1)*0x0101010101010101}
        csr:=uint32(0x1f80|rc<<13)
        if controls&1!=0 {csr|=0x40};if controls&2!=0 {csr|=0x8000}
        if controls&4!=0 {csr|=0x21}
        if sae!=0 {csr &^=0x1080}
        fn(&out,input,csr,masks[m])
        for _,word:=range out { for shift:=0;shift<64;shift+=8 {hash=(hash^uint64(byte(word>>shift)))*1099511628211} }
        count++
    }}}}
    fmt.Printf("%d %d %016x\n",index,count,hash)
}
` + decl.String() + "func main(){\n" + goCalls.String() + "}\n"
	driver = `#include <stdint.h>
#include <stdio.h>
static const uint64_t values[]={` + cValues.String() + `};
static const uint32_t masks[]={0xffff,0,1,0xaaaa};
static void check(unsigned index,unsigned bits,unsigned maskCount,unsigned sae,void (*fn)(uint64_t*,const uint64_t*,uint32_t,uint32_t)) {
    uint64_t hash=UINT64_C(1469598103934665603);unsigned count=0,N=sizeof(values)/sizeof(*values);
    for(unsigned n=0;n<N;n++) for(unsigned rc=0;rc<4;rc++) for(unsigned controls=0;controls<8;controls++) for(unsigned m=0;m<maskCount;m++) {
        _Alignas(16) uint64_t input[8],out[12];
        for(unsigned lane=0;lane<8;lane++) input[lane]=bits==32 ? (uint64_t)(uint32_t)values[(n+2*lane)%N]|(uint64_t)(uint32_t)values[(n+2*lane+1)%N]<<32 : values[(n+lane)%N];
        for(unsigned lane=0;lane<12;lane++) out[lane]=(lane+1)*UINT64_C(0x0101010101010101);
        uint32_t csr=0x1f80|(rc<<13);
        if(controls&1) csr|=0x40;if(controls&2) csr|=0x8000;
        if(controls&4) csr|=0x21;
        if(sae) csr&=~UINT32_C(0x1080);
        fn(out,input,csr,masks[m]);
        for(unsigned lane=0;lane<12;lane++) for(unsigned shift=0;shift<64;shift+=8) hash=(hash^(uint8_t)(out[lane]>>shift))*UINT64_C(1099511628211);
        count++;
    }
    printf("%u %u %016llx\n",index,count,(unsigned long long)hash);
}
` + cDecl.String() + "int main(void){\n" + cCalls.String() + "return 0;}\n"
	return asm.String(), decl.String(), original, driver
}

func x86PackedConversionRuntimeMatrix(t *testing.T, wide bool) {
	t.Helper()
	axis := x86FloatCompareSSE
	if wide {
		axis = x86FloatCompareEVEX
	}
	execution := x86FloatCompareRuntimeTools(t, axis)
	rows := x86PackedConversionRuntimeRows(wide)
	const limit = 96
	consumed := 0
	for start := 0; start < len(rows); start += limit {
		end := start + limit
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			assembly, declarations, main, driver := x86PackedConversionRuntimeFixture(rows[start:end])
			want := x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, main)
			if strings.Count(string(want), "\n") != end-start {
				t.Fatal("incomplete original Go function/case receipts")
			}
			var originals []string
			for _, row := range rows[start:end] {
				originals = append(originals, row.instruction)
			}
			raw := x86PackedConversionOriginalRawRows(t, "amd64", originals)
			rawRows := append([]x86PackedConversionRuntimeRow(nil), rows[start:end]...)
			for index := range rawRows {
				rawRows[index].instruction = raw[index]
			}
			rawAssembly, _, _, _ := x86PackedConversionRuntimeFixture(rawRows)
			for _, spelling := range []struct{ name, source string }{{"named", assembly}, {"raw", rawAssembly}} {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations, "amd64", execution.triple, api)
					if err != nil {
						t.Fatal(start, api, err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							got := execution.compileAndRunLLVM(t, "packed-conversion-matrix", input, driver, level)
							if string(got) != string(want) {
								t.Fatalf("batch %d %s/%s optimized=%v %s\nGo:\n%sLLVM:\n%s", start, spelling.name, api, optimized, level, want, got)
							}
						}
					}
				}
			}
			consumed += end - start
		})
	}
	if consumed != len(rows) {
		t.Fatal("runtime batch partition lost rows")
	}
	t.Logf("%d independent conversion kernels, 63 bit-pattern seeds x 4 rounding x 4 DAZ/FTZ x 2 clean/sticky status; masked kernels also 4 masks; named/raw x 3 APIs x 4 optimization axes", len(rows))
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionLegacyIEEEStatusFlags(t *testing.T) {
	x86PackedConversionRuntimeMatrix(t, false)
}

// Object receipts for the actual wide runtime fixture are not execution
// receipts. They close its source/API/lifecycle path before a native owner
// attempts the same kernels, without executing unsupported host instructions.
func TestX86PackedConversionNativeRuntimeFixtureObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86PackedConversionRuntimeRows(true)
	const limit = 96
	consumed := 0
	for start := 0; start < len(rows); start += limit {
		end := start + limit
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			batch := append([]x86PackedConversionRuntimeRow(nil), rows[start:end]...)
			var instructions []string
			for _, row := range batch {
				instructions = append(instructions, row.instruction)
			}
			raw := x86PackedConversionOriginalRawRows(t, "amd64", instructions)
			for _, spelling := range []string{"named", "raw"} {
				if spelling == "raw" {
					for index := range batch {
						batch[index].instruction = raw[index]
					}
				}
				source, declarations, _, _ := x86PackedConversionRuntimeFixture(batch)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil {
						t.Fatal(spelling, api, err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, ir)
						}
						compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "native-runtime.ll", "native-runtime.o", input)
					}
				}
			}
			consumed += end - start
		})
	}
	if consumed != len(rows) {
		t.Fatal("native runtime fixture partition lost rows")
	}
	t.Logf("%d complete wide runtime kernels, named/raw x 3 APIs x 2 IR pipelines; object-only", consumed)
}
