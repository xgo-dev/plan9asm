package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64ScalarMemoryCase struct {
	op, suffix, index  string
	bits               int
	offset, indexValue int64
	scale              int64
	store, signed      bool
	base27, data27     bool
	scratchKind        int // Independent oracle: 0 preserved, 1 base+hi, 2 literal.
	scratchValue       int64
}

func arm64ScalarMemoryCases() []arm64ScalarMemoryCase {
	var cases []arm64ScalarMemoryCase
	for i, op := range arm64MemoryScratchAuditMoves {
		bits := 8 << (i / 2)
		if op == "MOVD" {
			bits = 64
		}
		for _, store := range []bool{false, true} {
			base := arm64ScalarMemoryCase{op: op, bits: bits, signed: i%2 == 0 && bits < 64, store: store, scale: 1}
			for _, offset := range []int64{-256, -1, 0, 255, 4095 * int64(bits/8), 65536, -8192} {
				tc := base
				tc.offset = offset
				if offset == 65536 {
					tc.scratchKind, tc.scratchValue = 1, 65536
				} else if offset == -8192 {
					tc.scratchKind, tc.scratchValue = 2, -8192
				}
				cases = append(cases, tc)
			}
			if op == "MOVD" {
				tc := base
				tc.offset, tc.scratchKind, tc.scratchValue = 65537, 2, 65537
				cases = append(cases, tc)
			}
			for _, suffix := range []string{".P", ".W"} {
				for _, offset := range []int64{-256, 0, 255} {
					tc := base
					tc.suffix, tc.offset = suffix, offset
					cases = append(cases, tc)
				}
			}
			for _, index := range []struct {
				text  string
				value int64
				scale int64
			}{
				{"R2", 3, 1},
				{fmt.Sprintf("R2<<%d", i/2), 3, int64(bits / 8)},
				{"R2.SXTW<<0", -3, 1},
				{fmt.Sprintf("R2.UXTW<<%d", i/2), 0x100000003, int64(bits / 8)},
				{fmt.Sprintf("R2.SXTX<<%d", i/2), -3, int64(bits / 8)},
			} {
				tc := base
				tc.index, tc.indexValue, tc.scale = index.text, index.value, index.scale
				cases = append(cases, tc)
			}
			for _, aliases := range [][2]bool{{true, false}, {false, true}, {true, true}} {
				tc := base
				tc.base27, tc.data27 = aliases[0], aliases[1]
				tc.offset, tc.scratchKind, tc.scratchValue = 65536, 1, 65536
				cases = append(cases, tc)
			}
		}
	}
	return cases
}

func arm64ScalarMemoryFixture() (source, declaration string, cases []arm64ScalarMemoryCase) {
	cases = arm64ScalarMemoryCases()
	var assembly, goDecl strings.Builder
	for i, tc := range cases {
		name := fmt.Sprintf("Memory%d", i)
		fmt.Fprintf(&goDecl, "func %s(input *[262144]byte, output *[4]uint64)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\n", name)
		assembly.WriteString("MOVD input+0(FP),R0\nMOVD output+8(FP),R11\nADD $65536,R0\nMOVD R0,R9\nMOVD $107,R27\nMOVD $0x10203040aa80feff,R1\n")
		base, data := "R0", "R1"
		if tc.base27 {
			base = "R27"
			assembly.WriteString("MOVD R0,R27\n")
		}
		if tc.data27 {
			data = "R27"
		}
		fmt.Fprintf(&assembly, "MOVD $%d,R2\n", tc.indexValue)
		assembly.WriteString("MOVD $255,R6\nMOVD $1,R7\nCMP R7,R6\n")
		memory := fmt.Sprintf("%d(%s)", tc.offset, base)
		if tc.index != "" {
			memory = fmt.Sprintf("(%s)(%s)", base, tc.index)
		}
		if tc.store {
			fmt.Fprintf(&assembly, "%s%s %s,%s\n", tc.op, tc.suffix, data, memory)
		} else {
			fmt.Fprintf(&assembly, "%s%s %s,%s\n", tc.op, tc.suffix, memory, data)
		}
		fmt.Fprintf(&assembly, "MOVD %s,(R11)\n", data)
		if tc.scratchKind == 1 && (!tc.data27 || tc.store) || tc.scratchKind == 0 && tc.base27 {
			assembly.WriteString("SUB R9,R27,R5\nMOVD R5,8(R11)\n")
		} else {
			assembly.WriteString("MOVD R27,8(R11)\n")
		}
		fmt.Fprintf(&assembly, "SUB R9,%s,R5\nMOVD R5,16(R11)\n", base)
		assembly.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET HS,R4\nCSET VS,R5\nLSL $1,R3\nLSL $2,R4\nLSL $3,R5\nORR R3,R2\nORR R4,R2\nORR R5,R2\nMOVD R2,24(R11)\nRET\n")
	}
	return assembly.String(), goDecl.String(), cases
}

func arm64ScalarMemoryIRs(t *testing.T, source, declaration, target string) []string {
	t.Helper()
	pkg := mustGoPackage(t, "test/memory", "package memory\n"+declaration)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	ir, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, opt)
	if err != nil {
		t.Fatal(err)
	}
	moduleIR := module.String()
	module.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
	if err != nil {
		t.Fatal(err)
	}
	boundIR := bound.Module.String()
	bound.Module.Dispose()
	return []string{ir, moduleIR, boundIR}
}

func arm64ScalarMemoryPrograms(declaration string, cases []arm64ScalarMemoryCase) (string, string) {
	boolInt := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	var goCases, cDecl, cCases strings.Builder
	for i, tc := range cases {
		index := tc.indexValue
		if strings.Contains(tc.index, "UXTW") {
			index = int64(uint32(index))
		}
		effective := tc.offset + index*tc.scale
		if tc.suffix == ".P" {
			effective = 0
		}
		fmt.Fprintf(&goCases, "{Memory%d,%d,%t,%t,%t,%t,%d,%d,%d,%d,%t},\n", i, tc.bits, tc.signed, tc.store, tc.base27, tc.data27, effective, tc.offset, tc.scratchKind, tc.scratchValue, tc.suffix != "")
		fmt.Fprintf(&cDecl, "extern void Memory%d(uint8_t *,uint64_t *);\n", i)
		fmt.Fprintf(&cCases, "{Memory%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d},\n", i, tc.bits, boolInt(tc.signed), boolInt(tc.store), boolInt(tc.base27), boolInt(tc.data27), effective, tc.offset, tc.scratchKind, tc.scratchValue, boolInt(tc.suffix != ""))
	}
	goProgram := `package main
import (
    "fmt"
    "unsafe"
)
` + declaration + `
type memoryCase struct {
    fn func(*[262144]byte,*[4]uint64)
    bits int
    signed,store,base27,data27 bool
    effective,offset int64
    scratch int
    scratchValue int64
    writeback bool
}
func initialByte(i int) byte { return byte(i*73+128) }
func main() {
    cases := []memoryCase{
` + goCases.String() + `
    }
    storage := new([262160]byte)
    input := (*[262144]byte)(unsafe.Pointer(&storage[8]))
    for number,tc := range cases {
        for i := range storage { storage[i]=0xa7 }
        for i := range input { input[i]=initialByte(i) }
        output := struct { left uint64; values [4]uint64; right uint64 }{left:0x1234,right:0x5678}
        base := uint64(uintptr(unsafe.Pointer(&input[65536])))
        data := uint64(0x10203040aa80feff)
        scratch := uint64(107)
        if tc.base27 { scratch=base }
        if tc.scratch==1 { scratch=base+uint64(tc.scratchValue) }
        if tc.scratch==2 { scratch=uint64(tc.scratchValue) }
        if tc.data27 && tc.store { data=scratch }
        at := 65536+int(tc.effective)
        if !tc.store {
            data=0
            for j:=0;j<tc.bits/8;j++ { data|=uint64(input[at+j])<<uint(j*8) }
            if tc.signed && data&(uint64(1)<<uint(tc.bits-1))!=0 { data|=^uint64(0)<<uint(tc.bits) }
            if tc.data27 { scratch=data }
        }
        baseAfter := base
        if tc.base27 { baseAfter=scratch }
        if tc.writeback { baseAfter+=uint64(tc.offset) }
        observedScratch := scratch
        if tc.scratch==1 && (!tc.data27 || tc.store) || tc.scratch==0 && tc.base27 { observedScratch-=base }
        expected := [4]uint64{data,observedScratch,baseAfter-base,4}
        tc.fn(input,&output.values)
        if output.values!=expected { panic(fmt.Sprintf("Go case %d got %x want %x",number,output.values,expected)) }
        for i,value := range input {
            want:=initialByte(i)
            if tc.store && i>=at && i<at+tc.bits/8 { want=byte(data>>uint((i-at)*8)) }
            if value!=want { panic(fmt.Sprintf("Go case %d input byte %d",number,i)) }
        }
        for i:=0;i<8;i++ { if storage[i]!=0xa7 || storage[262152+i]!=0xa7 { panic("Go input canary") } }
        if output.left!=0x1234 || output.right!=0x5678 { panic("Go output canary") }
    }
}
`
	cProgram := `#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
` + cDecl.String() + `
struct memory_case {
    void (*fn)(uint8_t *,uint64_t *);
    unsigned bits,signed_load,store,base27,data27;
    int64_t effective,offset;
    unsigned scratch;
    int64_t scratch_value;
    unsigned writeback;
};
static uint8_t initial_byte(unsigned i) { return (uint8_t)(i*73+128); }
int main(void) {
    const struct memory_case cases[]={
` + cCases.String() + `
    };
    uint8_t *storage=malloc(262160);
    if (!storage) return 90;
    uint8_t *input=storage+8;
    for (unsigned number=0;number<sizeof(cases)/sizeof(cases[0]);number++) {
        struct memory_case tc=cases[number];
        memset(storage,0xa7,262160);
        for (unsigned i=0;i<262144;i++) input[i]=initial_byte(i);
        struct { uint64_t left,values[4],right; } output={.left=0x1234,.right=0x5678};
        uint64_t base=(uintptr_t)(input+65536),data=UINT64_C(0x10203040aa80feff),scratch=107;
        if (tc.base27) scratch=base;
        if (tc.scratch==1) scratch=base+(uint64_t)tc.scratch_value;
        if (tc.scratch==2) scratch=(uint64_t)tc.scratch_value;
        if (tc.data27 && tc.store) data=scratch;
        unsigned at=(unsigned)(65536+tc.effective);
        if (!tc.store) {
            data=0;
            for (unsigned j=0;j<tc.bits/8;j++) data|=(uint64_t)input[at+j]<<(j*8);
            if (tc.signed_load && (data&(UINT64_C(1)<<(tc.bits-1)))) data|=UINT64_MAX<<tc.bits;
            if (tc.data27) scratch=data;
        }
        uint64_t base_after=tc.base27 ? scratch : base;
        if (tc.writeback) base_after+=(uint64_t)tc.offset;
        uint64_t observed_scratch=scratch;
        if ((tc.scratch==1 && (!tc.data27 || tc.store)) || (tc.scratch==0 && tc.base27)) observed_scratch-=base;
        const uint64_t expected[]={data,observed_scratch,base_after-base,4};
        tc.fn(input,output.values);
        for (unsigned i=0;i<4;i++) {
            if (output.values[i]!=expected[i]) {
                fprintf(stderr,"LLVM case %u field %u got %#llx want %#llx\n",number,i,(unsigned long long)output.values[i],(unsigned long long)expected[i]);
                free(storage);
                return 1;
            }
        }
        for (unsigned i=0;i<262144;i++) {
            uint8_t want=initial_byte(i);
            if (tc.store && i>=at && i<at+tc.bits/8) want=(uint8_t)(data>>((i-at)*8));
            if (input[i]!=want) { fprintf(stderr,"LLVM case %u input byte %u\n",number,i); free(storage); return 2; }
        }
        for (unsigned i=0;i<8;i++) if (storage[i]!=0xa7 || storage[262152+i]!=0xa7) { free(storage); return 3; }
        if (output.left!=0x1234 || output.right!=0x5678) { free(storage); return 4; }
    }
    free(storage);
    return 0;
}
`
	return goProgram, cProgram
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMemoryComplete(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	source, declaration, cases := arm64ScalarMemoryFixture()
	goProgram, cProgram := arm64ScalarMemoryPrograms(declaration, cases)
	runARM64LocalRegisterGoOracle(t, source, goProgram, len(runner) != 0, "1.20")
	for api, ir := range arm64ScalarMemoryIRs(t, source, declaration, target) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("scalar-memory-complete-%d", api), target, ir, cProgram, runner)
	}
	t.Logf("%d initialized original Go / three API LLVM cases, full input/output canaries and NZCV", len(cases))
}

func TestARM64ScalarMemoryCompleteLLVM22Objects(t *testing.T) {
	source, declaration, cases := arm64ScalarMemoryFixture()
	requireARM64GoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc unavailable")
	}
	for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		for api, ir := range arm64ScalarMemoryIRs(t, source, declaration, target) {
			compileLLVMToObject(t, llc, target, fmt.Sprintf("scalar-memory-%d.ll", api), fmt.Sprintf("scalar-memory-%d.o", api), ir)
		}
	}
	t.Logf("%d original Go-accepted scalar-memory cases × 3 APIs × 5 object targets", len(cases))
}
