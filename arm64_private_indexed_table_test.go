package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64PrivateIndexedSource(store, load string, shift int) string {
	return fmt.Sprintf(`#include "textflag.h"
TEXT ·Indexed(SB),NOSPLIT,$80-24
    CALL ·Noop(SB)
    MOVD dst+0(FP),R7
    MOVD n+8(FP),R11
    AND $7,R11
    ADD $16,RSP,R17
    MOVD $0x123456789abcde7e,R5
    %s R5,0(R17)(R11<<%d)
    %s 0(R17)(R11<<%d),R12
    MOVD R12,(R7)
    MOVD R12,ret+16(FP)
    RET
TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0
    RET
`, store, shift, load, shift)
}

func TestARM64PrivateIndexedScalarDataObjects(t *testing.T) {
	for _, tc := range []struct {
		store, load string
		shift       int
	}{
		{"MOVB", "MOVBU", 0}, {"MOVBU", "MOVBU", 0},
		{"MOVH", "MOVHU", 1}, {"MOVHU", "MOVHU", 1},
		{"MOVW", "MOVWU", 2}, {"MOVWU", "MOVWU", 2},
		{"MOVD", "MOVD", 3},
	} {
		t.Run(tc.store, func(t *testing.T) {
			source := arm64PrivateIndexedSource(tc.store, tc.load, tc.shift)
			arm64PrivateDataBoundObjects(t, source, "func Indexed(dst *uint64,n uint64) uint64", tc.store)
		})
	}
}

const arm64PrivateCountedTableSource = `#include "textflag.h"
TEXT ·CountedTable(SB),0,$32904-16
    CALL ·Noop(SB)
    MOVD n+0(FP),R14
    MOVD $24,R5
    MOVD $256,R6
count:
    MOVD $16384,R2
    CMP R2,R6
    BGE allocated
    CMP R14,R6
    BGE allocated
    SUB $1,R5
    LSL $1,R6
    B count
allocated:
    ADD $128,RSP,R17
    MOVD R17,R4
    ADD R6<<1,R17,R6
clear:
    STP.P (ZR,ZR),64(R4)
    STP (ZR,ZR),-48(R4)
    STP (ZR,ZR),-32(R4)
    STP (ZR,ZR),-16(R4)
    CMP R4,R6
    BHI clear
    MOVD $0,R6
    MOVD R5,64(RSP)
    CALL ·Noop(SB)
    MOVD 64(RSP),R5
    MOVW n+0(FP),R11
    MOVW $0xa7bd,R16
    MULW R16,R11
    LSRW R5,R11
    MOVD $0x1234,R3
    MOVH R3,0(R17)(R11<<1)
    MOVW n+0(FP),R11
    EORW $1,R11
    MULW R16,R11
    LSRW R5,R11
    MOVHU 0(R17)(R11<<1),R12
    MOVD R12,ret+8(FP)
    RET
TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0
    RET
`

func TestARM64PrivateCountedTableExtentObjects(t *testing.T) {
	arm64PrivateDataBoundObjects(t, arm64PrivateCountedTableSource, "func CountedTable(n uint64) uint64", "counted-table")
}

func arm64PrivateIndexedModule(t *testing.T, source, declaration, target string) string {
	t.Helper()
	pkg := mustGoPackage(t, "test/indexed", "package indexed\n"+declaration+"\nfunc Noop()\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: target,
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Module.Dispose()
	return bound.Module.String()
}

func TestCrossLinuxRuntimeMatrixARM64PrivateIndexedScalarData(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range []struct {
		store, load  string
		shift, bytes int
	}{
		{"MOVB", "MOVBU", 0, 1}, {"MOVBU", "MOVBU", 0, 1},
		{"MOVH", "MOVHU", 1, 2}, {"MOVHU", "MOVHU", 1, 2},
		{"MOVW", "MOVWU", 2, 4}, {"MOVWU", "MOVWU", 2, 4},
		{"MOVD", "MOVD", 3, 8},
	} {
		t.Run(tc.store, func(t *testing.T) {
			source := arm64PrivateIndexedSource(tc.store, tc.load, tc.shift)
			mask := ^uint64(0)
			if tc.bytes < 8 {
				mask = uint64(1)<<uint(tc.bytes*8) - 1
			}
			want := uint64(0x123456789abcde7e) & mask
			goSource := fmt.Sprintf(`package main
func Indexed(dst *uint64,n uint64) uint64
func Noop()
func main() {
    for _,n := range []uint64{0,1,2,3,4,5,6,7,8,255,^uint64(0)} {
        data := [3]uint64{0xa7a7a7a7a7a7a7a7,0,0xb8b8b8b8b8b8b8b8}
        if Indexed(&data[1],n) != %#x || data != [3]uint64{0xa7a7a7a7a7a7a7a7,%#x,0xb8b8b8b8b8b8b8b8} {
            panic("indexed scalar value/canary mismatch")
        }
    }
}
`, want, want)
			runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
			ir := arm64PrivateIndexedModule(t, source, "func Indexed(dst *uint64,n uint64) uint64", target)
			cSource := fmt.Sprintf(`#include <stdint.h>
extern uint64_t Indexed(uint64_t *,uint64_t);
int main(void) {
    const uint64_t values[]={0,1,2,3,4,5,6,7,8,255,UINT64_MAX};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        uint64_t data[]={UINT64_C(0xa7a7a7a7a7a7a7a7),0,UINT64_C(0xb8b8b8b8b8b8b8b8)};
        if(Indexed(data+1,values[i])!=UINT64_C(%#x) || data[1]!=UINT64_C(%#x) ||
            data[0]!=UINT64_C(0xa7a7a7a7a7a7a7a7) || data[2]!=UINT64_C(0xb8b8b8b8b8b8b8b8)) return 1;
    }
    return 0;
}
`, want, want)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "indexed_scalar_"+tc.store, target, ir, cSource, runner)
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateCountedTable(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	runARM64LocalRegisterGoOracle(t, arm64PrivateCountedTableSource, `package main
func CountedTable(n uint64) uint64
func Noop()
func main() {
    for _,n := range []uint64{0,1,255,256,257,511,512,513,1024,4096,8192,16383,16384,65536,1<<63-1,^uint64(0)} {
        size,shift:=uint64(256),uint(24)
        for size<16384 && int64(size)<int64(n) { size*=2; shift-- }
        first:=uint32(n)*0xa7bd>>shift
        second:=(uint32(n)^1)*0xa7bd>>shift
        want:=uint64(0)
        if first==second { want=0x1234 }
        if CountedTable(n)!=want { panic("counted clear/index/typed spill mismatch") }
    }
}
`, len(runner) != 0, "1.20")
	ir := arm64PrivateIndexedModule(t, arm64PrivateCountedTableSource, "func CountedTable(n uint64) uint64", target)
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "counted_private_table", target, ir, `#include <stdint.h>
extern uint64_t CountedTable(uint64_t);
int main(void) {
    const uint64_t values[]={0,1,255,256,257,511,512,513,1024,4096,8192,16383,16384,65536,INT64_MAX,UINT64_MAX};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        uint64_t n=values[i],size=256;
        unsigned shift=24;
        while(size<16384 && (int64_t)size<(int64_t)n) { size*=2; shift--; }
        uint32_t first=((uint32_t)n*UINT32_C(0xa7bd))>>shift;
        uint32_t second=(((uint32_t)n^UINT32_C(1))*UINT32_C(0xa7bd))>>shift;
        if(CountedTable(n)!=(first==second?UINT64_C(0x1234):0)) return 1;
    }
    return 0;
}
`, runner)
}
