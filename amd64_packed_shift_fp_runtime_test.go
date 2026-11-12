package plan9asm

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedShiftFPSpanNumerical(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools required")
	}
	var prefix []string
	flags := []string{"-no-pie"}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if !rosettaAvailable() {
			t.Fatal("Darwin x86 diagnostic transport required")
		}
		prefix = []string{"/usr/bin/arch", "-x86_64"}
		flags = []string{"-arch", "x86_64"}
	} else if runtime.GOOS == "linux" && runtime.GOARCH == "arm64" {
		qemu, err := exec.LookPath("qemu-x86_64")
		if err != nil {
			t.Fatal("explicit Linux x86 runtime transport required:", err)
		}
		clang, err = exec.LookPath("x86_64-linux-gnu-gcc")
		if err != nil {
			t.Fatal("x86 cross C compiler required:", err)
		}
		prefix = []string{qemu, "-L", "/usr/x86_64-linux-gnu"}
	} else if runtime.GOARCH != "amd64" {
		t.Skip("required Linux/amd64 counterpart supplies this numerical axis")
	}
	const source = `TEXT fpbytes(SB),4,$0-16
VPSRLD.BCST $0,a+0(FP),X0
MOVQ X0,AX
MOVQ AX,r+8(FP)
RET
TEXT fpcross(SB),4,$0-24
VPSRLQ.BCST $0,a+4(FP),X0
MOVQ X0,AX
MOVQ AX,r+16(FP)
RET
TEXT fpcount(SB),4,$0-24
MOVQ $0x89abcdef76543210,AX
MOVQ AX,X0
VPSRLD a+0(FP),X0,X1
MOVQ X1,AX
MOVQ AX,r+16(FP)
RET
`
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	bytesSig := FuncSig{Name: "fpbytes", Args: []LLVMType{I8, I8, I8, I8}, Ret: I64,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I8, Index: 0, Field: -1}, {Offset: 1, Type: I8, Index: 1, Field: -1},
			{Offset: 2, Type: I8, Index: 2, Field: -1}, {Offset: 3, Type: I8, Index: 3, Field: -1},
		}, Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}}}}
	wideSig := FuncSig{Args: []LLVMType{I64, I64}, Ret: I64,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1},
		}, Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}}}}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"fpbytes": bytesSig, "fpcross": wideSig, "fpcount": wideSig}})
	if err != nil {
		t.Fatal(err)
	}
	const driver = `
#include <stdint.h>
#include <stdio.h>
extern uint64_t fpbytes(uint8_t,uint8_t,uint8_t,uint8_t);
extern uint64_t fpcross(uint64_t,uint64_t);
extern uint64_t fpcount(uint64_t,uint64_t);
int main(void) {
 for(unsigned i=0;i<96;++i) {
  uint8_t a=(uint8_t)(i*71+13),b=(uint8_t)(i*97+11);
  uint8_t c=(uint8_t)(i*53+17),d=(uint8_t)(i*19+7);
  uint64_t word=(uint32_t)a|((uint32_t)b<<8)|((uint32_t)c<<16)|((uint32_t)d<<24);
  if(fpbytes(a,b,c,d)!=(word|(word<<32))) { fprintf(stderr,"four byte FP BCST mismatch %u\n",i); return 1; }
  uint64_t first=UINT64_C(0xabcdef1276543210)^(UINT64_C(0x12345678)*i);
  uint64_t second=UINT64_C(0x179bdeff23056789)^(UINT64_C(0x87654321)*i);
  if(fpcross(first,second)!=((first>>32)|(second<<32))) { fprintf(stderr,"cross slot FP BCST mismatch %u\n",i); return 2; }
  uint64_t count=i<40?i:UINT64_C(0x100000000)+i;
  uint64_t expected=count<32?((uint64_t)(UINT32_C(0x89abcdef)>>count)<<32)|(UINT32_C(0x76543210)>>count):0;
  if(fpcount(count,second)!=expected) { fprintf(stderr,"full m128 FP count mismatch %u\n",i); return 3; }
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, append([]string{clang}, flags...), "packed_shift_fp_span", triple, ir, driver, prefix)
	if strings.Contains(ir, "inttoptr i64 0") {
		t.Fatal("FP bytes were replaced by an unbound zero pointer")
	}
	t.Logf("three initialized FP span programs ×96 numerical inputs; original Go encoding accepted, LLVM execution transport=%v", prefix)
}
