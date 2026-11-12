package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

const arm64ABI0TailLoopSource = `TEXT ·Slots(SB),516,$0-24
MOVD data+0(FP),R0
MOVD n+8(FP),R1
MOVD $out+16(FP),R8
B resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
MOVD $0,R11
CBZ R1,done
loop:
MOVD.P 8(R0),R12
ADD R12,R11,R11
SUB $1,R1
CBNZ R1,loop
done:
MOVD R11,(R8)
RET
`

func TestCrossLinuxRuntimeMatrixARM64ABI0TailResultInitializedLoop(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const declaration = "func Slots(data *uint64, n uint64) (out uint64)"
	const program = `package main
func Slots(data *uint64, n uint64) (out uint64)
func main() {
  data := [...]uint64{0xabc,0,1,255,1<<63,^uint64(0),0xdef}
  original := data
  for n:=uint64(0); n<=5; n++ {
    want := uint64(0)
    for i:=uint64(0); i<n; i++ { want += data[1+i] }
    out := [3]uint64{0x123,Slots(&data[1],n),0x456}
    if out != [3]uint64{0x123,want,0x456} { panic("ABI0 initialized-loop result/canaries") }
    if data != original { panic("ABI0 initialized-loop source changed") }
  }
}
`
	t.Run("original", func(t *testing.T) {
		runARM64LocalRegisterGoOracle(t, arm64ABI0TailLoopSource, program, len(runner) != 0)
	})
	const main = `#include <stdint.h>
#include <string.h>
extern uint64_t Slots(const uint64_t*, uint64_t);
int main(void) {
  uint64_t data[] = {0xabc,0,1,255,UINT64_C(1)<<63,UINT64_MAX,0xdef};
  uint64_t original[7];
  memcpy(original,data,sizeof data);
  for (unsigned n=0; n<=5; n++) {
    uint64_t want=0;
    for (unsigned i=0; i<n; i++) want+=data[1+i];
    uint64_t out[] = {0x123,Slots(data+1,n),0x456};
    if (out[0]!=0x123 || out[1]!=want || out[2]!=0x456) return 11;
    if (memcmp(data,original,sizeof data)!=0) return 12;
  }
  return 0;
}
`
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run("LLVM/"+api, func(t *testing.T) {
			ir, err := arm64ABI0TailResultTranslate(t, arm64ABI0TailLoopSource, declaration, triple, api, nil)
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_tail_loop", triple, ir, main, runner)
		})
	}
	// Removing the zero-count result write or relying on an entry GP value
	// must fail even though the result alloca happens to be zero-initialized.
	for _, changed := range []string{
		strings.Replace(arm64ABI0TailLoopSource, "CBZ R1,done", "CBZ R1,unwritten", 1) + "unwritten:\nRET\n",
		strings.Replace(arm64ABI0TailLoopSource, "MOVD n+8(FP),R1\n", "", 1),
	} {
		requireARM64GoABIInternalObject(t, changed)
		_, err := arm64ABI0TailResultTranslate(t, changed, declaration, triple, "text", nil)
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unwritten/empty-entry loop acquired result permission: %v", err)
		}
	}
}
