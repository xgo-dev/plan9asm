package plan9asm

import (
	"fmt"
	"testing"
)

// The initialized mathematical reference is independent of layout, result
// routing, LLVM allocas and the capability analysis. Original-Go execution is
// retained in its own root and is not counted as translated execution.
func TestCrossLinuxRuntimeMatrixARM64ABI0TailResultLLVMNumerics(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tail := range []string{"B", "JMP", "RET"} {
		for _, tuple := range []bool{false, true} {
			declaration, source := arm64ABI0TailResultFixture(tuple, tail)
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(fmt.Sprintf("tuple=%t/%s/%s", tuple, tail, api), func(t *testing.T) {
					ir, err := arm64ABI0TailResultTranslate(t, source, declaration, triple, api, nil)
					if err != nil {
						t.Fatal(err)
					}
					prototype := "extern uint64_t Slots(uint64_t);"
					observation := `out[1] = Slots(value);
    if (out[1] != value + UINT64_C(7) || out[2] != UINT64_C(0xdef)) return 11;`
					if tuple {
						prototype = "struct pair { uint64_t low, high; };\nextern struct pair Slots(uint64_t);"
						observation = `struct pair got = Slots(value);
    out[1] = got.low;
    out[2] = got.high;
    if (out[1] != value + UINT64_C(7) || out[2] != value - UINT64_C(3)) return 12;`
					}
					main := `#include <stdint.h>
#include <string.h>
` + prototype + `
int main(void) {
  uint64_t values[] = {0, 1, 3, 99, UINT64_C(1)<<63, (UINT64_C(1)<<63)-1, UINT64_MAX};
  uint64_t original[7];
  memcpy(original, values, sizeof values);
  for (unsigned i = 0; i < 7; i++) {
    uint64_t value = values[i];
    uint64_t out[4] = {UINT64_C(0xabc), UINT64_C(0xbad), UINT64_C(0xdef), UINT64_C(0x987)};
    ` + observation + `
    if (out[0] != UINT64_C(0xabc) || out[3] != UINT64_C(0x987)) return 13;
  }
  if (memcmp(original, values, sizeof values) != 0) return 14;
  return 0;
}
`
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_tail_result", triple, ir, main, runner)
				})
			}
		}
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run("empty/"+tail+"/"+api, func(t *testing.T) {
				source := fmt.Sprintf(`TEXT ·Slots(SB),516,$0-8
MOVD $out+0(FP),R8
%s resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
MOVD $99,R11
MOVD R11,(R8)
RET
`, tail)
				ir, err := arm64ABI0TailResultTranslate(t, source, "func Slots() (out uint64)", triple, api, nil)
				if err != nil {
					t.Fatal(err)
				}
				const main = `#include <stdint.h>
extern uint64_t Slots(void);
int main(void) {
  uint64_t out[3] = {UINT64_C(0xabc), UINT64_C(0xbad), UINT64_C(0xdef)};
  out[1] = Slots();
  return out[0] == UINT64_C(0xabc) && out[1] == 99 && out[2] == UINT64_C(0xdef) ? 0 : 15;
}
`
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_tail_empty", triple, ir, main, runner)
			})
		}
	}
}
