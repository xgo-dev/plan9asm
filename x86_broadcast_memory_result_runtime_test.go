package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Execute the entire memory-form directory through the result-checking path.
// The independent byte reference samples the last dword of each X/Y/Z result;
// this is portable LLVM execution, not original native AVX512 execution.
func TestX86BroadcastDataResultsLLVMRuntime(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	// These source-local broadcasts use portable byte/vector lowering. Keep
	// the original AMD64 Go oracle below, but execute LLVM on the actual host;
	// an x86-only floating comparison transport unnecessarily skipped ARM64.
	execution := x86FloatCompareExecution{llc: llc, compiler: []string{clang},
		triple: testTargetTriple(runtime.GOOS, runtime.GOARCH)}
	rows := x86BroadcastMemoryRows()
	for start := 0; start < len(rows); start += 64 {
		end := start + 64
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%d", start/64), func(t *testing.T) {
			var source, declarations, prototypes, checks strings.Builder
			source.WriteString(x86ScalarResultDataTable)
			for index, row := range rows[start:end] {
				name := fmt.Sprintf("broadcast%d", index)
				fmt.Fprintf(&declarations, "func %s(mask uint64) uint32\n", name)
				fmt.Fprintf(&prototypes, "extern uint32_t %s(uint64_t);\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVQ mask+0(FP),CX\nKMOVQ CX,K3\nMOVL $0x91929394,AX\nVPBROADCASTD AX,Z2\n%s\n", name, row)
				width := 16
				switch row[len(row)-2] {
				case 'Y':
					width = 32
					source.WriteString("VEXTRACTI128 $1,Y2,X2\n")
				case 'Z':
					width = 64
					source.WriteString("VEXTRACTI32X4 $3,Z2,X2\n")
				}
				source.WriteString("VPEXTRD $3,X2,AX\nMOVL AX,ret+8(FP)\nRET\n")
				op, _, _ := strings.Cut(strings.Fields(row)[0], ".")
				for _, spec := range x86BroadcastTestDirectory {
					if spec.name == op {
						masked, zeroing := 0, 0
						if strings.Contains(row, "K3,") {
							masked = 1
						}
						if strings.Contains(row, ".Z ") {
							zeroing = 1
						}
						fmt.Fprintf(&checks, "if (check(%s,%d,%d,%d,%d,%d)) return 1;\n", name, width, spec.bytes, spec.lane, masked, zeroing)
					}
				}
			}
			goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
			main := x86BroadcastDataResultDriver + prototypes.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							execution.compileAndRunLLVM(t, "data-broadcast-result", ir, main, level)
						})
					}
				})
			}
		})
	}
}

const x86BroadcastDataResultDriver = `
#include <stdint.h>
#include <stdio.h>
static int check(uint32_t (*fn)(uint64_t), int width, int bytes, int lane, int masked, int zeroing) {
  static const uint8_t input[32] = {
    0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01, 0,0,0,0,0,0,0,0,
    0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe, 0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10
  };
  const uint64_t masks[] = {0,1,5,UINT64_MAX,UINT64_C(1)<<63,UINT64_C(0xaaaaaaaaaaaaaaaa)};
  for (unsigned sample=0; sample<sizeof(masks)/sizeof(masks[0]); sample++) {
    uint32_t expected=0;
    for (int byte=0; byte<4; byte++) {
      int position=width-4+byte;
      int enabled=!masked || ((masks[sample]>>(position/lane))&1);
      uint8_t value=enabled ? input[position%bytes] : zeroing ? 0 : (uint8_t)(UINT32_C(0x91929394)>>(8*byte));
      expected |= (uint32_t)value<<(8*byte);
    }
    uint32_t actual=fn(masks[sample]);
    if (actual!=expected) {
      fprintf(stderr,"broadcast width=%d bytes=%d lane=%d masked=%d zero=%d sample=%u got=%08x want=%08x\n",
              width,bytes,lane,masked,zeroing,sample,actual,expected);
      return 1;
    }
  }
  return 0;
}
`
