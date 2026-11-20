package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86MOVBEOriginalRuntimeDriver = `
#include <stdint.h>
#include <string.h>
extern void movesemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[72] = {0};
  movesemantics(out);
  if (load64(out+8) != UINT64_C(0x1122334455661234)) return 10;
  if (load64(out+24) != UINT64_C(0x12345678)) return 11;
  if (load64(out+40) != UINT64_C(0x0123456789abcdef)) return 12;
  const uint8_t stores[14] = {0x77,0x88, 0x55,0x66,0x77,0x88, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
  if (memcmp(out+48, stores, sizeof(stores)) != 0) return 13;
  if (out[62] != 1 || out[63] != 1 || out[64] != 0 || out[65] != 1) return 14;
  return 0;
}
`

func TestX86MOVBERepairedOriginalPortableValuesAndFlags(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	driver := strings.Replace(x86MOVBEOriginalRuntimeDriver, "uint8_t out[72] = {0};",
		"uint8_t storage[74];\n  memset(storage,0xc3,sizeof(storage));\n  uint8_t *out=storage+1;", 1)
	driver = strings.Replace(driver, "  return 0;",
		"  if(storage[0]!=0xc3 || storage[73]!=0xc3) return 1;\n  for(int byte=66;byte<72;byte++) if(out[byte]!=0xc3) return 1;\n  return 0;", 1)
	if driver == x86MOVBEOriginalRuntimeDriver || !strings.Contains(driver, "storage[73]") {
		t.Fatal("independent unaligned MOVBE driver lost its canaries")
	}
	for _, raw := range []bool{false, true} {
		source := x86MOVBERepairedRuntimeSource(t)
		if raw {
			lines := strings.Split(source, "\n")
			for index, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "MOVBE") {
					lines[index] = x86RawNumericalInstruction(t, "amd64", strings.TrimSpace(line))
				}
			}
			source = strings.Join(lines, "\n")
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("raw=%t/%s", raw, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func movesemantics(out *[72]byte)", "amd64", triple, api)
				if err != nil {
					t.Fatal("Go-valid original MOVBE fixture rejected", err)
				}
				for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						compileAndRunRuntimeTestForTarget(t, llc, clang,
							fmt.Sprintf("movbe-%t-%s-ir%d-%s", raw, api, index, level[1:]), triple, text, driver, nil)
					}
				}
			})
		}
	}
	t.Log("actual-host portable byte-order values, partial-register preservation, FLAGS and unaligned canaries; not original MOVBE opcode execution")
}
