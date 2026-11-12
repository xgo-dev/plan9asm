package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86ADXOriginalRuntimeDriver = `
#include <stdint.h>
#include <string.h>
extern void adxsemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[72] = {0};
  adxsemantics(out);
  if (load64(out + 0) != 0) return 10;
  const uint8_t adcx_flags[4] = {1, 1, 0, 1};
  for (int i = 0; i < 4; i++) if (out[8+i] != adcx_flags[i]) return 20+i;
  if (load64(out + 16) != 0) return 30;
  const uint8_t adox_flags[4] = {1, 1, 0, 1};
  for (int i = 0; i < 4; i++) if (out[24+i] != adox_flags[i]) return 40+i;
  if (load64(out + 40) != 0) return 50;
  const uint8_t adcxq_flags[3] = {1, 0, 1};
  for (int i = 0; i < 3; i++) if (out[48+i] != adcxq_flags[i]) return 60+i;
  if (load64(out + 56) != 0) return 70;
  const uint8_t adoxq_flags[4] = {1, 1, 0, 1};
  for (int i = 0; i < 4; i++) if (out[64+i] != adoxq_flags[i]) return 80+i;
  return 0;
}
`

// This executes the unchanged source's integer values and independent carry
// chains on the actual host. Native original ADX execution remains required.
func TestX86ADXOriginalSourcePortableValuesAndCarryChains(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	driver := strings.Replace(x86ADXOriginalRuntimeDriver, "uint8_t out[72] = {0};", "uint8_t storage[74];\n  memset(storage,0xc3,sizeof(storage));\n  uint8_t *out=storage+1;", 1)
	driver = strings.Replace(driver, "  return 0;", "  if(storage[0]!=0xc3 || storage[73]!=0xc3) return 1;\n  return 0;", 1)
	if driver == x86ADXOriginalRuntimeDriver || !strings.Contains(driver, "storage[73]") {
		t.Fatal("independent unaligned driver lost its canaries")
	}
	for _, raw := range []bool{false, true} {
		source := x86ADXOriginalRuntimeSource
		if raw {
			source = x86ADXOriginalRawSource(source)
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("raw=%t/%s", raw, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func adxsemantics(out *[72]byte)", "amd64", triple, api)
				if err != nil {
					t.Fatal("complete original independent carry-chain source rejected", err)
				}
				for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						compileAndRunRuntimeTestForTarget(t, llc, clang, fmt.Sprintf("adx-%t-%s-ir%d-%s", raw, api, index, level[1:]), triple, text, driver, nil)
					}
				}
			})
		}
	}
}
