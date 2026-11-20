package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ANDNOriginalPortableValuesAndStatus(t *testing.T) {
	driver := strings.Replace(x86ANDNOriginalRuntimeDriver, "uint8_t out[40] = {0};", "uint8_t storage[42];\n  memset(storage,0xc3,sizeof(storage));\n  uint8_t *out=storage+1;", 1)
	driver = strings.Replace(driver, "  return 0;", "  if(storage[0]!=0xc3 || storage[41]!=0xc3) return 1;\n  for(int byte=36;byte<40;byte++) if(out[byte]!=0xc3) return 1;\n  return 0;", 1)
	if driver == x86ANDNOriginalRuntimeDriver || !strings.Contains(driver, "storage[41]") {
		t.Fatal("independent original ANDN driver lost its unaligned canaries")
	}
	for _, raw := range []bool{false, true} {
		source := x86ANDNOriginalRuntimeSource
		if raw {
			lines := strings.Split(source, "\n")
			for index, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "ANDN") {
					lines[index] = x86RawNumericalInstruction(t, "amd64", strings.TrimSpace(line))
				}
			}
			source = strings.Join(lines, "\n")
		}
		t.Run(fmt.Sprint("raw=", raw), func(t *testing.T) {
			x86TernaryGPOriginalPortableExecution(t, source, "func andnsemantics(out *[40]byte)", driver)
		})
	}
}

func TestX86ParallelBitsOriginalPortableValuesAndStatus(t *testing.T) {
	source, prototypes, checks, _ := x86ParallelBitsOriginalRuntimeFixture(t)
	driver := x86ParallelBitsOriginalRuntimeDriver(prototypes.String(), checks.String())
	driver = strings.Replace(driver, "uint8_t storage[9],out[16]={0};memcpy(storage+1,&mask,8);",
		"uint8_t storage[10],before[10],outStorage[18];\n  memset(storage,0xc3,sizeof(storage));\n  memset(outStorage,0xc3,sizeof(outStorage));\n  uint8_t *out=outStorage+1;\n  memcpy(storage+1,&mask,8);\n  memcpy(before,storage,sizeof(storage));", 1)
	driver = strings.Replace(driver, "fn(value,storage+1,out);uint64_t actual;",
		"fn(value,storage+1,out);\n  if(memcmp(storage,before,sizeof(storage)) || outStorage[0]!=0xc3 || outStorage[17]!=0xc3) return 1;\n  for(int byte=13;byte<16;byte++) if(out[byte]!=0xc3) return 1;\n  uint64_t actual;", 1)
	if !strings.Contains(driver, "outStorage[17]") || !strings.Contains(driver, "before,sizeof(storage)") {
		t.Fatal("independent parallel-bit driver lost its input/output canaries")
	}
	x86TernaryGPOriginalPortableExecution(t, source.String(), x86ParallelBitsOriginalDeclarations(), driver)
}

// Execute the original source's numerical values on the actual host. This is
// distinct from execution of the original BMI1/BMI2 physical opcode bytes.
func x86TernaryGPOriginalPortableExecution(t *testing.T, source, declaration, driver string) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
			if err != nil {
				t.Fatal("original source lost its ordered numerical inputs", err)
			}
			for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					compileAndRunRuntimeTestForTarget(t, llc, clang,
						fmt.Sprintf("ternary-%s-ir%d-%s", api, index, level[1:]), triple, text, driver, nil)
				}
			}
		})
	}
}
