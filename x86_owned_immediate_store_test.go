package plan9asm

import (
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Reuse the complete independent Yi32 boundary inventory and its byte/canary
// reference. Only the actual destination changes from a caller pointer to an
// explicitly defined module-owned object. C names that object, not defines it.
func x86OwnedImmediateStoreFixture(t *testing.T, arch string) (source, declarations, driver string, count int) {
	t.Helper()
	source, declarations, driver, count = x86NativeImmediateStoreFixture(arch)
	want := 66
	if arch == "386" {
		want = 42
	}
	if count != want || strings.Count(source, "-1(DI)(BX*2)") != count ||
		strings.Count(driver, "int main(void){uint8_t actual[32],expected[32];") != 1 {
		t.Fatal("complete original immediate boundary/reference inventory changed", count)
	}
	source = "GLOBL ·storage(SB),16,$32\n" +
		strings.ReplaceAll(source, "-1(DI)(BX*2)", "·storage+5(SB)")
	driver = strings.Replace(driver, "int main(void){uint8_t actual[32],expected[32];",
		"extern uint8_t storage[32];\nint main(void){uint8_t expected[32];", 1)
	driver = strings.ReplaceAll(driver, "actual", "storage")
	if strings.Count(driver, "memset(storage,") != count || strings.Count(driver, "memcmp(storage,") != count ||
		strings.Count(driver, "extern uint8_t storage[32];") != 1 {
		t.Fatal("owned counterpart lost full independent expected bytes or canaries")
	}
	return
}

func TestX86OwnedImmediateStoreCompleteGoEncodingValues(t *testing.T) {
	store := regexp.MustCompile(`(?m)^  store(?: volatile)? i([0-9]+) (-?[0-9]+), ptr [^\n]+, align 1$`)
	for _, arch := range []string{"386", "amd64"} {
		source, _, _, count := x86OwnedImmediateStoreFixture(t, arch)
		goAssemblerOracleOutput(t, arch, source, "", true)
		file := mustParseX86RawReturn(t, source)
		seen := 0
		for _, function := range file.Funcs {
			for _, instruction := range function.Instrs {
				if len(instruction.Args) != 2 || instruction.Args[0].Kind != OpImm ||
					instruction.Args[1].Kind != OpSym || instruction.Args[1].Sym != "·storage+5(SB)" {
					continue
				}
				seen++
				t.Run(arch+"/"+function.Sym, func(t *testing.T) {
					width := map[Op]int{"MOVB": 1, "MOVW": 2, "MOVL": 4, "MOVQ": 8, "MOVD": 8, "MOVDQ2Q": 8}[instruction.Op]
					if width == 0 {
						t.Fatal("unreviewed original immediate-store opcode", instruction.Op)
					}
					context, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
					context.goarch = arch
					before := output.Len()
					known, terminated, err := context.lowerMov(instruction.Op, instruction)
					if !known || terminated || err != nil {
						t.Fatal("original static immediate format emitter", known, terminated, err)
					}
					// This is private format emission, not public source/NUM or
					// native execution qualification. Observe only this instruction.
					matches := store.FindAllStringSubmatch(output.String()[before:], -1)
					if len(matches) != 1 || matches[0][1] != strconv.Itoa(width*8) {
						t.Fatal("one exact-width immediate store required", output.String()[before:])
					}
					value, err := strconv.ParseInt(matches[0][2], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					got, want := uint64(value), uint64(instruction.Args[0].Imm)
					if width == 8 {
						want = uint64(int64(int32(instruction.Args[0].Imm)))
					} else {
						mask := uint64(1)<<(width*8) - 1
						got, want = got&mask, want&mask
					}
					if got != want {
						t.Fatalf("original Go imm32 encoding differs: %s got %#x want %#x", instruction.Raw, got, want)
					}
				})
			}
		}
		if seen != count {
			t.Fatal("incomplete immediate byte-value inventory", seen, count)
		}
	}
}

func TestX86OwnedImmediateStoreCompleteFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		source, declarations, _, _ := x86OwnedImmediateStoreFixture(t, arch)
		for _, target := range x86AddressMemoryTargets(arch) {
			t.Run(target, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, arch, target, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, target, api)
						if err != nil || ir == "" {
							t.Fatal("complete original Go immediate boundaries with actual writable storage", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target, ir, level)
						}
					})
				}
			})
		}
	}
}

// Portable LLVM/C values on the actual host, not the stock-Go native ABI.
// The independent reference still checks every boundary and all 32 canaries.
func TestX86OwnedImmediateStorePortableValuesAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch := "amd64"
	if runtime.GOARCH == "386" {
		arch = "386"
	}
	source, declarations, driver, count := x86OwnedImmediateStoreFixture(t, arch)
	if count != 66 && arch != "386" || count != 42 && arch == "386" {
		t.Fatal("complete execution denominator changed", count)
	}
	goAssemblerOracleOutput(t, arch, source, "", true)
	target := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, target, api)
			if err != nil || ir == "" {
				t.Fatal("complete owned immediate source rejected", err)
			}
			for pipeline, text := range []string{ir, ir, x86DwordProductIROptimize(t, ir)} {
				level := 2
				if pipeline == 0 {
					level = 0
				}
				t.Run(fmt.Sprintf("pipeline%d", pipeline), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "owned-immediate-store", target, text, driver, nil, level)
				})
			}
		})
	}
}
