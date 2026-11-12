package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86UnlockedScalarRMWRuntimeFixture(arch string, native bool) (declarations, assembly, driver, reference string, count int) {
	word, cWord, suffix, slot := "uint64", "uint64_t", "Q", 8
	if arch == "386" {
		word, cWord, suffix, slot = "uint32", "uint32_t", "L", 4
	}
	var decl, source, goRows, prototypes, cRows strings.Builder
	decl.WriteString("package main\n")
	for _, row := range x86LockScalarRuntimeCases(arch) {
		if strings.HasPrefix(row.stem, "BT") {
			continue // Bit strings retain their separate typed and runtime family.
		}
		count++
		fmt.Fprintf(&decl, "func %s(memory *[128]byte,output *[8]uint64,offset,value,seed %s)\n", row.name, word)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", row.name, slot*5)
		fmt.Fprintf(&source, "MOV%s memory+0(FP),SI\nMOV%s output+%d(FP),DI\nMOV%s offset+%d(FP),AX\n",
			suffix, suffix, slot, suffix, slot*2)
		fmt.Fprintf(&source, "ADD%s AX,SI\nMOV%s value+%d(FP),CX\nMOV%s seed+%d(FP),DX\nPUSH%s DX\nPOPF%s\n",
			suffix, suffix, slot*3, suffix, slot*4, suffix, suffix)
		if native {
			source.WriteString("STMXCSR 24(DI)\n")
		}
		statusMask := x86ScalarRuntimeStatusMask(row.stem)
		// Refine the saved word in the original source, before any native
		// output store. A C-side mask alone cannot initialize unknown bits.
		fmt.Fprintf(&source, "%s\nPUSHF%s\nPOP%s AX\nAND%s $%d,AX\nMOV%s AX,0(DI)\nMOV%s CX,8(DI)\nMOV%s DX,16(DI)\n",
			row.body, suffix, suffix, suffix, statusMask, suffix, suffix, suffix)
		if native {
			source.WriteString("STMXCSR 32(DI)\n")
		}
		source.WriteString("RET\n")
		fmt.Fprintf(&goRows, "{%s,%q,%d,%t,%d},\n", row.name, row.stem, row.width, row.immediate, row.literal)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,uint64_t*,%s,%s,%s);\n", row.name, cWord, cWord, cWord)
		immediate := 0
		if row.immediate {
			immediate = 1
		}
		fmt.Fprintf(&cRows, "{%s,%q,%d,%d,UINT64_C(%d)},\n", row.name, row.stem, row.width, immediate, row.literal)
	}
	if strings.Contains(source.String(), "LOCK") {
		panic("ordinary scalar memory source acquired a LOCK prefix")
	}
	driver = strings.NewReplacer("@WORD@", word, "@ROWS@", goRows.String(),
		"lock observations", "unlocked observations").Replace(x86LockScalarOriginalReference)
	oracle := x86ScalarMemoryIndependentC + x86UnlockedScalarPortableDriverC
	if native {
		oracle = x86LockScalarIndependentC
	}
	reference = strings.NewReplacer("@WORD@", cWord, "@PROTOTYPES@", prototypes.String(),
		"@ROWS@", cRows.String(), "lock observations", "unlocked observations").Replace(oracle)
	return decl.String(), source.String(), driver, reference, count
}

func TestX86UnlockedScalarRMWObservationUsesOnlyDefinedStatus(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, native := range []bool{false, true} {
			_, source, _, _, count := x86UnlockedScalarRMWRuntimeFixture(arch, native)
			file, err := Parse(ArchAMD64, source)
			if err != nil || len(file.Funcs) != count {
				t.Fatal("complete observation source lost a kernel", arch, native, err)
			}
			for _, function := range file.Funcs {
				observations := 0
				for index, instruction := range function.Instrs {
					if instruction.Op != "PUSHFQ" && instruction.Op != "PUSHFL" {
						continue
					}
					if index == 0 || index+2 >= len(function.Instrs) {
						t.Fatal("saved FLAGS lost its complete source neighborhood")
					}
					operation := string(function.Instrs[index-1].Op)
					mask := int64(0x8d5)
					if strings.HasPrefix(operation, "AND") || strings.HasPrefix(operation, "OR") || strings.HasPrefix(operation, "XOR") {
						mask = 0x8c5
					}
					refinement := function.Instrs[index+2]
					if !strings.HasPrefix(string(refinement.Op), "AND") || len(refinement.Args) != 2 ||
						refinement.Args[0].Kind != OpImm || refinement.Args[0].Imm != mask ||
						refinement.Args[1].Kind != OpReg || refinement.Args[1].Reg != AX {
						t.Fatal("saved FLAGS borrowed undefined or unmodeled bits", arch, native, operation)
					}
					observations++
				}
				if observations != 1 {
					t.Fatal("ordinary kernel lost its single complete FLAGS observation", function.Sym)
				}
			}
		}
	}
}

func x86UnlockedScalarRMWPortableRuntime(t *testing.T, api string) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang are required")
	}
	arch, want := "amd64", 156
	if strconv.IntSize == 32 {
		arch, want = "386", 117
	}
	declarations, source, _, reference, count := x86UnlockedScalarRMWRuntimeFixture(arch, false)
	if count != want {
		t.Fatal("complete ordinary arithmetic/immediate-boundary denominator changed", count, want)
	}
	originalTriple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		originalTriple = "i386-unknown-linux-gnu"
	}
	x86LEAActualTargetGoObject(t, arch, originalTriple, source)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := x86OrderingHintTranslateAPI(t, api, source, declarations, arch, triple)
	if err != nil || ir == "" {
		t.Fatal("complete initialized ordinary memory/FLAGS source rejected", api, err)
	}
	for _, optimized := range []bool{false, true} {
		text := ir
		if optimized {
			text = x86DwordProductIROptimize(t, ir)
		}
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "ordinary-rmw", triple, text, reference, nil, level)
			})
		}
	}
	if !t.Failed() {
		t.Logf("%d complete ordinary kernels, %d observations per backend: memory bytes, defined/preserved FLAGS, source registers and canaries; portable LLVM, not original-Go native execution",
			count, count*292*2*8)
	}
}

func TestX86UnlockedScalarRMWPortableTextRuntime(t *testing.T) {
	x86UnlockedScalarRMWPortableRuntime(t, "text")
}

func TestX86UnlockedScalarRMWPortableModuleRuntime(t *testing.T) {
	x86UnlockedScalarRMWPortableRuntime(t, "module")
}

func TestX86UnlockedScalarRMWPortableGoRuntime(t *testing.T) {
	x86UnlockedScalarRMWPortableRuntime(t, "Go")
}

// The independent arithmetic is shared with the original-Go/native oracle.
// This portable driver observes no MXCSR or host-native x86 instruction.
const x86UnlockedScalarPortableDriverC = `
int main(void) {
    static const uint64_t edges[] = {0,1,15,16,17,127,128,255,256,32767,32768,65535,
        0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000,UINT64_MAX};
    const uint64_t sentinel = UINT64_C(0xa7a7a7a7a7a7a7a7);
    unsigned observations = 0;
    for (unsigned kernel = 0; kernel < sizeof(kernels)/sizeof(kernels[0]); kernel++) {
        const struct kernel *k = &kernels[kernel];
        for (unsigned sample = 0; sample < 292; sample++) {
            uint64_t a = sample/16, b = sample%16;
            if (sample >= 256) {
                a = edges[(sample-256)/2];
                b = edges[((sample-256)/2+1+6*(sample%2))%18];
            }
            b = (word)b;
            for (unsigned state = 0; state < 2; state++) {
                for (unsigned offset = 64; offset < 72; offset++) {
                    uint64_t seed = state ? 0x12 : 0x8c7, out[8];
                    uint8_t memory[128], expected[128];
                    for (unsigned i = 0; i < 128; i++) {
                        memory[i] = (i*73+19)^(sample*29);
                    }
                    store(memory, offset, k->width, a);
                    memcpy(expected, memory, 128);
                    for (unsigned i = 0; i < 8; i++) {
                        out[i] = sentinel;
                    }
                    uint64_t valid, flags = reference(k, expected, offset, b, seed, &valid);
                    k->fn(memory, out, offset, b, seed);
                    uint64_t word_mask = (word)~(word)0;
                    if (memcmp(memory, expected, 128) || (out[0]&valid) != flags ||
                        (out[1]&word_mask) != b || (out[2]&word_mask) != seed) {
                        fprintf(stderr, "%s/%u sample=%u offset=%u flags=%llx/%llx mask=%llx\n",
                            k->op, k->width, sample, offset, (unsigned long long)out[0],
                            (unsigned long long)flags, (unsigned long long)valid);
                        return 1;
                    }
                    for (unsigned i = 0; i < 3; i++) {
                        if ((out[i]&~word_mask) != (sentinel&~word_mask)) return 2;
                    }
                    for (unsigned i = 3; i < 8; i++) {
                        if (out[i] != sentinel) return 3;
                    }
                    observations++;
                }
            }
        }
    }
    unsigned expected = (unsigned)(sizeof(kernels)/sizeof(kernels[0]))*292*2*8;
    if (observations != expected) return 4;
    printf("unlocked observations %u\n", observations);
    return 0;
}
`
