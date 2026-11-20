package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The independent integer model runs on the actual development host. This
// verifies translated values, not original SSSE3/AVX2/AVX512 execution.
func TestX86PackedAbsSignWholeBytesMinimumWrapAndFlags(t *testing.T) {
	x86PackedAbsSignOriginalProgramUnchanged(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("portable ABS/sign numerical oracle requires LLVM22 llc/clang")
	}
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	rows := x86PackedAbsSignOracleRows()
	for start := 0; start < len(rows); start += 48 {
		end := start + 48
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("%d-%d", start, end), func(t *testing.T) {
			var source, declarations, prototypes, metadata strings.Builder
			flag := func(value bool) int {
				if value {
					return 1
				}
				return 0
			}
			for index := start; index < end; index++ {
				row := rows[index]
				body, declaration := x86PackedAbsSignInitializedSource(index, row, arch)
				source.WriteString(body)
				declarations.WriteString(declaration)
				fmt.Fprintf(&prototypes, "extern void AbsSign%d(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", index)
				fmt.Fprintf(&metadata, "{AbsSign%d,%d,%d,%d,%d,%d,%d,%d},\n", index, row.width, row.bits/8,
					flag(row.sign), flag(row.legacy), flag(row.source == "broadcast"),
					flag(row.mode == "merge" || row.mode == "zero"), flag(row.mode == "zero"))
			}
			original := source.String()
			x86LEAActualTargetGoObject(t, arch, triple, original)
			legacyMemory := 0
			for _, row := range rows[start:end] {
				if row.legacy && row.memory {
					legacyMemory++
				}
			}
			// This companion owns mathematics on the actual host, not the
			// original x86 alignment exception. Preserve legacy writeback by
			// transporting only the checked memory source through an unused X
			// bank. Actual native objects/faults have independent owners.
			instrumented := x86PackedAbsSignPortableMemoryInstrumentation(t, original, legacyMemory)
			ir, err := x86ScalarFPBitViewAPI(t, instrumented, declarations.String(), arch, triple, "Go")
			if err != nil {
				t.Fatal("complete initialized ABS/sign source failed before independent minimum-wrap comparison", err)
			}
			ir, err = x86PackedAbsSignPortableIR(instrumented, ir, arch)
			if err != nil {
				t.Fatal("portable ABS/sign IR projection failed", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "packed-abs-sign-whole-bytes", triple, ir,
				fmt.Sprintf(x86PackedAbsSignWholeBytesC, prototypes.String(), metadata.String()))
		})
	}
}

// Instrumentation is deliberately limited to these six original legacy m128
// instructions. It does not change their opcode to VEX (which would clear
// upper aliases), infer backing, or claim execution of the original program.
func x86PackedAbsSignPortableMemoryInstrumentation(t *testing.T, source string, expected int) string {
	t.Helper()
	originalHash := sha256.Sum256([]byte(source))
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal("portable ABS/sign instrumentation requires the complete parsed original", err)
	}
	used := [8]bool{}
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			for _, arg := range ins.Args {
				register := string(arg.Reg)
				if arg.Kind == OpReg && len(register) > 1 && strings.ContainsRune("XYZ", rune(register[0])) {
					index, err := strconv.Atoi(register[1:])
					if err != nil {
						t.Fatal("unrecognized original vector alias", register)
					}
					if index < len(used) {
						used[index] = true
					}
				}
			}
		}
	}
	scratch := -1
	for index, live := range used {
		if !live {
			scratch = index
			break
		}
	}
	if scratch < 0 {
		t.Fatal("complete original ABS/sign program has no genuinely unused mode32 X bank")
	}
	replacements := make(map[string]string)
	count := 0
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			switch ins.Op {
			case "PABSB", "PABSW", "PABSD", "PSIGNB", "PSIGNW", "PSIGND":
				if len(ins.Args) != 2 {
					t.Fatal("portable instrumentation requires the exact legacy two-operand grammar", ins)
				}
				if ins.Args[0].Kind == OpReg {
					continue
				}
				if ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpReg || !strings.HasPrefix(string(ins.Args[1].Reg), "X") {
					t.Fatal("portable instrumentation refuses any different legacy storage/operand role", ins)
				}
				key := strings.TrimSpace(ins.Raw)
				if key == "" {
					t.Fatal("portable instrumentation lost original source spelling")
				}
				// VMOVDQU is the portable unaligned byte transport. MOVOU's
				// native bridge would itself introduce x86 inline assembly.
				replacements[key] = fmt.Sprintf("VMOVDQU %s,X%d\n%s X%d,%s", ins.Args[0], scratch, ins.Op, scratch, ins.Args[1])
				count++
			}
		}
	}
	if count != expected {
		t.Fatal("portable original legacy m128 inventory changed", count, expected)
	}
	lines := strings.Split(source, "\n")
	replaced := 0
	for index, line := range lines {
		if replacement, found := replacements[strings.TrimSpace(line)]; found {
			lines[index] = replacement
			replaced++
		}
	}
	if replaced != expected || originalHash != sha256.Sum256([]byte(source)) {
		t.Fatal("portable instrumentation did not bind every unchanged original source instruction", replaced, expected)
	}
	t.Logf("portable ABS/sign mathematical instrumentation: original sha256=%x checked legacy m128 replacements=%d unused X bank=%d; not original alignment/fault execution", originalHash, replaced, scratch)
	return strings.Join(lines, "\n")
}

const x86PackedAbsSignWholeBytesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
%s
struct kernel {
    void (*run)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
    unsigned width,lane,sign,legacy,broadcast,masked,zeroing;
};
static const struct kernel kernels[]={%s};
static uint64_t read_word(const uint8_t *p,unsigned bytes) {
    uint64_t value=0;
    for (unsigned i=0;i<bytes;i++) value|=(uint64_t)p[i]<<(8*i);
    return value;
}
static void write_word(uint8_t *p,unsigned bytes,uint64_t value) {
    for (unsigned i=0;i<bytes;i++) p[i]=(uint8_t)(value>>(8*i));
}
int main(void) {
    unsigned outcomes=0;
    for (unsigned row=0;row<sizeof(kernels)/sizeof(kernels[0]);row++) {
        struct kernel k=kernels[row];
        unsigned bits=k.lane*8,lanes=k.width/k.lane;
        uint64_t sign=UINT64_C(1)<<(bits-1),all=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1;
        const uint64_t patterns[]={0,1,sign-1,sign,all-1,all,UINT64_C(0x1122334455667788)&all};
        const uint64_t controls[]={all,0,1,sign,sign-1};
        const uint64_t masks[]={0,1,UINT64_C(1)<<(lanes-1),UINT64_C(0x5555555555555555),
            UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX};
        for (unsigned sample=0;sample<7;sample++) for (unsigned mask=0;mask<6;mask++) {
            uint8_t input[64],control[64],old[64],out[80],expected[80];
            for (unsigned at=0;at<64;at+=k.lane) {
                write_word(input+at,k.lane,patterns[(sample+at/k.lane)%%7]);
                write_word(control+at,k.lane,controls[(sample+at/k.lane)%%5]);
                write_word(old+at,k.lane,patterns[(sample+at/k.lane+3)%%7]);
            }
            uint8_t beforeInput[64],beforeControl[64],beforeOld[64];
            memcpy(beforeInput,input,64);memcpy(beforeControl,control,64);memcpy(beforeOld,old,64);
            memset(out,0xc3,sizeof(out));memset(expected,0xc3,sizeof(expected));
            memset(expected,0,64);
            if (k.legacy) memcpy(expected,old,64);
            for (unsigned lane=0;lane<lanes;lane++) {
                unsigned at=lane*k.lane;
                uint64_t data=read_word(k.sign&&k.legacy?old+at:input+(k.broadcast?0:at),k.lane);
                uint64_t result=(data&sign)?(UINT64_C(0)-data)&all:data;
                if (k.sign) {
                    uint64_t c=read_word(control+at,k.lane);
                    result=!c?0:(c&sign)?(UINT64_C(0)-data)&all:data;
                }
                if (k.masked && !(masks[mask]>>lane&1)) result=k.zeroing?0:read_word(old+at,k.lane);
                write_word(expected+at,k.lane,result);
            }
            expected[64]=1;
            k.run(out,input,control,old,masks[mask]);
            if (memcmp(out,expected,sizeof(out)) || memcmp(input,beforeInput,64) ||
                    memcmp(control,beforeControl,64) || memcmp(old,beforeOld,64)) {
                fprintf(stderr,"ABS/sign row=%%u sample=%%u mask=%%u\n",row,sample,mask);
                for (unsigned i=0;i<sizeof(out);i++) if (out[i]!=expected[i])
                    fprintf(stderr,"byte %%u got %%02x want %%02x\n",i,out[i],expected[i]);
                return 1;
            }
            outcomes++;
        }
    }
    if (outcomes!=42*sizeof(kernels)/sizeof(kernels[0])) return 2;
    printf("portable ABS/sign full64/minimum-wrap/CF/input-output-canary outcomes %%u failures 0\n",outcomes);
    return 0;
}
`
