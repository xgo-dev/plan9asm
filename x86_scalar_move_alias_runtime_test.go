package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// These integer-only programs run the translated IR on the actual host. Go
// independently assembles both source modes; this is not native x86 execution.
// Mode32 has no host-pointer argument, so a 64-bit host cannot mask a truncated
// 386 native address. Its memory operations remain in the five-target owner.
func TestX86ScalarMoveAliasesPortableValuesFlagsAndMemory(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			word, move, ctype, gotype := goWordSize(arch), "MOVQ", "uint64_t", "uint64"
			if arch == "386" {
				move, ctype, gotype = "MOVL", "uint32_t", "uint32"
			}
			var source, declarations, prototypes strings.Builder
			for _, op := range []string{"MOVQL", "MOVLQZX"} {
				name := "Alias" + op
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),AX\n%s seed+%d(FP),BX\n"+
					"CMPL BX,$0\n%s AX,BX\nJNE done%s\nADDL $7,BX\ndone%s:\n%s BX,ret+%d(FP)\nRET\n",
					name, 3*word, move, move, word, op, name, name, move, 2*word)
				fmt.Fprintf(&declarations, "func %s(x,seed %s) %s\n", name, gotype, gotype)
				fmt.Fprintf(&prototypes, "extern %s %s(%s,%s);\n", ctype, name, ctype, ctype)
			}
			if arch == "amd64" {
				for _, op := range []string{"MOVQL", "MOVLQZX"} {
					body, declaration := scalarMoveAliasFunction("Memory"+op, arch, op, true)
					source.WriteString(body)
					declarations.WriteString(declaration)
				}
			}
			x86LEAActualTargetGoObject(t, arch, map[string]string{
				"amd64": "x86_64-unknown-linux-gnu", "386": "i386-unknown-linux-gnu",
			}[arch], source.String())
			driver := scalarMoveAliasPortableOracle(ctype, prototypes.String(), arch == "amd64")
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized scalar alias executable rejected", err)
					}
					x86ConflictFunnelPortableRuntime(t, llc, clang, "scalar_move_alias", triple, ir, driver)
				})
			}
		})
	}
}

func scalarMoveAliasPortableOracle(ctype, prototypes string, memory bool) string {
	driver := `
#include <stdint.h>
#include <string.h>
` + prototypes + `
static const uint64_t inputs[]={0,1,UINT64_C(0x80000000),UINT64_C(0xffffffff),
    UINT64_C(0x1234567800000000),UINT64_C(0x1234567880000001),
    UINT64_C(0xffffffff12345678),UINT64_MAX};
static const uint64_t seeds[]={0,UINT64_MAX,UINT64_C(0x8765432100000000),
    UINT64_C(0x76543210aabbccdd)};
typedef ` + ctype + ` Word;
static int registers(void) {
    Word (*rows[])(Word,Word)={AliasMOVQL,AliasMOVLQZX};
    unsigned observations=0;
    for(unsigned repeat=0;repeat<16;repeat++) {
        for(unsigned r=0;r<2;r++) {
            for(unsigned v=0;v<8;v++) {
                for(unsigned s=0;s<4;s++) {
                    uint32_t low=(uint32_t)inputs[v];
                    Word want=(uint32_t)(low+((uint32_t)seeds[s]==0?7u:0u));
                    if(rows[r]((Word)inputs[v],(Word)seeds[s])!=want) return 1;
                    observations++;
                }
            }
        }
    }
    return observations==1024?0:2;
}
`
	if memory {
		driver += `
extern uint64_t MemoryMOVQL(uint8_t *,uint64_t);
extern uint64_t MemoryMOVLQZX(const uint8_t *);
static int memory(void) {
    unsigned stores=0,loads=0;
    for(unsigned repeat=0;repeat<16;repeat++) {
        for(unsigned v=0;v<8;v++) {
            uint8_t actual[16],want[16],before[16];
            for(unsigned b=0;b<16;b++) actual[b]=want[b]=(uint8_t)(0xa5+b*13+repeat);
            for(unsigned b=0;b<4;b++) want[b+3]=(uint8_t)(inputs[v]>>(8*b));
            if(MemoryMOVQL(actual+2,inputs[v])!=(uint32_t)inputs[v] ||
               memcmp(actual,want,sizeof(actual))) return 3;
            stores++;
            for(unsigned b=0;b<16;b++) actual[b]=before[b]=(uint8_t)(v*37+b*19+repeat);
            uint32_t expected=0;
            for(unsigned b=0;b<4;b++) expected|=(uint32_t)before[b+3]<<(8*b);
            if(MemoryMOVLQZX(actual+2)!=expected || memcmp(actual,before,sizeof(actual))) return 4;
            loads++;
        }
    }
    return stores==128&&loads==128?0:5;
}
int main(void) {return registers() || memory();}
`
	} else {
		driver += "\nint main(void) {return registers();}\n"
	}
	return driver
}
