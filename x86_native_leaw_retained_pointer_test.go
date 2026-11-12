package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86NativeLEAWRetainedPointerSource(arch, variant, control string) (string, string) {
	word, move, suffix, number := goWordSize(arch), "MOVQ", "Q", "0x1122334455667788"
	if arch == "386" {
		move, suffix, number = "MOVL", "L", "0x55667788"
	}
	var source strings.Builder
	if control == "foreign address" {
		source.WriteString("GLOBL oldAddress<>(SB),8,$8\n")
	}
	fmt.Fprintf(&source, "TEXT ·Retain(SB),4,$0-%d\n%s out+0(FP),DI\n%s base+%d(FP),SI\nMOVL index+%d(FP),DX\n",
		3*word+4, move, move, word, 3*word)
	source.WriteString("MOVL $0x7fffffff,CX\nADDL $1,CX\nSTC\nSTD\n")
	switch control {
	case "unknown old":
		// Direct/copied variants retain an independently valid SI address;
		// only the unchanged upper destination bytes have no producer.
	case "numeric upper":
		fmt.Fprintf(&source, "%s $%s,AX\n", move, number)
	case "foreign address":
		lea := "LEAQ"
		if arch == "386" {
			lea = "LEAL"
		}
		fmt.Fprintf(&source, "%s oldAddress<>(SB),AX\n", lea)
	default:
		if variant == "Copied" {
			fmt.Fprintf(&source, "%s old+%d(FP),BX\n%s BX,AX\n", move, 2*word, move)
		} else {
			fmt.Fprintf(&source, "%s old+%d(FP),AX\n", move, 2*word)
		}
	}
	base := "SI"
	if variant == "Alias" {
		base = "AX" // Both effective-address reads precede this same destination's partial write.
	}
	fmt.Fprintf(&source, "LEAW -7(%s)(DX*8),AX\n", base)
	if control == "nonadjacent" {
		source.WriteString("NOP\n")
	}
	fmt.Fprintf(&source, "%s AX,1(DI)\n", move)
	if control == "reuse" {
		fmt.Fprintf(&source, "%s AX,9(DI)\n", move)
	} else if control == "dereference" {
		source.WriteString("MOVB (AX),BX\n")
	}
	fmt.Fprintf(&source, "PUSHF%s\nPOP%s CX\nANDL $0xcd5,CX\nMOVL CX,32(DI)\nCLD\nRET\n", suffix, suffix)
	return source.String(), "func Retain(out *[48]byte,base,old *byte,index uint32)\n"
}

func x86NativeLEAWRetainedPointerBatch(arch, control string) (string, string) {
	var source, declarations strings.Builder
	for _, variant := range []string{"Direct", "Copied", "Alias"} {
		body, declaration := x86NativeLEAWRetainedPointerSource(arch, variant, control)
		source.WriteString(strings.ReplaceAll(body, "Retain", "Retain"+variant))
		declarations.WriteString(strings.ReplaceAll(declaration, "Retain", "Retain"+variant))
	}
	return source.String(), declarations.String()
}

func TestX86NativeLEAWRetainedPointerFiveTargetThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for actual retained-pointer LEAW objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86NativeLEAWRetainedPointerBatch(target.arch, "")
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("actual old typed pointer's unchanged high bytes cannot be observed beside the new LEAW low16", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "retained-pointer-leaw.ll", "retained-pointer-leaw.o", body)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				})
			}
		})
	}
}

func TestX86NativeLEAWRetainedNumericUpperControls(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86NativeLEAWRetainedPointerBatch(arch, "numeric upper")
		triple := x86AddressMemoryTargets(arch)[0]
		x86LEAActualTargetGoObject(t, arch, triple, source)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api); err != nil || ir == "" {
					t.Fatal("independently initialized numerical upper bytes changed under the same LEAW/store/source extent", err)
				}
			})
		}
	}
}

func TestX86NativeLEAWRetainedPointerNeedsOldIdentityAndAdjacency(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, variant := range []string{"Direct", "Copied", "Alias"} {
			for _, control := range []string{"unknown old", "foreign address", "nonadjacent", "reuse", "dereference"} {
				source, declaration := x86NativeLEAWRetainedPointerSource(arch, variant, control)
				triple := x86AddressMemoryTargets(arch)[0]
				x86LEAActualTargetGoObject(t, arch, triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+variant+"/"+control+"/"+api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unknown/foreign upper bytes or an intervening effect acquired an old typed pointer's one-store observation", err)
						}
					})
				}
			}
		}
	}
}

const x86NativeLEAWRetainedPointerC = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
extern void RetainDirect(uint8_t*,const uint8_t*,const uint8_t*,uint32_t);
extern void RetainCopied(uint8_t*,const uint8_t*,const uint8_t*,uint32_t);
extern void RetainAlias(uint8_t*,const uint8_t*,const uint8_t*,uint32_t);
typedef void (*operation)(uint8_t*,const uint8_t*,const uint8_t*,uint32_t);
int main(void) {
    const operation programs[]={RetainDirect,RetainCopied,RetainAlias};
    uint8_t live[16]={0};
    const uintptr_t bases[]={(uintptr_t)live,0,UINTPTR_MAX-3,UINT32_MAX-3,UINT16_MAX-3};
    const uintptr_t oldValues[]={(uintptr_t)(live+3),0,UINTPTR_MAX,UINT32_MAX-1,UINT16_MAX+5};
    const uint32_t indexes[]={0,1,UINT16_MAX,UINT32_MAX};
    unsigned observations=0;
    for (unsigned op=0;op<3;op++) for (unsigned b=0;b<5;b++)
    for (unsigned old=0;old<5;old++) for (unsigned index=0;index<4;index++) {
        uint8_t packet[80],want[80];
        memset(packet,0xa5,sizeof(packet)); memcpy(want,packet,sizeof(packet));
        uintptr_t input=op==2 ? oldValues[old] : bases[b];
        uintptr_t address=input+(uintptr_t)indexes[index]*8-7;
        uintptr_t expected=(oldValues[old]&~(uintptr_t)UINT16_MAX)|(address&UINT16_MAX);
        memcpy(want+17,&expected,sizeof(expected));
        uint32_t flags=UINT32_C(0xc95); /* ADD signed overflow, STC, STD; known six status plus DF. */
        memcpy(want+48,&flags,sizeof(flags));
        programs[op](packet+16,(const uint8_t*)bases[b],(const uint8_t*)oldValues[old],indexes[index]);
        if (memcmp(packet,want,sizeof(packet))) {
            fprintf(stderr,"retained-pointer LEAW op=%u base=%u old=%u index=%u\n",op,b,old,index);
            return 1;
        }
        for (unsigned byte=0;byte<sizeof(live);byte++) if (live[byte]) return 2;
        observations++;
    }
    if (observations!=300) return 3;
    puts("LEAW_RETAINED_POINTER_300_VALUES_STATUS_CANARIES_PASS");
    return 0;
}
`

func TestX86NativeLEAWRetainedPointerPortableValuesStatusAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required for retained-pointer LEAW values")
	}
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	source, declarations := x86NativeLEAWRetainedPointerBatch(arch, "")
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("retained typed-pointer program rejected before independent value/status/canary execution", err)
			}
			native := x86ScalarFloatIntegerNativeTarget(arch, triple)
			for _, variant := range []string{"Direct", "Copied", "Alias"} {
				if err := x86NativeLEAWCheckTargetDFBody(x86StringMemoryFunction(t, ir, "Retain"+variant), native); err != nil {
					t.Fatal("actual target lost its virtual/native direction lifecycle", variant, err)
				}
			}
			for _, pipeline := range []struct {
				text  string
				level int
			}{{ir, 0}, {ir, 2}, {x86DwordProductIROptimize(t, ir), 2}} {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "leaw-retained-pointer", triple, pipeline.text, x86NativeLEAWRetainedPointerC, nil, pipeline.level)
			}
		})
	}
	t.Log("300 input triples x 3 APIs x 3 pipelines; unmodified actual-target LLVM executes virtual DF, pointer values, status and canaries; physical DF remains separate matching-x86 execution")
}
