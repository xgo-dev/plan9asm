package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarShiftArchitecturalChoiceStableRepeatedObservations(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required for repeated scalar output observations")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	rows := []x86ShiftChoiceCase{{text: "SHLW CL,BX,AX"}, {text: "SHRW CL,BX,AX"}}
	code := x86ShiftChoiceOriginalBytes(t, "amd64", rows)
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprint("raw=", raw), func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows {
				var original []byte
				if raw {
					original = code[index]
				}
				body, declaration := x86ShiftChoiceSource("amd64", row.text, original, "", true)
				// Independent repeated consumers must see the same per-producer
				// choices, including AF in both LAHF observations. No arithmetic
				// or other FLAGS writer may intervene between these observations.
				body = strings.TrimSuffix(body, "RET\n") + "SETCS 38(DI)\nSETOS 39(DI)\nSETEQ 40(DI)\nSETMI 41(DI)\nSETPS 42(DI)\nLAHF\nMOVB AH,43(DI)\nRET\n"
				name := fmt.Sprint("StableShift", index)
				source.WriteString(strings.ReplaceAll(body, "Choice", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Choice", name))
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("actual initialized scalar choices lost their repeated consumers", err)
					}
					for _, pipeline := range []struct {
						input string
						level int
					}{{ir, 0}, {ir, 2}, {x86DwordProductIROptimize(t, ir), 2}} {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "scalar-stable-choices", triple,
							pipeline.input, x86ShiftChoiceStableC, nil, pipeline.level)
					}
				})
			}
		})
	}
	t.Log("two original W-double opcodes x 7 values x 256 counts x named/raw x 3 APIs x 3 optimization paths; exact defined results/FLAGS, preserved high bytes/canaries and same-producer repeated choices; portable integer LLVM, not native FLAGS execution")
}

const x86ShiftChoiceStableC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void StableShift0(uint8_t*,uint8_t*,uint64_t,uint64_t,uint64_t);
extern void StableShift1(uint8_t*,uint8_t*,uint64_t,uint64_t,uint64_t);
int main(void) {
    void (*functions[])(uint8_t*,uint8_t*,uint64_t,uint64_t,uint64_t)={StableShift0,StableShift1};
    const uint64_t samples[]={0,1,UINT64_MAX,UINT64_C(0x8000000080000000),
        UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(0x8877665544332211)};
    unsigned observations=0;
    for(unsigned k=0;k<2;k++) for(unsigned n=0;n<256;n++) for(unsigned s=0;s<7;s++) {
        uint8_t packet[80],want[80],memory[16],before[16];
        for(unsigned i=0;i<80;i++) packet[i]=(uint8_t)(i*37+91);
        for(unsigned i=0;i<16;i++) memory[i]=(uint8_t)(i*19+43);
        memcpy(want,packet,80);memcpy(before,memory,16);
        const uint64_t x=samples[s],y=samples[(s+3)%7];
        unsigned count=n&31,cf=1,pf=1,af=1,zf=0,sf=1,of=1;
        uint16_t value=(uint16_t)x,source=(uint16_t)y,old=value;
        unsigned flagmask=0x8d5;
        if(count>16) flagmask=0;
        else if(count) {
            for(unsigned i=0;i<count;i++) {
                if(k==0) {cf=value>>15;value=(uint16_t)((value<<1)|((source>>(15-i))&1));}
                else {cf=value&1;value=(uint16_t)((value>>1)|(((source>>i)&1)<<15));}
            }
            zf=value==0;sf=value>>15;pf=(__builtin_popcount((uint8_t)value)&1)==0;
            flagmask&=~0x10u;
            if(count==1) of=(old^value)>>15;else flagmask&=~0x800u;
        }
        functions[k](packet+8,memory,x,y,n|UINT64_C(0x1234567800000000));
        uint64_t got;memcpy(&got,packet+8,8);
        uint64_t expected=(x&~UINT64_C(0xffff))|(count>16?(got&0xffff):value);
        memcpy(want+8,&expected,8);
        const unsigned bits[]={1,0x800,0x40,0x80,4};
        const unsigned flags[]={cf,of,zf,sf,pf};
        for(unsigned i=0;i<5;i++) {
            uint8_t actual=packet[40+i];
            if(actual>1||actual!=packet[46+i]||((flagmask&bits[i])&&actual!=flags[i])) {
                fprintf(stderr,"scalar stable FLAGS k%u count%u sample%u flag%u\n",k,n,s,i);return 1;
            }
            want[40+i]=want[46+i]=actual;
        }
        unsigned lahf=packet[45],lahfmask=2|(flagmask&0xd5);
        unsigned expectedLahf=2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7);
        if(lahf!=packet[51]||(lahf&0x2a)!=2||(lahf&lahfmask)!=(expectedLahf&lahfmask)||
            (lahf&1)!=packet[40]||((lahf>>2)&1)!=packet[44]||
            ((lahf>>6)&1)!=packet[42]||((lahf>>7)&1)!=packet[43]) return 2;
        want[45]=want[51]=(uint8_t)lahf;
        if(memcmp(packet,want,80)||memcmp(memory,before,16)) {
            fprintf(stderr,"scalar stable values/canaries k%u count%u sample%u\n",k,n,s);return 3;
        }
        observations++;
    }
    if(observations!=3584) return 4;
    puts("SCALAR_SAME_PRODUCER_3584_DEFINED_AND_CHOICE_OBSERVATIONS_PASS");
    return 0;
}
`
