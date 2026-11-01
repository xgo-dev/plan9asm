package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86MMXStreamingOracleSources() (string, string, string, string) {
	var declarations, assembly, c, goTest strings.Builder
	declarations.WriteString("package oracle\n")
	c.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	var names []string
	var offsets []string
	for register := 0; register < 8; register++ {
		for index, address := range []string{"0(DI)", "0(DI)(DX*8)"} {
			name := fmt.Sprintf("Stream%d", len(names))
			names = append(names, name)
			offsets = append(offsets, fmt.Sprint(index*8))
			source, declaration := x86NativeMMXNonTemporalFixture("amd64", register, address)
			assembly.WriteString(strings.ReplaceAll(source, "Store", name))
			declarations.WriteString(strings.ReplaceAll(declaration, "Store", name) + "\n")
			fmt.Fprintf(&c, "extern void %s(uint32_t,uint8_t*);\n", name)
		}
	}
	fmt.Fprintf(&c, "static void (*const kernels[])(uint32_t,uint8_t*) = {%s};\n", strings.Join(names, ","))
	fmt.Fprintf(&c, "static const int offsets[] = {%s};\n", strings.Join(offsets, ","))
	c.WriteString(`
int main(void) {
    static const uint32_t values[] = {0,1,0xffffffffu,0x87654321u};
    __asm__ volatile("emms" ::: "memory");
    for (unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);++k) {
        for (unsigned v=0;v<sizeof(values)/sizeof(values[0]);++v) {
            _Alignas(64) uint8_t out[128];
            memset(out,0xa5,sizeof(out));
            kernels[k](values[v],out);
            for (unsigned byte=0;byte<sizeof(out);++byte) {
                uint8_t want=0xa5;
                if (byte>=(unsigned)offsets[k] && byte<(unsigned)offsets[k]+8) {
                    want=(uint8_t)((uint64_t)values[v] >> (8*(byte-offsets[k])));
                }
                if (out[byte]!=want) {
                    fprintf(stderr,"kernel=%u value=%x byte=%u got=%x want=%x\n",
                        k,values[v],byte,out[byte],want);
                    return 1;
                }
            }
            _Alignas(16) uint8_t state[512];
            __asm__ volatile("fxsave %0" : "=m"(state));
            if (state[4]!=0) {
                fprintf(stderr,"kernel=%u value=%x x87 tag=%x\n",k,values[v],state[4]);
                return 1;
            }
        }
    }
    return 0;
}
`)
	fmt.Fprintf(&goTest, "package oracle\nimport \"testing\"\nvar kernels=[]func(uint32,*[128]byte){%s}\n", strings.Join(names, ","))
	fmt.Fprintf(&goTest, "var offsets=[]int{%s}\n", strings.Join(offsets, ","))
	goTest.WriteString(`
func TestOriginalStreamingStores(t *testing.T) {
    for k,run:=range kernels {
        for _,value:=range []uint32{0,1,0xffffffff,0x87654321} {
            var aligned struct { word uint64; out [128]byte }
            for index:=range aligned.out { aligned.out[index]=0xa5 }
            run(value,&aligned.out)
            for index,got:=range aligned.out {
                want:=byte(0xa5)
                if index>=offsets[k] && index<offsets[k]+8 {
                    want=byte(uint64(value) >> (8*(index-offsets[k])))
                }
                if got!=want { t.Fatalf("kernel=%d value=%x byte=%d got=%x want=%x",k,value,index,got,want) }
            }
        }
    }
}
`)
	return declarations.String(), assembly.String(), c.String(), goTest.String()
}

func TestX86NativeMMXStreamingOriginalGoBuildOnly(t *testing.T) {
	declarations, source, _, tests := x86MMXStreamingOracleSources()
	x86PackedIntegerCompareOriginalGoDriver(t, declarations, source, tests, true)
}
