//go:build unix

package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// The native fault reference executes original Go-assembled instruction bytes
// under the explicit SysV DI/SI/DX transport below. It is not a Go-runtime or
// ABI0 execution receipt; the separate value owners execute actual Go programs.
func x86PackedReductionFaultOriginalBytes(t *testing.T, rows []x86PackedReductionRuntimeRow) [][]byte {
	t.Helper()
	var assembly strings.Builder
	assembly.WriteString("TEXT original(SB),4,$0-0\n")
	for _, row := range rows {
		assembly.WriteString("LDMXCSR (SI)\nVMOVDQU (DX),Y1\n" + row.instruction + "\nRET\n")
	}
	code := x86PackedShiftActualGoBytes(t, "amd64", assembly.String())
	var result [][]byte
	offset := 0
	for _, row := range rows {
		// Independent exact Go LDMXCSR (SI), VMOVDQU (DX),Y1, arithmetic,
		// RET bytes bind the complete reference, not a search for byte 0xc3.
		want := []byte{0x0f, 0xae, 0x16, 0xc5, 0xfe, 0x6f, 0x0a}
		want = append(want, x86PackedReductionRuntimeExpectedBytes(row, true)...)
		want = append(want, 0xc3)
		end := offset + len(want)
		if end > len(code) || !bytes.Equal(code[offset:end], want) {
			t.Fatal("original native reduction fault bytes/whole boundaries changed", row.instruction, offset)
		}
		result = append(result, append([]byte(nil), code[offset:end]...))
		offset = end
	}
	if offset != len(code) {
		t.Fatal("unconsumed original native reduction fault bytes", offset, len(code))
	}
	return result
}

func x86PackedReductionFaultFixture(rows []x86PackedReductionRuntimeRow, original [][]byte) (assembly, declarations, driver string) {
	var source, decl, native, prototypes, pairs strings.Builder
	for index, row := range rows {
		name, reference := fmt.Sprintf("reductionfault%d", index), fmt.Sprintf("original%d", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ p+0(FP),DI\nMOVQ csr+8(FP),SI\nMOVQ b+16(FP),DX\n"+
			"LDMXCSR (SI)\nVMOVDQU (DX),Y1\n%s\nRET\n", name, row.instruction)
		fmt.Fprintf(&decl, "func %s(p *byte,csr *uint32,b *[4]uint64)\n", name)
		var octets []string
		for _, value := range original[index] {
			octets = append(octets, fmt.Sprintf("0x%02x", value))
		}
		fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+reference+"\n"+reference+":\n.byte "+strings.Join(octets, ",")+"\n")
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,uint32_t*,uint64_t*),%s(uint8_t*,uint32_t*,uint64_t*);\n", name, reference)
		bits := 32
		if strings.HasSuffix(row.oracle.mnemonic, "pd") {
			bits = 64
		}
		fmt.Fprintf(&pairs, "{%s,%s,%d,%d,%d,%d,%d,%d},\n", reference, name, row.oracle.width, bits,
			x86FloatAddSubBoolInt(row.oracle.legacy), x86FloatAddSubBoolInt(row.oracle.dot), row.selector,
			x86FloatAddSubBoolInt(strings.Contains(row.oracle.mnemonic, "hsub")))
	}
	driver = `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + native.String() + prototypes.String() + `
typedef void (*program)(uint8_t*,uint32_t*,uint64_t*);
static const struct {program original,translated;unsigned width,bits,aligned,dot,selector,subtract;} pairs[]={
` + pairs.String() + `};
static int outcome(program fn,uint8_t *p,uint32_t csr,uint64_t *second) {
    pid_t child=fork();if(child<0)return -1;
    if(!child) {
        struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core))_exit(120);
        fn(p,&csr,second);_exit(0);
    }
    int status;if(waitpid(child,&status,0)!=child)return -1;
    if(WIFEXITED(status)&&WEXITSTATUS(status)==0)return 0;
    if(WIFSIGNALED(status)) {
        int sig=WTERMSIG(status);
        if(sig==SIGSEGV||sig==SIGBUS)return 1;
        if(sig==SIGFPE)return 2;
    }
    return -1;
}
static void fill(uint8_t *p,unsigned bits,uint64_t even,uint64_t odd) {
    for(unsigned lane=0;lane<32/(bits/8);lane++) {
        uint64_t value=lane&1?odd:even;
        memcpy(p+lane*(bits/8),&value,bits/8);
    }
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);if(page<64)return 1;
    uint8_t *p=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(p==MAP_FAILED||mprotect(p+page,page,PROT_NONE))return 2;
    _Alignas(16) uint64_t second[4]={0};
    memset(p,0,page);
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);i++) {
        int limits[]={0,pairs[i].width-1,pairs[i].width,pairs[i].width+1};
        for(unsigned n=0;n<5;n++) {
            uint8_t *input=n==4?0:p+page-limits[n];
            int expected=n==4||limits[n]<(int)pairs[i].width;
            if(pairs[i].aligned&&((uintptr_t)input&15))expected=1;
            int a=outcome(pairs[i].original,input,0x1f80,second);
            int b=outcome(pairs[i].translated,input,0x1f80,second);
            if(a!=expected||b!=expected) {
                fprintf(stderr,"dead tuple=%u limit=%u original=%d LLVM=%d expected=%d\n",i,n,a,b,expected);
                return 3;
            }
        }
        for(unsigned event=0;event<5;event++) {
            if(event==4&&!pairs[i].dot)continue;
            uint64_t first,other;uint32_t csr=0x1f80;
            if(event==0) {
                first=pairs[i].bits==32?UINT64_C(0x7f812345):UINT64_C(0x7ff0123456789abc);
                other=pairs[i].bits==32?UINT64_C(0x3f800000):UINT64_C(0x3ff0000000000000);
                csr&=~UINT32_C(0x80);
            } else if(event==1) {
                first=1;other=pairs[i].bits==32?UINT64_C(0x3f800000):UINT64_C(0x3ff0000000000000);
                csr&=~UINT32_C(0x100);
            } else if(event==2) {
                first=pairs[i].bits==32?UINT64_C(0x7f7fffff):UINT64_C(0x7fefffffffffffff);
                other=pairs[i].dot?(pairs[i].bits==32?UINT64_C(0x40000000):UINT64_C(0x4000000000000000)):first;
                csr&=~UINT32_C(0x400);
            } else if(event==3) {
                first=pairs[i].dot?(pairs[i].bits==32?UINT64_C(0x3f800001):UINT64_C(0x3ff0000000000001)):
                    (pairs[i].bits==32?UINT64_C(0x3f800000):UINT64_C(0x3ff0000000000000));
                other=pairs[i].dot?first:(pairs[i].bits==32?UINT64_C(0x33000000):UINT64_C(0x3c90000000000000));
                csr&=~UINT32_C(0x1000);
            } else {
                first=pairs[i].bits==32?UINT64_C(0x00800000):UINT64_C(0x0010000000000000);
                other=first;csr&=~UINT32_C(0x800);
            }
            uint64_t odd=pairs[i].dot?first:other;
            if(event==2&&pairs[i].subtract)odd^=pairs[i].bits==32?UINT64_C(0x80000000):UINT64_C(0x8000000000000000);
            fill(p,pairs[i].bits,first,odd);
            fill((uint8_t*)second,pairs[i].bits,other,pairs[i].dot?other:odd);
            unsigned inputs=pairs[i].bits==32?0xf0:0x30;
            int expected=pairs[i].dot&&!(pairs[i].selector&inputs)?0:2;
            int a=outcome(pairs[i].original,p,csr,second);
            int b=outcome(pairs[i].translated,p,csr,second);
            if(a!=expected||b!=expected) {
                fprintf(stderr,"dead exception=%u event=%u selector=%x original=%d LLVM=%d expected=%d\n",i,event,pairs[i].selector,a,b,expected);
                return 4;
            }
        }
    }
    if(munmap(p,2*page))return 5;
    puts("complete original Go-opcode/LLVM native reduction dead-fault receipt");
    return 0;
}
`
	return source.String(), decl.String(), driver
}

func x86PackedReductionNativeFaults(t *testing.T, owner int) {
	t.Helper()
	if owner < 0 || owner >= x86PackedReductionNativeOwners {
		t.Fatal("invalid complete native reduction fault owner", owner)
	}
	execution := x86PackedReductionNativeTools(t)
	rows := x86PackedReductionNativeRows(true)
	if len(rows) != 37 {
		t.Fatal("complete native reduction fault denominator changed", len(rows))
	}
	consumed := 0
	for batch, start := 0, 0; start < len(rows); batch, start = batch+1, start+x86PackedReductionFaultCapture {
		if batch%x86PackedReductionNativeOwners != owner {
			continue
		}
		end := start + x86PackedReductionFaultCapture
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			current := rows[start:end]
			var original [][]byte
			t.Run("original_go_opcode_reference", func(t *testing.T) {
				original = x86PackedReductionFaultOriginalBytes(t, current)
				if len(original) != len(current) {
					t.Fatal("incomplete actual Go-assembled native reference kernels")
				}
			})
			if len(original) != len(current) {
				t.Fatal("missing actual Go-assembled native reference kernels")
			}
			assembly, declarations, driver := x86PackedReductionFaultFixture(current, original)
			raw := x86PackedReductionRuntimeRawRows(t, current, true)
			rawRows := append([]x86PackedReductionRuntimeRow(nil), current...)
			for index := range rawRows {
				rawRows[index].instruction = raw[index]
			}
			rawAssembly, _, _ := x86PackedReductionFaultFixture(rawRows, original)
			for _, spelling := range []struct{ name, source string }{{"named", assembly}, {"raw", rawAssembly}} {
				t.Run(spelling.name, func(t *testing.T) {
					goAssemblerOracleOutput(t, "amd64", spelling.source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations, "amd64", execution.triple, api)
							if err != nil {
								t.Fatal("initialized native reduction dead source rejected", err)
							}
							x86PackedReductionNativePipelines(t, execution, ir, driver,
								[]byte("complete original Go-opcode/LLVM native reduction dead-fault receipt\n"))
						})
					}
				})
			}
			consumed += len(current)
		})
	}
	if consumed == 0 {
		t.Fatal("empty native reduction dead-fault owner")
	}
	t.Logf("%d/37 original-Go-opcode native memory/alignment and actual unmasked invalid/denormal/overflow/precision/dot-underflow kernels", consumed)
}
