package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The original Go and C reference independently observe all eight sign bits,
// r32 zero-extension, FLAGS, aliasing, exact m64 faults and real EMMS tags.
func x86MMXMoveMaskOracleSources() (string, string, string, string) {
	var declarations, assembly, c, goTest strings.Builder
	declarations.WriteString("package oracle\n")
	c.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include <signal.h>\n#include <sys/mman.h>\n#include <sys/wait.h>\n#include <sys/resource.h>\n#include <unistd.h>\n")
	var names []string
	for bank := 0; bank < 8; bank++ {
		for _, destination := range []string{"BX", "R8"} {
			name := fmt.Sprintf("MMXMask%d", len(names))
			names = append(names, name)
			fmt.Fprintf(&declarations, "func %s(p *[8]byte,out *[24]byte)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),SI\nMOVQ out+8(FP),DI\nMOVQ $-1,%s\nMOVL $0,AX\nCMPL AX,AX\nMOVQ (SI),M%d\nPMOVMSKB M%d,%s\nEMMS\nMOVQ %s,0(DI)\nSETCS AL\nMOVB AL,8(DI)\nSETPS AL\nMOVB AL,9(DI)\nSETEQ AL\nMOVB AL,10(DI)\nSETMI AL\nMOVB AL,11(DI)\nSETOS AL\nMOVB AL,12(DI)\nLAHF\nMOVB AH,13(DI)\nRET\n", name, destination, bank, bank, destination, destination)
			fmt.Fprintf(&c, "extern void %s(const uint8_t*,uint8_t*);\n", name)
		}
	}
	fmt.Fprintf(&c, "static void (*const kernels[])(const uint8_t*,uint8_t*)={%s};\n", strings.Join(names, ","))
	c.WriteString(`
static unsigned reference(const uint8_t *p) {
    unsigned result=0;
    for(unsigned i=0;i<8;i++) result|=(unsigned)(p[i]>>7)<<i;
    return result;
}
static int check(unsigned k,const uint8_t *p,uint8_t *out) {
    unsigned want=reference(p);
    kernels[k](p,out);
    uint64_t mask;const uint8_t flags[]={0,1,1,0,0,0x46};
    memcpy(&mask,out,8);
    if(mask!=want || memcmp(out+8,flags,sizeof(flags))) {
        fprintf(stderr,"mask/FLAGS k=%u got=%llx want=%x\n",k,(unsigned long long)mask,want);
        return 1;
    }
    _Alignas(16) uint8_t state[512];
    __asm__ volatile("fxsave %0":"=m"(state));
    if(state[4]!=0) { fprintf(stderr,"MMX tag k=%u got=%x\n",k,state[4]);return 1; }
    return 0;
}
int main(void) {
    const unsigned count=sizeof(kernels)/sizeof(kernels[0]);
    __asm__ volatile("emms":::"memory");
    for(unsigned k=0;k<count;k++) {
        for(unsigned pattern=0;pattern<256;pattern++) for(unsigned low=0;low<2;low++) {
            uint8_t input[8],before[8],out[24];
            for(unsigned j=0;j<8;j++) input[j]=((pattern>>j)&1)*128+(low?127:0);
            memcpy(before,input,8); memset(out,0xa5,sizeof(out));
            if(check(k,input,out) || memcmp(input,before,8)) return 1;
            for(unsigned j=14;j<24;j++) if(out[j]!=0xa5) return 1;
            uint8_t alias[32];memset(alias,0xa5,sizeof(alias));memcpy(alias+1,input,8);
            if(check(k,alias+1,alias+1) || alias[0]!=0xa5) return 1;
            for(unsigned j=15;j<32;j++) if(alias[j]!=0xa5) return 1;
        }
        long page=sysconf(_SC_PAGESIZE);
        uint8_t *mapping=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(mapping==MAP_FAILED || mprotect(mapping+page,page,PROT_NONE)) return 2;
        memset(mapping+page-8,0x80,8);uint8_t out[24];
        if(check(k,mapping+page-8,out)) return 1;
        for(unsigned fault=0;fault<8;fault++) {
            const uint8_t *p=fault?mapping+page-fault:0;
            pid_t child=fork();if(child<0)return 2;
            if(child==0) { struct rlimit limit={0,0};setrlimit(RLIMIT_CORE,&limit);kernels[k](p,out);_exit(99); }
            int status;if(waitpid(child,&status,0)!=child)return 2;
            if(!WIFSIGNALED(status) || WTERMSIG(status)!=SIGSEGV) {fprintf(stderr,"missing m64 fault k=%u case=%u status=%x\n",k,fault,status);return 1;}
        }
        if(munmap(mapping,2*page))return 2;
    }
    puts("MMX_MASK kernels=16 values=8192 aliases=8192 faults=128 boundary=16 failures=0");
    return 0;
}
`)
	fmt.Fprintf(&goTest, "package oracle\nimport(\"encoding/binary\";\"os\";\"runtime/debug\";\"syscall\";\"testing\";\"unsafe\")\nvar kernels=[]func(*[8]byte,*[24]byte){%s}\n", strings.Join(names, ","))
	goTest.WriteString(`
func check(t *testing.T,k int,p *[8]byte,out *[24]byte) {
    t.Helper();var want uint64
    for i,b:=range p { want|=uint64(b>>7)<<uint(i) }
    kernels[k](p,out)
    if got:=binary.LittleEndian.Uint64(out[:8]);got!=want {t.Fatalf("k=%d got=%x want=%x",k,got,want)}
    flags:=[6]byte{0,1,1,0,0,0x46};for i,want:=range flags {if out[8+i]!=want {t.Fatalf("k=%d flag=%d got=%x want=%x",k,i,out[8+i],want)}}
}
func TestOriginalMMXMoveMasks(t *testing.T) {
    for k,run:=range kernels {
        for pattern:=0;pattern<256;pattern++ {for _,low:=range []byte{0,127} {
            var input [8]byte;var out [24]byte
            for j:=range input {input[j]=byte((pattern>>uint(j))&1)*128+low}
            before:=input;for j:=range out {out[j]=0xa5}
            check(t,k,&input,&out)
            if input!=before {t.Fatal("input changed",k)}
            for _,b:=range out[14:] {if b!=0xa5{t.Fatal("output extent",k)}}
            var alias [32]byte;for j:=range alias{alias[j]=0xa5};copy(alias[1:9],input[:])
            check(t,k,(*[8]byte)(unsafe.Pointer(&alias[1])),(*[24]byte)(unsafe.Pointer(&alias[1])))
            if alias[0]!=0xa5 {t.Fatal("alias prefix",k)}
            for _,b:=range alias[15:] {if b!=0xa5{t.Fatal("alias suffix",k)}}
        }}
        page:=os.Getpagesize()
        mapping,err:=syscall.Mmap(-1,0,2*page,syscall.PROT_READ|syscall.PROT_WRITE,syscall.MAP_PRIVATE|syscall.MAP_ANON)
        if err!=nil {t.Fatal(err)}
        if err:=syscall.Mprotect(mapping[page:],syscall.PROT_NONE);err!=nil{t.Fatal(err)}
        for j:=page-8;j<page;j++{mapping[j]=0x80};var out [24]byte
        check(t,k,(*[8]byte)(unsafe.Pointer(&mapping[page-8])),&out)
        old:=debug.SetPanicOnFault(true)
        for fault:=0;fault<8;fault++ {
            var p *[8]byte;if fault!=0{p=(*[8]byte)(unsafe.Pointer(&mapping[page-fault]))}
            caught:=func()(caught bool){defer func(){if recover()!=nil{caught=true}}();run(p,&out);return false}()
            if !caught {t.Fatal("missing original m64 fault",k,fault)}
        }
        debug.SetPanicOnFault(old)
        if err:=syscall.Munmap(mapping);err!=nil{t.Fatal(err)}
    }
}
`)
	return declarations.String(), assembly.String(), c.String(), goTest.String()
}

func TestX86NativeMMXMoveMaskRuntimeOriginalGoBuildOnly(t *testing.T) {
	declarations, source, _, tests := x86MMXMoveMaskOracleSources()
	x86PackedIntegerCompareOriginalGoDriver(t, declarations, source, tests, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, strings.TrimPrefix(declarations, "package oracle\n"), "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal("complete mask runtime source", err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, level)
			}
		})
	}
}

func TestX86NativeMMXMoveMaskBuildOnlyUsesLinuxFaultProfile(t *testing.T) {
	// Exercise the exact Unix fault oracle on a Windows build host profile.
	// The parent test still runs normally; only its child target is changed.
	t.Setenv("GOOS", "windows")
	declarations, source, _, tests := x86MMXMoveMaskOracleSources()
	x86PackedIntegerCompareOriginalGoDriver(t, declarations, source, tests, true)
}

func x86NativeMMXMoveMaskRuntime(t *testing.T) {
	declarations, source, c, tests := x86MMXMoveMaskOracleSources()
	t.Run("original-go", func(t *testing.T) { x86PackedIntegerCompareRunOriginalGo(t, declarations, source, tests) })
	execution := x86FloatCompareExecutionTools(t)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, strings.TrimPrefix(declarations, "package oracle\n"), "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) { execution.compileAndRunLLVM(t, "mmxmask", ir, c, level) })
			}
		})
	}
}
