package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86SignedPackedIntegerFloatAmbientConstant(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	const source = "TEXT constant(SB),4,$0-8\nMOVQ out+0(FP),AX\nMOVQ $0x0100000101000001,CX\nMOVQ CX,X0\nCVTPL2PS X0,X1\nMOVUPS X1,(AX)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"constant": sig}})
	if err != nil {
		t.Fatal(err)
	}
	const reference = `#include <stdint.h>
#include <stdio.h>
extern void constant(uint32_t*);
int main(void) {
    uint32_t out[6] = {0xabcdef01,0,0,0,0,0x12345678}, csr=0x5f80, observed;
    __asm__ volatile("ldmxcsr %0" :: "m"(csr) : "memory");
    constant(out+1);
    __asm__ volatile("stmxcsr %0" : "=m"(observed) :: "memory");
    if (out[1]!=0x4b800001 || out[2]!=0x4b800001 || out[3] || out[4] || observed!=0x5fa0) {
        fprintf(stderr,"packed ambient constant bits=%08x/%08x CSR=%x expected4b800001/5fa0\n",out[1],out[2],observed);
        return 1;
    }
    if (out[0]!=0xabcdef01 || out[5]!=0x12345678) return 2;
    return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "signed-packed-float-constant", triple, x86SignedIntegerFloatOptimize(t, ir), reference, prefix)
}

func TestCrossLinuxRuntimeMatrixX86SignedPackedIntegerFloatSSE(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range []string{
		"CVTPL2PS X0,X1", "CVTPL2PS X0,X0", "CVTPL2PS (BX),X1",
		"CVTPL2PD X0,X1", "CVTPL2PD X0,X0", "CVTPL2PD (BX),X1",
	} {
		name := fmt.Sprintf("packed%d", index)
		out := "X1"
		if strings.HasSuffix(row, "X0") {
			out = "X0"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-28\nMOVQ out+0(FP),AX\nMOVQ input+8(FP),BX\nMOVQ old+16(FP),DX\nLDMXCSR csr+24(FP)\nMOVUPS (BX),X0\nMOVUPS (DX),X1\nSTC\n%s\nMOVUPS %s,(AX)\nSTMXCSR 16(AX)\nSETCS 20(AX)\nRET\n", name, row, out)
		sigs[name] = FuncSig{Args: []LLVMType{Ptr, Ptr, Ptr, I32}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I32, Index: 3, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*,const void*,uint32_t);\n", name)
		fmt.Fprintf(&checks, "if (check(%s,%d)) return %d;\n", name, index, index+1)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := x86SignedPackedFloatSSEOracle + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "signed-packed-float-sse", triple, x86SignedIntegerFloatOptimize(t, ir), main, prefix)
	t.Log("6 original-Go accepted register/memory/alias programs x1024 inputs x4 RC x6 initial MXCSR states; full16/canaries/CF")
}

func runX86SignedPackedIntegerFloatNativeReadAndPrecisionFaults(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	ir := x86SignedPackedIntegerFloatFaultIR(t, triple)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "signed-packed-native-fault", triple, ir, x86SignedPackedFloatFaultOracle, prefix)
}

func TestX86SignedPackedIntegerFloatFaultEffectsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := x86SignedPackedIntegerFloatFaultIR(t, triple)
			compileLLVMToObject(t, llc, triple, "signed-packed-fault.ll", "signed-packed-fault.o", ir)
		})
	}
}

func x86SignedPackedIntegerFloatFaultIR(t *testing.T, triple string) string {
	t.Helper()
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for _, tc := range []struct{ name, op string }{{"packedPS", "CVTPL2PS"}, {"packedPD", "CVTPL2PD"}, {"packedDeadPS", "CVTPL2PS"}} {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ out+0(FP),AX\nMOVQ input+8(FP),BX\n%s (BX),X0\n", tc.name, tc.op)
		if tc.name != "packedDeadPS" {
			source.WriteString("MOVUPS X0,(AX)\n")
		}
		source.WriteString("RET\n")
		sigs[tc.name] = FuncSig{Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}}}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	ir = x86SignedIntegerFloatOptimize(t, ir)
	// Native output moves are side effects too. Count the conversion family,
	// not unrelated stores, while requiring the dead conversion to survive O2.
	for _, function := range []struct{ name, opcode string }{
		{"packedPS", "cvtdq2ps"}, {"packedPD", "cvtdq2pd"}, {"packedDeadPS", "cvtdq2ps"},
	} {
		_, body, found := strings.Cut(ir, "define void @"+function.name+"(")
		body, _, ended := strings.Cut(body, "\n}")
		if !found || !ended || strings.Count(body, `asm sideeffect "`+function.opcode+` `) != 1 {
			t.Fatalf("%s lost its native precision or memory faults:\n%s", function.name, ir)
		}
	}
	return ir
}

// Both the native-fault oracle and its non-faulting resource test execute
// this same child branch. The latter does not need an x86 instruction.
const x86SignedPackedFloatChildOracle = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
typedef void (*childfn)(void*,const void*,unsigned);

static int fault_child(childfn fn, const void *input, unsigned csr, const unsigned char *expected) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        struct rlimit core = {0,0};
        if (setrlimit(RLIMIT_CORE,&core) != 0) _exit(90);
        unsigned char out[18];
        memset(out,0xc3,sizeof(out));
        fn(out+1,input,csr);
        if (out[0]!=0xc3 || out[17]!=0xc3 || expected && memcmp(out+1,expected,16)) _exit(91);
        _exit(0);
    }
    int status;
    if (waitpid(pid,&status,0)!=pid) return -2;
    if (WIFSIGNALED(status)) return 128+WTERMSIG(status);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -3;
}
`

// The original native memory instruction, not a preloaded vector, is the
// independent fault/read-extent oracle. Each child returns its whole 16-byte
// result and guards, or a concrete signal. A dead result must still trap.
const x86SignedPackedFloatFaultOracle = x86SignedPackedFloatChildOracle + `
#include <sys/mman.h>
typedef void (*memoryfn)(void*,const void*);
extern void packedPS(void*,const void*);
extern void packedPD(void*,const void*);
extern void packedDeadPS(void*,const void*);

static void originalPS(void *out, const void *input) {
    __asm__ volatile("cvtdq2ps (%1),%%xmm0; movups %%xmm0,(%0)" ::
        "r"(out), "r"(input) : "xmm0", "memory");
}

static void originalPD(void *out, const void *input) {
    __asm__ volatile("cvtdq2pd (%1),%%xmm0; movups %%xmm0,(%0)" ::
        "r"(out), "r"(input) : "xmm0", "memory");
}

static void originalDeadPS(void *out, const void *input) {
    (void)out;
    __asm__ volatile("cvtdq2ps (%0),%%xmm0" :: "r"(input) : "xmm0", "memory");
}

struct conversion_request {
    memoryfn fn;
    const void *input;
};

static void invoke_conversion(void *out, const void *opaque, unsigned csr) {
    const struct conversion_request *request = opaque;
    __asm__ volatile("ldmxcsr %0" :: "m"(csr) : "memory");
    request->fn(out,request->input);
}

static int child(memoryfn fn, const void *input, unsigned csr, const unsigned char *expected) {
    const struct conversion_request request = {fn,input};
    return fault_child(invoke_conversion,&request,csr,expected);
}

static int compare(memoryfn reference, memoryfn translated, const void *input,
                   unsigned csr, const unsigned char *expected, int requireFault) {
    int native = child(reference,input,csr,expected);
    int got = child(translated,input,csr,expected);
    int memoryFault = native==128+SIGSEGV || native==128+SIGBUS;
    int valid = requireFault==1 ? memoryFault : requireFault==2 ? native==128+SIGFPE :
        requireFault==-1 ? native==0 || memoryFault : native==0;
    if (native<0 || got!=native || !valid) {
        fprintf(stderr,"signed packed native fault: original=%d LLVM=%d requiredFault=%d csr=%x\n",native,got,requireFault,csr);
        return 1;
    }
    return 0;
}

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page<64) return 10;
    unsigned char *region = mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if (region==MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 11;
    _Alignas(16) const int32_t exact[4]={1,-1,2,-2}, inexact[4]={16777217,-16777217,1,-1};
    const uint32_t single[4]={0x3f800000,0xbf800000,0x40000000,0xc0000000};
    const uint64_t doubled[2]={UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000)};
    memcpy(region+page-32,exact,16);
    memcpy(region+page-16,exact,16);
    if (compare(originalPS,packedPS,region+page-16,0x1f80,(const unsigned char*)single,0)) return 12;
    memcpy(region+page-8,exact,8);
    if (compare(originalPD,packedPD,region+page-8,0x1f80,(const unsigned char*)doubled,0)) return 13;
    if (compare(originalPS,packedPS,region+page-8,0x1f80,0,1)) return 14;
    // Preserve the exact original opcode's host alignment behavior. Rosetta
    // does not establish native AMD64 alignment-fault conformance; if it
    // returns, the full output must still match independent exact integers.
    memcpy(region+page-31,exact,16);
    if (compare(originalPS,packedPS,region+page-31,0x1f80,(const unsigned char*)single,-1)) return 15;
    if (compare(originalPS,packedPS,0,0x1f80,0,1) || compare(originalPD,packedPD,0,0x1f80,0,1)) return 16;
    if (compare(originalPS,packedPS,exact,0x0f80,(const unsigned char*)single,0)) return 17;
    if (compare(originalPS,packedPS,inexact,0x0f80,0,2)) return 18;
    if (compare(originalDeadPS,packedDeadPS,inexact,0x0f80,0,2)) return 19;
    if (compare(originalDeadPS,packedDeadPS,0,0x1f80,0,1)) return 20;
    if (munmap(region,2*page)) return 21;
    return 0;
}
`

// The native original opcode and an independent integer rounding algorithm
// must agree. No LLVM conversion or result observed from the tested function
// defines expected bits. Rosetta execution remains a diagnostic ISA axis.
const x86SignedPackedFloatSSEOracle = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef void (*packedfn)(void*,const void*,const void*,uint32_t);

static uint32_t integer_float(int32_t input, unsigned rounding, int *inexact) {
    uint32_t sign = input < 0 ? 0x80000000u : 0;
    uint32_t magnitude = input < 0 ? 0u - (uint32_t)input : (uint32_t)input;
    if (!magnitude) return 0;
    unsigned exponent = 31u - (unsigned)__builtin_clz(magnitude);
    if (exponent <= 23) return sign | ((exponent + 127) << 23) | ((magnitude << (23-exponent)) & 0x7fffffu);
    unsigned shift = exponent - 23;
    uint32_t fraction = magnitude & ((1u << shift) - 1), significand = magnitude >> shift;
    *inexact |= fraction != 0;
    int increment = rounding == 0 ? fraction > (1u << (shift-1)) ||
        (fraction == (1u << (shift-1)) && (significand & 1)) :
        rounding == 1 ? sign && fraction : rounding == 2 ? !sign && fraction : 0;
    significand += increment;
    if (significand == 0x1000000u) { significand >>= 1; exponent++; }
    return sign | ((exponent + 127) << 23) | (significand & 0x7fffffu);
}

static uint64_t integer_double(int32_t input) {
    uint64_t sign = input < 0 ? UINT64_C(0x8000000000000000) : 0;
    uint32_t magnitude = input < 0 ? 0u - (uint32_t)input : (uint32_t)input;
    if (!magnitude) return 0;
    unsigned exponent = 31u - (unsigned)__builtin_clz(magnitude);
    return sign | ((uint64_t)(exponent + 1023) << 52) |
        (((uint64_t)magnitude << (52-exponent)) & UINT64_C(0xfffffffffffff));
}

static void original(unsigned char *out, const void *input, const void *old, unsigned csr, int variant) {
    unsigned saved;
    __asm__ volatile("stmxcsr %0" : "=m"(saved));
    __asm__ volatile("ldmxcsr %0; movups (%1),%%xmm0; movups (%2),%%xmm1" ::
        "m"(csr), "r"(input), "r"(old) : "xmm0", "xmm1", "memory");
    switch (variant) {
    case 0: __asm__ volatile("cvtdq2ps %%xmm0,%%xmm1" ::: "xmm1"); break;
    case 1: __asm__ volatile("cvtdq2ps %%xmm0,%%xmm0" ::: "xmm0"); break;
    case 2: __asm__ volatile("cvtdq2ps (%0),%%xmm1" :: "r"(input) : "xmm1", "memory"); break;
    case 3: __asm__ volatile("cvtdq2pd %%xmm0,%%xmm1" ::: "xmm1"); break;
    case 4: __asm__ volatile("cvtdq2pd %%xmm0,%%xmm0" ::: "xmm0"); break;
    case 5: __asm__ volatile("cvtdq2pd (%0),%%xmm1" :: "r"(input) : "xmm1", "memory"); break;
    }
    if (variant == 1 || variant == 4) __asm__ volatile("movups %%xmm0,(%0)" :: "r"(out) : "memory");
    else __asm__ volatile("movups %%xmm1,(%0)" :: "r"(out) : "memory");
    __asm__ volatile("stmxcsr %0" : "=m"(*(uint32_t *)(out+16)) :: "memory");
    __asm__ volatile("ldmxcsr %0" :: "m"(saved) : "memory");
}

static int check(packedfn fn, int variant) {
    static const uint32_t edges[] = {0,1,0xffffffff,0x80000000,0x7fffffff,0x1000001,0xfeffffff,0x1000003,0x1000005,0x2000001,0x4000007,0xfffffff0};
    static const uint32_t controls[] = {0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};
    for (unsigned sample=0; sample<1024; sample++) {
        _Alignas(16) uint32_t input[4];
        unsigned char old[16], before[16], got[24], native[20], want[16], inputBefore[16];
        for (unsigned lane=0; lane<4; lane++) {
            input[lane] = sample<12 ? edges[(sample+lane)%12] : 0xd31733a7u*sample + 0x92c48135u*lane;
            for (unsigned b=0; b<4; b++) old[lane*4+b] = (unsigned char)(sample+lane*37+b*71);
        }
        memcpy(before,old,16);
        memcpy(inputBefore,input,16);
        for (unsigned rc=0; rc<4; rc++) for (unsigned c=0; c<6; c++) {
            unsigned csr = controls[c] | (rc << 13), lanes = variant>=3 ? 2 : 4;
            int inexact=0;
            memcpy(want,old,16);
            for (unsigned lane=0; lane<lanes; lane++) {
                if (variant>=3) {
                    uint64_t bits=integer_double((int32_t)input[lane]); memcpy(want+lane*8,&bits,8);
                } else {
                    uint32_t bits=integer_float((int32_t)input[lane],rc,&inexact); memcpy(want+lane*4,&bits,4);
                }
            }
            original(native,input,old,csr,variant);
            unsigned nativeCSR; memcpy(&nativeCSR,native+16,4);
            if (memcmp(native,want,16) || nativeCSR!=(csr | (inexact ? 0x20 : 0))) return 4;
            memset(got,0xc3,sizeof(got)); fn(got+1,input,old,csr);
            unsigned observed; memcpy(&observed,got+17,4);
            if (memcmp(got+1,want,16) || observed!=nativeCSR) {
                fprintf(stderr,"packed signed variant=%d sample=%u rc=%u csr=%x observed=%x want=%x first=%08x\n",variant,sample,rc,csr,observed,nativeCSR,input[0]); return 1;
            }
            if (got[0]!=0xc3 || got[21]!=1 || got[22]!=0xc3 || got[23]!=0xc3 ||
                memcmp(old,before,16) || memcmp(input,inputBefore,16)) return 2;
        }
    }
    unsigned csr=0x1f80;
    __asm__ volatile("ldmxcsr %0" :: "m"(csr) : "memory");
    return 0;
}
`
