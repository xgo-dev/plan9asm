package plan9asm

import (
	"debug/macho"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const nativeCallbackSource = `#include "textflag.h"
TEXT callback<>(SB), NOSPLIT|NOFRAME, $0
 SUB $16, RSP
 MOVD R30, (RSP)
 BL imported_strlen(SB)
 MOVD (RSP), R30
 ADD $16, RSP
 RET
GLOBL ·entry(SB), RODATA, $8
DATA ·entry(SB)/8, $callback<>(SB)
TEXT mixedtramp<>(SB), NOSPLIT, $0-0
 FMOVD R1, F0
 MOVD $0x11, R1
 JMP imported_mixed(SB)
GLOBL ·mixedEntry(SB), RODATA, $8
DATA ·mixedEntry(SB)/8, $mixedtramp<>(SB)
`

func TestNativeARM64Source(t *testing.T) {
	imports := map[string]string{"imported_strlen": "strlen", "imported_mixed": "mixed"}
	assembly, data, err := TranslateNativeARM64Source([]byte(nativeCallbackSource), imports, "probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2 || data[0] != (NativeData{"probe.entry", 8}) {
		t.Fatalf("data=%v", data)
	}
	for _, want := range []string{`bl "_strlen"`, `.quad Lnative_func_0`, "fmov d0, x1", ".section __DATA_CONST,__const"} {
		if !strings.Contains(assembly, want) {
			t.Fatalf("missing %q:\n%s", want, assembly)
		}
	}
	nativeCompileAndRun(t, assembly, `extern void *entry __asm("_probe.entry");
extern void *mixedEntry __asm("_probe.mixedEntry");
unsigned long mixed(unsigned long x, unsigned long flags, double y) {
 return flags == 17 ? x + (unsigned long)y : 999;
}
int main(void) {
 if (((unsigned long (*)(const char *))entry)("native ABI") != 10) return 1;
 return ((unsigned long (*)(unsigned long, unsigned long))mixedEntry)(5, 0x4000000000000000UL) != 7;
}`)
}

func TestNativeARM64SourceRequiresLLVM22(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(executable, "-test.run=^TestNativeARM64Source$", "-test.v")
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(variable), "LLVM_CONFIG=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "LLVM_CONFIG="+filepath.Join(t.TempDir(), "missing-llvm-config"))

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("native ARM64 source test passed without required LLVM 22 tools:\n%s", output)
	}
	if !strings.Contains(string(output), "LLVM 22 clang not found") {
		t.Fatalf("native ARM64 source test did not fail for missing LLVM 22: %v\n%s", err, output)
	}
}

// Compile the generated Mach-O assembly on every LLVM host; only execution
// needs Darwin/ARM64. No test or implementation reads a Go object format.
func nativeCompileAndRun(t *testing.T, assembly, harness string) {
	t.Helper()
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "native.s")
	object := filepath.Join(dir, "native.o")
	if err := os.WriteFile(src, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(clang, "--target=arm64-apple-darwin", "-c", src, "-o", object)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("assemble: %v\n%s\n%s", err, b, assembly)
	}
	obj, err := macho.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	if obj.Cpu != macho.CpuArm64 {
		t.Fatal("wrong architecture")
	}
	constant := obj.Section("__const")
	if constant == nil || constant.Seg != "__DATA_CONST" {
		t.Fatal("lost read-only DATA placement")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Log("Mach-O object validated; native execution requires darwin/arm64")
		return
	}
	c := filepath.Join(dir, "main.c")
	exe := filepath.Join(dir, "probe")
	if err := os.WriteFile(c, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(clang, object, c, "-o", exe)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("link: %v\n%s", err, b)
	}
	if b, err := exec.Command(exe).CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, b)
	}
}

func TestNativeARM64RegistersAndMemory(t *testing.T) {
	src := `TEXT probe<>(SB), NOSPLIT, $0
 MOVD $0x123456789abcdef0, R2
 MOVD R2, (R0)
 MOVD R1, 16(R0)
 MOVD 16(R0), R3
 MOVW 8(R0), R4
 MOVWU 8(R0), R5
 MOVD R4, 24(R0)
 MOVD R5, 32(R0)
 MOVW R4, R6
 MOVWU R4, R7
 MOVD R6, 40(R0)
 MOVD R7, 48(R0)
 MOVW R4, 56(R0)
 MOVD $0x1122334455667788, R8
 MOVD R8, -8(R1)
 MOVD -8(R1), R9
 CMP R8, R9
 BNE fail
 ADD $64, R0, R10
 MOVD R8, 1(R10)
 MOVD 1(R10), R9
 CMP R8, R9
 BNE fail
 FMOVD R8, F0
 FMOVD F0, F1
 FMOVD F1, R9
 CMP R8, R9
 BNE fail
 MOVD $0, R4
 CBZ R4, zero
 B fail
zero:
 MOVD $4, R4
 LSL $2, R4, R5
 ADD R4, R5, R5
 SUB R4, R5, R5
 CMP $16, R5
 BNE fail
loop:
 SUB $1, R4
 CBNZ R4, loop
 CMPW $0, R4
 BNE fail
 MOVD $0, R0
 RET
fail:
 MOVD $1, R0
 RET
GLOBL ·entry(SB), RODATA, $8
DATA ·entry(SB)/8, $probe<>(SB)
`
	assembly, _, err := TranslateNativeARM64Source([]byte(src), nil, "probe")
	if err != nil {
		t.Fatal(err)
	}
	nativeCompileAndRun(t, assembly, `#include <stdint.h>
extern void *entry __asm("_probe.entry");
int main(void) {
 uint64_t memory[10] = {0,0x80000000};
 uint64_t other[2] = {0};
 int status=((int (*)(uint64_t *,uint64_t *))entry)(memory,other+1);
 if(status) return status;
 if(memory[0]!=0x123456789abcdef0ULL) return 2;
 if(memory[2]!=(uintptr_t)(other+1)) return 3;
 if(memory[3]!=0xffffffff80000000ULL || memory[4]!=0x80000000ULL) return 4;
 if(memory[5]!=memory[3] || memory[6]!=memory[4]) return 5;
 if(memory[7]!=0x80000000ULL || other[0]!=0x1122334455667788ULL) return 6;
 return 0;
}`)
}

func TestNativeARM64RejectsUnsupportedSource(t *testing.T) {
	const prefix = "TEXT raw<>(SB), NOSPLIT|NOFRAME, $0\n"
	tests := []struct{ name, source, want string }{
		{"empty", "", "no TEXT"},
		{"data only", "GLOBL ·p(SB), RODATA, $8\n", "requires TEXT"},
		{"invalid local name", "TEXT bad-name<>(SB), NOSPLIT, $0\nRET\n", "file-local"},
		{"duplicate label", prefix + "here:\nRET\nhere:\nRET\n", "duplicate native label"},
		{"invalid global name", prefix + "RET\nGLOBL p<>(SB), RODATA, $8\n", "package global"},
		{"duplicate global", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nGLOBL ·p(SB), RODATA, $8\n", "duplicate native GLOBL"},
		{"empty global", prefix + "RET\nGLOBL ·p(SB), RODATA, $0\n", "GLOBL size"},
		{"huge global", prefix + "RET\nGLOBL ·p(SB), RODATA, $67108865\n", "GLOBL size"},
		{"data width", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nDATA ·p(SB)/3, $1\n", "DATA width"},
		{"data string", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nDATA ·p(SB)/3, $\"abc\"\n", "source syntax"},
		{"block comment", prefix + "/* ignored */ RET\n", "source syntax"},
		{"FP to FP integer move", prefix + "MOVD F0, R0\n", "unsupported native register"},
		{"floating move without FP", prefix + "FMOVD R0, R1\n", "operand form"},
		{"stack register arithmetic", prefix + "ADD R0, RSP\n", "operand form"},
		{"stack immediate move", prefix + "MOVD $0, RSP\n", "operand form"},
		{"narrow immediate move", prefix + "MOVW $1, R0\n", "operand form"},
		{"zero memory base", prefix + "MOVD (ZR), R0\n", "memory base"},
		{"zero immediate arithmetic", prefix + "ADD $1, ZR\n", "operand form"},
		{"explicit return operand", prefix + "RET R0\n", "operand form"},

		{"Go ABI", "TEXT ·goFunc(SB), NOSPLIT, $0\nRET\n", "file-local"},
		{"frame", "TEXT raw<>(SB), NOSPLIT, $8-0\nRET\n", "zero Go frame"},
		{"args", "TEXT raw<>(SB), NOSPLIT, $0-8\nRET\n", "zero Go frame"},
		{"missing nosplit", "TEXT raw<>(SB), NOFRAME, $0\nRET\n", "NOSPLIT"},
		{"implicit frame", "TEXT raw<>(SB), NOSPLIT, $0\nBL imported(SB)\nRET\n", "NOFRAME"},
		{"flags", "TEXT raw<>(SB), NOSPLIT|WRAPPER, $0\nRET\n", "flag"},
		{"undeclared", prefix + "BL missing(SB)\n", "undeclared foreign"},
		{"package call", prefix + "BL runtime·foo(SB)\n", "undeclared foreign"},
		{"unknown", prefix + "NOT_AN_INSTRUCTION\n", "unsupported native instruction"},
		{"raw opcode", prefix + "WORD $0xd65f03c0\n", "unsupported native instruction"},
		{"indirect call", prefix + "BL (R0)\n", "undefined native branch"},
		{"postincrement", prefix + "MOVD.P 8(R0), R1\n", "unsupported native instruction"},
		{"indexed", prefix + "MOVD (R0)(R1), R2\n", "native memory"},
		{"large displacement", prefix + "MOVD 32768(R0), R1\n", "address expansion"},
		{"Go FP", prefix + "MOVD arg+0(FP), R0\n", "Go stack"},
		{"Go SP", prefix + "MOVD 8(SP), R0\n", "Go stack"},
		{"Go g", prefix + "MOVD g, R0\n", "Go stack"},
		{"reserved", prefix + "MOVD R18, R0\n", "Go stack"},
		{"ambiguous31", prefix + "MOVD R31, R0\n", "Go stack"},
		{"unknown label", prefix + "BNE nowhere\n", "undefined native branch"},
		{"branch addend", prefix + "BL imported+4(SB)\n", "undeclared foreign"},
		{"immediate expansion", prefix + "ADD $4096, R0\n", "operand form"},
		{"float immediate", prefix + "MOVD $1.0, R0\n", "constant integer"},
		{"symbolic immediate", prefix + "MOVD $(unknown + 8), R0\n", "constant integer"},
		{"include", "#include \"go_asm.h\"\n" + prefix + "RET\n", "preprocessor"},
		{"conditional", "#if 0\n" + prefix + "RET\n#endif\n", "preprocessor"},
		{"macro", "#define NAME RET\n" + prefix + "NAME\n", "preprocessor"},
		{"data size", prefix + "RET\nGLOBL ·p(SB), RODATA, $(unknown + 8)\n", "constant integer"},
		{"data missing", prefix + "RET\nDATA ·p(SB)/8, $raw<>(SB)\n", "no GLOBL"},
		{"data bounds", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nDATA ·p+4(SB)/8, $raw<>(SB)\n", "out-of-bounds"},
		{"data overlap", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nDATA ·p(SB)/8, $raw<>(SB)\nDATA ·p+4(SB)/4, $1\n", "overlapping"},
		{"data addend", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nDATA ·p(SB)/8, $raw<>+4(SB)\n", "undeclared foreign"},
		{"data pointer width", prefix + "RET\nGLOBL ·p(SB), RODATA, $8\nDATA ·p(SB)/4, $raw<>(SB)\n", "width 8"},
		{"data flags", prefix + "RET\nGLOBL ·p(SB), DUPOK, $8\n", "flag"},
		{"duplicate", prefix + "RET\n" + prefix + "RET\n", "duplicate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assembly, data, err := TranslateNativeARM64Source([]byte(tc.source), map[string]string{"imported": "strlen"}, "probe")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v; want %q", err, tc.want)
			}
			if assembly != "" || data != nil {
				t.Fatal("returned partial output on error")
			}
		})
	}
}

func TestForeignARM64Selection(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{nativeCallbackSource, true},
		{"TEXT ·declared(SB), NOSPLIT, $0\nRET", false},
		{"TEXT local<>(SB), NOSPLIT, $8\nRET", true}, // route and reject; never guess void()
		{"TEXT local<>(SB), NOSPLIT, $0\nRET\nTEXT ·declared(SB), NOSPLIT, $0\nRET", false},
	} {
		if got := len(ForeignARM64Functions([]byte(tc.src))) != 0; got != tc.want {
			t.Fatalf("selection=%v want %v for %s", got, tc.want, tc.src)
		}
	}
}

func TestNativeARM64CompareConditions(t *testing.T) {
	conditions := []struct{ op, expr string }{
		{"BEQ", "a == b"}, {"BNE", "a != b"},
		{"BLT", "(int64_t)b < (int64_t)a"}, {"BLE", "(int64_t)b <= (int64_t)a"},
		{"BGT", "(int64_t)b > (int64_t)a"}, {"BGE", "(int64_t)b >= (int64_t)a"},
		{"BHS", "b >= a"}, {"BLO", "b < a"}, {"BHI", "b > a"}, {"BLS", "b <= a"},
		{"BMI", "(int64_t)(b-a) < 0"}, {"BPL", "(int64_t)(b-a) >= 0"},
		{"BVS", "((b^a)&(b^(b-a))) >> 63"}, {"BVC", "!(((b^a)&(b^(b-a))) >> 63)"},
	}
	var source, c strings.Builder
	c.WriteString("#include <stdint.h>\n")
	for i, condition := range conditions {
		// MOVD's multi-instruction expansion must not overwrite CMP's flags.
		fmt.Fprintf(&source, `TEXT compare%d<>(SB), NOSPLIT, $0
 CMP R0, R1
 MOVD $0x1122334455667788, R2
 %s yes
 MOVD $0, R0
 RET
yes:
 MOVD $1, R0
 RET
GLOBL ·compare%d(SB), RODATA, $8
DATA ·compare%d(SB)/8, $compare%d<>(SB)
`, i, condition.op, i, i, i)
		fmt.Fprintf(&c, "extern void *compare%d __asm(\"_probe.compare%d\");\n", i, i)
	}
	c.WriteString("int main(void) { uint64_t values[]={0,1,17,0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL}; for(int i=0;i<6;i++) for(int j=0;j<6;j++){uint64_t a=values[i],b=values[j];\n")
	for i, condition := range conditions {
		fmt.Fprintf(&c, "if (((int (*)(uint64_t,uint64_t))compare%d)(a,b) != !!(%s)) return %d;\n", i, condition.expr, i+1)
	}
	c.WriteString("} return 0; }")
	assembly, _, err := TranslateNativeARM64Source([]byte(source.String()), nil, "probe")
	if err != nil {
		t.Fatal(err)
	}
	nativeCompileAndRun(t, assembly, c.String())
}

func TestNativeARM64DataAndLocalCalls(t *testing.T) {
	source := `TEXT caller<>(SB), NOSPLIT|NOFRAME, $0
 SUB $16, RSP
 MOVD R30, (RSP)
 CALL helper<>(SB)
 MOVD (RSP), R30
 ADD $16, RSP
 RET
TEXT helper<>(SB), NOSPLIT, $0
 ADD $3, R0
 RET
GLOBL ·entry(SB), RODATA, $8
DATA ·entry(SB)/8, $caller<>(SB)
GLOBL ·bytes(SB), NOPTR, $24
DATA ·bytes+0(SB)/1, $0x12
DATA ·bytes+2(SB)/2, $0x3456
DATA ·bytes+4(SB)/4, $0x789abcde
DATA ·bytes+8(SB)/8, $-1
GLOBL ·address(SB), RODATA, $8
DATA ·address(SB)/8, $·bytes(SB)
`
	assembly, _, err := TranslateNativeARM64Source([]byte(source), nil, "probe")
	if err != nil {
		t.Fatal(err)
	}
	nativeCompileAndRun(t, assembly, `#include <stdint.h>
extern void *entry __asm("_probe.entry");
extern unsigned char bytes[24] __asm("_probe.bytes");
extern void *address __asm("_probe.address");
int main(void) {
 if(((uint64_t (*)(uint64_t))entry)(39)!=42) return 1;
 if(address!=bytes) return 2;
 if(bytes[0]!=0x12 || bytes[1]!=0 || bytes[2]!=0x56 || bytes[3]!=0x34) return 3;
 if(*(uint32_t *)(bytes+4)!=0x789abcde) return 4;
 if(*(uint64_t *)(bytes+8)!=~0ULL || *(uint64_t *)(bytes+16)!=0) return 5;
 bytes[0]=42; return bytes[0]!=42;
}`)
}

func TestNativeARM64RejectsInvalidImport(t *testing.T) {
	for _, imports := range []map[string]string{
		{"bad.name": "strlen"}, {"imported_strlen": "bad+8"},
	} {
		assembly, data, err := TranslateNativeARM64Source([]byte(nativeCallbackSource), imports, "probe")
		if err == nil || !strings.Contains(err.Error(), "unsupported native import") || assembly != "" || data != nil {
			t.Fatalf("invalid import returned %q, %v, %v", assembly, data, err)
		}
	}
}
