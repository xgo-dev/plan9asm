package plan9asm

import (
	"debug/elf"
	"debug/macho"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const nativeAMD64Callback = `TEXT callback<>(SB), NOSPLIT|NOFRAME, $0
 SUBQ $8, SP
 CALL imported_strlen(SB)
 ADDQ $8, SP
 RET
GLOBL ·entry(SB), RODATA, $8
DATA ·entry(SB)/8, $callback<>(SB)
TEXT mixedtramp<>(SB), NOSPLIT, $0
 MOVQ SI, X0
 MOVQ $17, SI
 JMP imported_mixed(SB)
GLOBL ·mixedEntry(SB), RODATA, $8
DATA ·mixedEntry(SB)/8, $mixedtramp<>(SB)
TEXT arithmetic<>(SB), NOSPLIT, $0
 MOVQ $0x123456789abcdef0, AX
 MOVQ AX, (DI)
 MOVL $0xffffffff, CX
 MOVQ CX, 8(DI)
 LEAQ 8(DI), DX
 MOVQ (DX), AX
 SHLQ $1, AX
 SHRQ $1, AX
 CMPQ AX, CX
 JNE fail
 CMPQ SI, $-1
 JNE fail
 XORL AX, AX
 RET
fail:
 MOVQ $1, AX
 RET
GLOBL ·arithmetic(SB), RODATA, $8
DATA ·arithmetic(SB)/8, $arithmetic<>(SB)
`

func TestNativeTargetMatrix(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			t.Run(goos+"/"+goarch, func(t *testing.T) {
				src := nativeCallbackSource
				if goarch == "amd64" {
					src = nativeAMD64Callback
				}
				opts := NativeOptions{GOOS: goos, GOARCH: goarch, PackagePath: "probe", Imports: map[string]string{"imported_strlen": "strlen", "imported_mixed": "mixed"}}
				asm, _, err := TranslateNativeSource([]byte(src), opts)
				if err != nil {
					t.Fatal(err)
				}
				prefix := ""
				if goos == "darwin" {
					prefix = "_"
				}
				harness := fmt.Sprintf(`extern void *entry __asm("%sprobe.entry");
extern void *mixedEntry __asm("%sprobe.mixedEntry");
unsigned long mixed(unsigned long x, unsigned long flags, double y) { return flags == 17 ? x+(unsigned long)y : 999; }
int main(void) {
 if (((unsigned long (*)(const char *))entry)("native ABI") != 10) return 1;
 if (((unsigned long (*)(unsigned long,unsigned long))mixedEntry)(5,0x4000000000000000UL) != 7) return 2;
`, prefix, prefix)
				if goarch == "amd64" {
					harness += fmt.Sprintf(`extern void *arithmetic __asm("%sprobe.arithmetic"); unsigned long a[2]={0};
 if (((int (*)(void *,unsigned long))arithmetic)(a,~0UL) || a[0]!=0x123456789abcdef0UL || a[1]!=0xffffffffUL) return 3;
`, prefix)
				}
				harness += "return 0; }\n"
				nativeTargetCompileRun(t, opts, asm, harness)
			})
		}
	}
}

func nativeTargetCompileRun(t *testing.T, opts NativeOptions, asm, harness string) {
	t.Helper()
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "native.s")
	obj := filepath.Join(dir, "native.o")
	for name, value := range map[string]string{"native.s": asm, "main.c": harness} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	arch := "aarch64"
	if opts.GOARCH == "amd64" {
		arch = "x86_64"
	}
	triple := arch + "-unknown-linux-gnu"
	if opts.GOOS == "darwin" {
		triple = arch + "-apple-darwin"
	}
	if b, err := exec.Command(clang, "--target="+triple, "-c", src, "-o", obj).CombinedOutput(); err != nil {
		t.Fatalf("assemble: %v\n%s\n%s", err, b, asm)
	}
	if opts.GOOS == "linux" {
		f, err := elf.Open(obj)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		machine := elf.EM_AARCH64
		if opts.GOARCH == "amd64" {
			machine = elf.EM_X86_64
		}
		if f.Machine != machine || f.Type != elf.ET_REL {
			t.Fatal(f.FileHeader)
		}
		if f.Section(".data.rel.ro") == nil || f.Section(".note.GNU-stack") == nil {
			t.Fatal("missing RELRO or stack metadata")
		}
		syms, err := f.Symbols()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range syms {
			if strings.HasPrefix(s.Name, "probe.") && s.Section != elf.SHN_UNDEF {
				found = true
			}
		}
		if !found {
			t.Fatal("missing DATA symbol")
		}
	} else {
		f, err := macho.Open(obj)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cpu := macho.CpuArm64
		if opts.GOARCH == "amd64" {
			cpu = macho.CpuAmd64
		}
		if f.Cpu != cpu {
			t.Fatal(f.FileHeader)
		}
	}
	if runtime.GOOS == opts.GOOS && runtime.GOARCH == opts.GOARCH {
		exe := filepath.Join(dir, "probe")
		if b, err := exec.Command(clang, obj, filepath.Join(dir, "main.c"), "-o", exe).CombinedOutput(); err != nil {
			t.Fatalf("link: %v\n%s", err, b)
		}
		if b, err := exec.Command(exe).CombinedOutput(); err != nil {
			t.Fatalf("execute: %v\n%s", err, b)
		}
	} else if opts.GOOS == "linux" && os.Getenv("PLAN9ASM_NATIVE_DOCKER") != "" {
		image := os.Getenv("PLAN9ASM_NATIVE_DOCKER")
		if opts.GOARCH == "arm64" {
			image = os.Getenv("PLAN9ASM_NATIVE_DOCKER_ARM64")
		}
		if image == "" {
			t.Log("cross-object validated; no execution image")
			return
		}
		// Opt-in local execution; ordinary Linux CI executes directly above.
		cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "sh", "--platform", "linux/"+opts.GOARCH, "-v", dir+":/probe", "-w", "/probe", image, "-c", "cc -fPIE -pie native.o main.c -Wl,-z,relro,-z,now -o probe && ./probe")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Linux execution: %v\n%s", err, b)
		}
	} else {
		t.Log("object validated; execution needs matching target")
	}
}

func TestNativeAMD64Reject(t *testing.T) {
	opts := NativeOptions{GOOS: "linux", GOARCH: "amd64"}
	for _, body := range []string{"MOVQ foo+8(SP), AX", "MOVQ x+0(FP), AX", "MOVQ $symbol, AX", "MOVQ $1.5, AX", "MOVQ (AX)(CX*4), DX", "MOVQ 2147483648(AX), DX", "MOVQ FS:0(AX), DX", "MOVQ AX, R16", "MOVQ AX, X16", "MOVQ X0, X1", "MOVQ $4, X0", "ADDQ $0xffffffff, AX", "MOVQ $0x100000000, (AX)", "MOVL $0x100000000, AX", "SHLQ $64, AX", "SHLQ CX, AX", "LEAQ AX, BX", "MOVQ (AX), (BX)", "MOVQ AX, $1", "CALL AX", "CALL missing(SB)", "JEQ missing", "RET AX", "MOVB AL, BL", "MOVQ $1, AX, BX", "PUSHQ AX"} {
		t.Run(body, func(t *testing.T) {
			_, _, err := TranslateNativeSource([]byte("TEXT f<>(SB), NOSPLIT|NOFRAME, $0\n"+body+"\n"), opts)
			if err == nil {
				t.Fatal("accepted unsupported form")
			}
		})
	}
	for _, target := range []NativeOptions{{GOOS: "windows", GOARCH: "amd64"}, {GOOS: "linux", GOARCH: "386"}} {
		if _, _, err := TranslateNativeSource([]byte(nativeAMD64Callback), target); err == nil {
			t.Fatal("accepted unsupported target")
		}
	}
	if ForeignNativeFunctions([]byte("TEXT ·f(SB), NOSPLIT, $0\nRET\n"), "amd64") != nil {
		t.Fatal("routed Go entry")
	}
	asm, _, err := TranslateNativeSource([]byte("TEXT f<>(SB), NOSPLIT, $0\nJMP imported(SB)\n"), NativeOptions{GOOS: "linux", GOARCH: "amd64", Imports: map[string]string{"imported": "strlen"}})
	if err != nil || !strings.Contains(asm, `"strlen"@PLT`) {
		t.Fatalf("PLT reference: %s %v", asm, err)
	}
}

func TestNativeAMD64Conditions(t *testing.T) {
	conditions := []struct{ op, expr string }{
		{"JEQ", "a == b"}, {"JNE", "a != b"}, {"JLT", "(int64_t)a < (int64_t)b"}, {"JLE", "(int64_t)a <= (int64_t)b"}, {"JGT", "(int64_t)a > (int64_t)b"}, {"JGE", "(int64_t)a >= (int64_t)b"},
		{"JCS", "a < b"}, {"JCC", "a >= b"}, {"JHI", "a > b"}, {"JLS", "a <= b"}, {"JMI", "(int64_t)(a-b) < 0"}, {"JPL", "(int64_t)(a-b) >= 0"}, {"JOS", "((a^b)&(a^(a-b))) >> 63"}, {"JOC", "!(((a^b)&(a^(a-b))) >> 63)"},
	}
	var src, c strings.Builder
	c.WriteString("#include <stdint.h>\n")
	for i, cond := range conditions {
		fmt.Fprintf(&src, `TEXT compare%d<>(SB), NOSPLIT, $0
 CMPQ DI, SI
 MOVQ $0x1122334455667788, R8
 %s yes
 MOVL $0, AX
 RET
yes:
 MOVL $1, AX
 RET
GLOBL ·compare%d(SB), RODATA, $8
DATA ·compare%d(SB)/8, $compare%d<>(SB)
`, i, cond.op, i, i, i)
		fmt.Fprintf(&c, "extern void *compare%d __asm(\"probe.compare%d\");\n", i, i)
	}
	c.WriteString("int main(void){uint64_t values[]={0,1,17,0x7fffffffffffffffULL,0x8000000000000000ULL,~0ULL};for(int i=0;i<6;i++)for(int j=0;j<6;j++){uint64_t a=values[i],b=values[j];\n")
	for i, cond := range conditions {
		fmt.Fprintf(&c, "if(((int(*)(uint64_t,uint64_t))compare%d)(a,b)!=!!(%s))return %d;\n", i, cond.expr, i+1)
	}
	c.WriteString("}return 0;}")
	opts := NativeOptions{GOOS: "linux", GOARCH: "amd64", PackagePath: "probe"}
	asm, _, err := TranslateNativeSource([]byte(src.String()), opts)
	if err != nil {
		t.Fatal(err)
	}
	nativeTargetCompileRun(t, opts, asm, c.String())
}

func TestNativeAMD64Operations(t *testing.T) {
	src := `TEXT operations<>(SB), NOSPLIT|NOFRAME, $0
 SUBQ $8, SP
 MOVQ SI, X1
 MOVQ X1, R9
 MOVQ R9, (SP)
 MOVQ (SP), X2
 MOVQ X2, AX
 MOVL $0xffffffff, R8
 MOVL R8, R9
 ADDL $2, R9
 SUBL $1, R9
 CMPL R9, $0
 JNE fail
 MOVQ AX, R10
 ANDQ $255, R10
 ORQ $256, R10
 XORQ $256, R10
 TESTQ R10, R10
 JEQ fail
 SARQ $1, AX
 ADDQ $2, AX
 SUBQ $1, AX
 MOVL AX, (DI)
 MOVL (DI), R11
 ANDL $255, R11
 ORL $256, R11
 XORL $256, R11
 SHLL $2, R11
 SHRL $1, R11
 SARL $1, R11
 TESTL R11, R11
 JEQ fail
 CALL local<>(SB)
 ADDQ $8, SP
 RET
fail:
 MOVQ $-1, AX
 ADDQ $8, SP
 RET
TEXT local<>(SB), NOSPLIT, $0
 ADDQ $1, AX
 RET
GLOBL ·entry(SB), RODATA, $8
DATA ·entry(SB)/8, $operations<>(SB)
`
	opts := NativeOptions{GOOS: "linux", GOARCH: "amd64", PackagePath: "probe"}
	asm, _, err := TranslateNativeSource([]byte(src), opts)
	if err != nil {
		t.Fatal(err)
	}
	nativeTargetCompileRun(t, opts, asm, `extern void *entry __asm("probe.entry"); int main(void){unsigned int value=0;unsigned long result=((unsigned long(*)(void*,unsigned long))entry)(&value,10);return result!=7 || value!=6;}`)
}
