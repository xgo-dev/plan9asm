package plan9asm

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDataGlobalsRelocationsAndMutability(t *testing.T) {
	// The source contains inline bytes, an unaligned pointer field with an
	// addend, a forward definition, and an externally defined symbol.
	const src = `DATA ·rw+0(SB)/1, $41
GLOBL ·rw(SB), 16, $8
DATA ·ro+0(SB)/1, $11
GLOBL ·ro(SB), (8|16), $4
DATA ·links+0(SB)/1, $85
DATA ·links+1(SB)/8, $·rw+3(SB)
DATA ·links+9(SB)/8, $·external+(3*2)(SB)
DATA ·links+17(SB)/8, $·external-1(SB)
DATA ·links+31(SB)/1, $99
GLOBL ·links(SB), RODATA|NOPTR, $32
`
	f, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	opts := Options{TargetTriple: triple, Goarch: "arm64", ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }}
	// Both inputs use an explicit source pointer width. Execute the 8-byte
	// initializer only on native 64-bit hosts.
	for _, mode := range []string{"module", "text"} {
		t.Run(mode, func(t *testing.T) {
			var ir string
			if mode == "text" {
				ir, err = translateIRText(f, opts)
			} else {
				ir, err = Translate(f, opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			// The LLVM printer quotes names only when required.
			s := strings.ReplaceAll(ir, "\"", "")
			for _, want := range []string{"@rw = global ", "@ro = constant ", "@links = constant ", "@external = external global"} {
				if !strings.Contains(s, want) {
					t.Errorf("missing %q in %s", want, s)
				}
			}
			if t.Failed() {
				return
			}
			switch runtime.GOARCH {
			case "arm64", "amd64":
				llc, clang := requireLlcAndClang(t)
				compiler := []string{clang}
				if runtime.GOOS == "darwin" {
					// Chained fixups require aligned pointers. The classic Mach-O
					// relocation format can represent this packed DATA layout.
					compiler = append(compiler, "-Wl,-no_fixup_chains")
				}
				compileAndRunRuntimeTestWithCompilerOutput(t, llc, compiler, "data_reloc", triple, ir, `
#include <stdint.h>
#include <string.h>
extern unsigned char rw[8];
extern const unsigned char ro[4],links[32];
unsigned char external[16];
static uintptr_t pointer_at(int offset) {
    uintptr_t p;
    memcpy(&p, links + offset, sizeof(p));
    return p;
}

int main(void) {
    if (links[0] != 85 || links[31] != 99 || ro[0] != 11 || rw[0] != 41) return 1;
    if (pointer_at(1) != (uintptr_t)rw + 3) return 2;
    if (pointer_at(9) != (uintptr_t)external + 6) return 3;
    if (pointer_at(17) != (uintptr_t)external - 1) return 4;
    rw[0]++;
    return rw[0] != 42;
}
`, nil)
			}
		})
	}
}

func TestDataGlobalsDirectAndTextStorageClass(t *testing.T) {
	f, err := Parse(ArchARM64, "GLOBL ·rw(SB), $8\nGLOBL ·ro(SB), RODATA+NOPTR, $8\n")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }}
	direct, err := translateModuleDirect(f, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Dispose()
	text, err := translateIRText(f, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, ir := range []string{direct.String(), text} {
		for _, want := range []string{"@rw = global [8 x i8] zeroinitializer", "@ro = constant [8 x i8] zeroinitializer"} {
			if !strings.Contains(ir, want) {
				t.Errorf("missing %q in %s", want, ir)
			}
		}
	}
}

func TestDataGlobalsRejectUnknownSizeAndInvalidRanges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		f       *File
		context bool
	}{
		{"unresolved", &File{Globl: []GloblStmt{{Sym: "·x", Size: -1}}}, true},
		{"unresolved-flag", &File{Globl: []GloblStmt{{Sym: "·x", Size: 1, Flags: "RODATANOPTR"}}}, true},
		{"redeclared", &File{Globl: []GloblStmt{{Sym: "·x", Size: 1}, {Sym: "·x", Size: 1}}}, false},
		{"overrun", &File{Globl: []GloblStmt{{Sym: "·x", Size: 3}}, Data: []DataStmt{{Sym: "·x", Off: 2, Width: 2}}}, false},
		{"overlap", &File{Data: []DataStmt{{Sym: "·x", Width: 8, Addr: "·x(SB)"}, {Sym: "·x", Off: 1, Width: 1}}}, false},
		{"unknown-addend", &File{Data: []DataStmt{{Sym: "·x", Width: 8, Addr: "·x+unknown(SB)"}}}, true},
		{"reloc-width", &File{Data: []DataStmt{{Sym: "·x", Width: 1, Addr: "·x(SB)"}}}, false},
	} {
		for _, mode := range []string{"module", "text"} {
			t.Run(fmt.Sprintf("%s/%s", tc.name, mode), func(t *testing.T) {
				var err error
				tc.f.Arch = ArchARM64
				if mode == "module" {
					_, err = Translate(tc.f, Options{Goarch: "arm64"})
				} else {
					_, err = translateIRText(tc.f, Options{Goarch: "arm64"})
				}
				if err == nil || tc.context && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unexpected error %v", err)
				}
			})
		}
	}
}

func TestDataRelocationSourceWidthAndFunctionSymbol(t *testing.T) {
	llc := requireLLVM22Tool(t, "llc")
	for _, tc := range []struct {
		arch           Arch
		goarch, triple string
		width          int
	}{
		{ArchAMD64, "386", "i386-unknown-linux-gnu", 4},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", 4},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", 8},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", 8},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", 8},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			src := fmt.Sprintf("DATA ·table(SB)/%d, $·f(SB)\nGLOBL ·table(SB), 8, $%d\n", tc.width, tc.width)
			f, err := Parse(tc.arch, src)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(f, Options{Goarch: tc.goarch, TargetTriple: tc.triple, Sigs: map[string]FuncSig{"·f": {Name: "callee", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "@callee") {
				t.Fatal(ir)
			}
			obj := filepath.Join(t.TempDir(), "table.o")
			cmd := exec.Command(llc, "-mtriple="+tc.triple, "-filetype=obj", "-o", obj, "-")
			cmd.Stdin = strings.NewReader(ir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("object compilation: %v\n%s", err, out)
			}
			if stat, err := os.Stat(obj); err != nil || stat.Size() == 0 {
				t.Fatalf("missing object: %v", err)
			}
		})
	}
}

func TestDataGlobalTLSOffsetContract(t *testing.T) {
	for _, tc := range []struct {
		arch Arch
		move string
		word LLVMType
		size int
	}{
		{ArchARM, "MOVW", I32, 4},
		{ArchARM64, "MOVD", I64, 8},
	} {
		t.Run(string(tc.arch), func(t *testing.T) {
			src := fmt.Sprintf("TEXT ·offset(SB),4,$0-%d\n %s ·slot(SB), R0\n %s R0, ret+0(FP)\n RET\nGLOBL ·slot(SB), TLSBSS|DUPOK, $%d\n", tc.size, tc.move, tc.move, tc.size)
			file, err := Parse(tc.arch, src)
			if err != nil {
				t.Fatal(err)
			}
			triple := "armv7-unknown-linux-gnueabihf"
			if tc.arch == ArchARM64 {
				triple = "aarch64-unknown-linux-gnu"
			}
			opt := Options{TargetTriple: triple, Goarch: string(tc.arch), ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }, Sigs: map[string]FuncSig{"offset": {Ret: tc.word, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: tc.word, Field: -1}}}}}}
			ir, err := Translate(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "thread_local(localexec)") || !strings.Contains(ir, "@llvm.threadlocal.address") || !strings.Contains(ir, "@llvm.thread.pointer") {
				t.Fatalf("missing TLS storage or offset computation:\n%s", ir)
			}
			object := filepath.Join(t.TempDir(), "offset.o")
			cmd := exec.Command(requireLLVM22Tool(t, "llc"), "-filetype=obj", "-mtriple="+triple, "-o", object, "-")
			cmd.Stdin = strings.NewReader(ir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			obj, err := elf.Open(object)
			if err != nil {
				t.Fatal(err)
			}
			defer obj.Close()
			syms, err := obj.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			definedTLS := false
			for _, sym := range syms {
				if sym.Name == "slot" && elf.ST_TYPE(sym.Info) == elf.STT_TLS && sym.Section != elf.SHN_UNDEF && sym.Size == uint64(tc.size) {
					definedTLS = true
					break
				}
			}
			if !definedTLS {
				t.Fatal("missing defined TLS symbol in object")
			}
			if runtime.GOOS == "linux" && runtime.GOARCH == string(tc.arch) {
				llc, clang := requireLlcAndClang(t)
				compileAndRunRuntimeTestWithCompilerOutput(t, llc, []string{clang, "-pthread"}, "tls_offset", triple, ir, `
#include <stdint.h>
#include <pthread.h>
extern __thread uintptr_t slot;
extern intptr_t offset(void);
static int check(uintptr_t value) {
    if ((uintptr_t)__builtin_thread_pointer() + (uintptr_t)offset() != (uintptr_t)&slot || slot != 0) return 1;
    slot = value;
    return 0;
}
static void* worker(void* unused) { return (void*)(uintptr_t)check(29); }
int main(void) {
    pthread_t th;
    void* err;
    if (check(11) || pthread_create(&th, 0, worker, 0) || pthread_join(th, &err)) return 1;
    return err != 0 || slot != 11;
}
`, nil)
			}
		})
	}
}

func TestDataGlobalTLSUnsupportedUses(t *testing.T) {
	const glob = "GLOBL ·slot(SB), 256, $8\n"
	for _, tc := range []struct {
		name string
		arch Arch
		src  string
	}{
		{"x86", ArchAMD64, glob},
		{"wasm", ArchWASM, glob},
		{"address", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVD $·slot(SB), R1\n RET\n" + glob},
		{"store", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVD R1, ·slot(SB)\n RET\n" + glob},
		{"addend", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVD ·slot+1(SB), R1\n RET\n" + glob},
		{"symbolic-addend", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVD ·slot+(k)(SB), R1\n RET\n" + glob},
		{"expression-addend", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVD ·slot+(1+2)(SB), R1\n RET\n" + glob},
		{"indexed", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVD ·slot(SB)(R1), R0\n RET\n" + glob},
		{"narrow", ArchARM64, "TEXT ·f(SB),4,$0-0\n MOVW ·slot(SB), R1\n RET\n" + glob},
		{"initialize", ArchARM64, "DATA ·slot(SB)/8, $23\n" + glob},
		{"relocation", ArchARM64, "DATA ·address(SB)/8, $·slot(SB)\n" + glob},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(tc.arch, tc.src)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(f, Options{TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"·f": {Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("got %v; want TLS binding error", err)
			}
		})
	}
}
