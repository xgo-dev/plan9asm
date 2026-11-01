package plan9asm

import (
	"debug/elf"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type x86CustomPointerRuntimeForm struct {
	name, body string
	// -1 selects the whole-vector equality oracle; 0..8 select independent
	// scalar width/extension references in the original-Go and C drivers.
	scalar  int
	aligned bool
}

func x86CustomPointerRuntimeForms() []x86CustomPointerRuntimeForm {
	var forms []x86CustomPointerRuntimeForm
	for index, row := range []struct{ move, left, right string }{
		{"MOVB", "CL", "DL"}, {"MOVW", "CX", "DX"}, {"MOVL", "CX", "DX"},
		{"MOVBWSX", "CX", "DX"}, {"MOVBWZX", "CX", "DX"},
		{"MOVBLSX", "CX", "DX"}, {"MOVBLZX", "CX", "DX"},
		{"MOVWLSX", "CX", "DX"}, {"MOVWLZX", "CX", "DX"},
	} {
		// Different old high bytes make partial-register preservation visible.
		// BX is the caller's independent expected XOR, not pointer bits.
		body := fmt.Sprintf("MOVL $0x9632a5c7,CX\nMOVL $0x5a87bc91,DX\n%s (SI),%s\n%s (DI),%s\nXORL DX,CX\nCMPL CX,BX\nSETEQ (AX)",
			row.move, row.left, row.move, row.right)
		forms = append(forms, x86CustomPointerRuntimeForm{name: row.move, body: body, scalar: index})
	}
	for _, name := range strings.Fields("MOVOU MOVOA MOVO MOVUPS MOVAPS MOVUPD MOVAPD") {
		body := fmt.Sprintf("%s (SI),X0\n%s (DI),X1\nPCMPEQB X1,X0\nPMOVMSKB X0,CX\nCMPL CX,$65535\nSETEQ (AX)", name, name)
		aligned := name == "MOVOA" || name == "MOVO" || name == "MOVAPS" || name == "MOVAPD"
		forms = append(forms, x86CustomPointerRuntimeForm{name: name, body: body, scalar: -1, aligned: aligned})
	}
	return forms
}

const x86CustomPointerRuntimeBatchSize = 4

// Keep the exact typed pointer-role fixture producer, including its physical
// SI/DI/BX/AX transport and complete private helper. Only symbols are renamed
// to combine four independent complete root/helper pairs in one source unit.
func x86CustomPointerRuntimeSource(t *testing.T, start int) (assembly, declarations, observers, observerDecl string, helpers map[string]FuncSig) {
	t.Helper()
	forms := x86CustomPointerRuntimeForms()
	if start < 0 || start%x86CustomPointerRuntimeBatchSize != 0 || start+x86CustomPointerRuntimeBatchSize > len(forms) {
		t.Fatal("invalid complete custom pointer source batch", start)
	}
	helpers = make(map[string]FuncSig)
	for index := start; index < start+x86CustomPointerRuntimeBatchSize; index++ {
		decl, source, helper := x86CustomPointerHelperSource(t, "", forms[index].body)
		root, local := fmt.Sprintf("Value%d", index), fmt.Sprintf("pointerbody%d", index)
		assembly += strings.ReplaceAll(strings.ReplaceAll(source, "Value", root), "pointerbody", local)
		declarations += strings.ReplaceAll(decl, "Value", root) + "\n"
		helper.Name = local
		helpers[local] = helper
		observerDecl += fmt.Sprintf("func Observe%d(p,q *byte,n uint32) uint64\n", index)
		// The raw caller observes exactly the callee's actual bool byte and
		// seven adjacent bytes. Its source is never translated as a Go ABI.
		observers += fmt.Sprintf(`TEXT ·Observe%d(SB),4,$24-20
MOVL p+0(FP),CX
MOVL CX,0(SP)
MOVL q+4(FP),CX
MOVL CX,4(SP)
MOVL n+8(FP),CX
MOVL CX,8(SP)
MOVL $0x5a5a5a5a,12(SP)
MOVL $0x11223344,16(SP)
CALL ·%s(SB)
MOVL 12(SP),CX
MOVL CX,ret+12(FP)
MOVL 16(SP),CX
MOVL CX,ret+16(FP)
RET
`, index, root)
	}
	return
}

func TestX86CustomPointerRuntimeCompleteBoundedFixture(t *testing.T) {
	forms := x86CustomPointerRuntimeForms()
	want := strings.Fields("MOVB MOVW MOVL MOVBWSX MOVBWZX MOVBLSX MOVBLZX MOVWLSX MOVWLZX MOVOU MOVOA MOVO MOVUPS MOVAPS MOVUPD MOVAPD")
	if len(forms) != len(want) || len(forms)%x86CustomPointerRuntimeBatchSize != 0 {
		t.Fatal("incomplete scalar/whole128 native fixture", len(forms))
	}
	seen := make(map[string]bool)
	for start := 0; start < len(forms); start += x86CustomPointerRuntimeBatchSize {
		source, decl, observers, observerDecl, helpers := x86CustomPointerRuntimeSource(t, start)
		file, err := Parse(ArchAMD64, source)
		if err != nil || len(file.Funcs) != 8 || len(helpers) != 4 {
			t.Fatal("batch lost a whole root/helper pair", start, err)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), "main.go", "package main\n"+decl+observerDecl, 0); err != nil {
			t.Fatal(err)
		}
		goDriver, _, wrappers := x86CustomPointerRuntimeDrivers(t, start)
		if _, err := parser.ParseFile(token.NewFileSet(), "main.go", goDriver, 0); err != nil {
			t.Fatal("original numerical/canary driver is malformed", err)
		}
		if !strings.Contains(wrappers, fmt.Sprintf("store i64 %d,", uint64(0x112233445a5a5a5a))) {
			t.Fatal("LLVM raw helper observer lost its seven adjacent canaries")
		}
		observed, err := Parse(ArchAMD64, observers)
		if err != nil || len(observed.Funcs) != 4 {
			t.Fatal("batch lost an independent original raw observer", err)
		}
		if got := x86CustomPointerRuntimeChecks(start); got != []int{3072, 3072, 938, 272}[start/4] {
			t.Fatal("independent true/false/value/canary denominator changed", start, got)
		}
		for index := start; index < start+4; index++ {
			form := forms[index]
			wantScalar := index
			if index >= 9 {
				wantScalar = -1
			}
			wantAligned := form.name == "MOVOA" || form.name == "MOVO" || form.name == "MOVAPS" || form.name == "MOVAPD"
			if form.name != want[index] || seen[form.name] || form.scalar != wantScalar || form.aligned != wantAligned {
				t.Fatal("missing/duplicate native family member", index, form.name)
			}
			seen[form.name] = true
			root, helper := file.Funcs[2*(index-start)], file.Funcs[2*(index-start)+1]
			if root.Sym != fmt.Sprintf("·Value%d", index) || helper.Sym != fmt.Sprintf("pointerbody%d<>", index) ||
				!strings.Contains(source, form.body+"\nRET\n") || !strings.Contains(observers, fmt.Sprintf("CALL ·Value%d(SB)", index)) {
				t.Fatal("native batch did not retain the original complete pair", index)
			}
		}
	}
}

func x86CustomPointerRuntimeChecks(start int) int {
	checks := 0
	for _, form := range x86CustomPointerRuntimeForms()[start : start+4] {
		if form.scalar >= 0 {
			checks += 3 * 8 * 8 * 2 * 2 // offsets, value pair, true/false, typed/raw
		} else if form.aligned {
			checks += 17 * 2 // equal plus each independent mismatching byte
		} else {
			checks += 3 * 17 * 2
		}
	}
	return checks
}

// This portable axis validates the same complete original Go386 executable and
// all generated LLVM shims as objects. It does not execute them on another host
// or stand in for the required native Linux cross-runtime owner below.
func TestX86CustomPointerRuntimeOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for start := 0; start < len(x86CustomPointerRuntimeForms()); start += x86CustomPointerRuntimeBatchSize {
		t.Run(fmt.Sprintf("batch%02d", start/4), func(t *testing.T) {
			original := x86CustomPointerRuntimeOriginal(t, start)
			object, err := elf.Open(original)
			if err != nil {
				t.Fatal(err)
			}
			class, machine := object.Class, object.Machine
			if err := object.Close(); err != nil {
				t.Fatal(err)
			}
			if class != elf.ELFCLASS32 || machine != elf.EM_386 {
				t.Fatal("original Go oracle is not a real Linux i386 executable", class, machine)
			}
			assembly, declarations, _, _, helpers := x86CustomPointerRuntimeSource(t, start)
			_, _, wrappers := x86CustomPointerRuntimeDrivers(t, start)
			pkg := mustGoPackage(t, "pointerroles386", "package main\n"+declarations)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, assembly, pkg, "386", "i386-unknown-linux-gnu", api,
						func(name string) (FuncSig, bool) { sig, ok := helpers[name]; return sig, ok })
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					input, output := filepath.Join(dir, "helper.ll"), filepath.Join(dir, "helper.o")
					if err := os.WriteFile(input, []byte(ir+wrappers), 0600); err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=i386-unknown-linux-gnu", "-filetype=obj", input, "-o", output))
						if info, err := os.Stat(output); err != nil || info.Size() == 0 {
							t.Fatalf("actual LLVM i386 object missing: %v", err)
						}
					}
				})
			}
		})
	}
}

func x86CustomPointerRuntimeDrivers(t *testing.T, start int) (goDriver, driver, wrappersIR string) {
	t.Helper()
	_, declarations, _, observerDecl, _ := x86CustomPointerRuntimeSource(t, start)
	var goCalls, prototypes, cCalls, wrappers strings.Builder
	for index := start; index < start+4; index++ {
		form := x86CustomPointerRuntimeForms()[index]
		fmt.Fprintf(&goCalls, "\trun(%q, %d, %t, Value%d, Observe%d)\n", form.name, form.scalar, form.aligned, index, index)
		aligned := 0
		if form.aligned {
			aligned = 1
		}
		fmt.Fprintf(&prototypes, "extern uint32_t Probe%d(uint8_t *, uint8_t *, uint32_t);\n"+
			"extern uint64_t Raw%d(uint8_t *, uint8_t *, uint32_t);\n", index, index)
		fmt.Fprintf(&cCalls, "    run(\"%s\", %d, %d, Probe%d, Raw%d);\n", form.name, form.scalar, aligned, index, index)
		fmt.Fprintf(&wrappers, `
define i32 @Probe%d(ptr %%p, ptr %%q, i32 %%n) {
  %%v = call i1 @Value%d(ptr %%p, ptr %%q, i32 %%n)
  %%r = zext i1 %%v to i32
  ret i32 %%r
}

define i64 @Raw%d(ptr %%p, ptr %%q, i32 %%n) {
  %%out = alloca i64, align 8
  store i64 1234605616519600730, ptr %%out, align 8
  call void @pointerbody%d(ptr %%p, ptr %%q, i32 %%n, ptr %%out)
  %%r = load i64, ptr %%out, align 8
  ret i64 %%r
}
`, index, index, index, index)
	}
	goDriver = "package main\n\nimport (\n\t\"fmt\"\n\t\"unsafe\"\n)\n\n" + declarations + observerDecl +
		x86CustomPointerRuntimeGoDriver + "\nfunc main() {\n" + goCalls.String() +
		"\tfmt.Printf(\"original386 pointer-role checks: %d\\n\", checks)\n}\n"
	driver = "#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n" + prototypes.String() +
		x86CustomPointerRuntimeCDriver + "\nint main(void) {\n" + cCalls.String() +
		"    printf(\"LLVM386 pointer-role checks: %u\\n\", checks);\n    return 0;\n}\n"
	return goDriver, driver, wrappers.String()
}

func x86CustomPointerRuntimeOriginal(t *testing.T, start int) string {
	t.Helper()
	assembly, _, observers, _, _ := x86CustomPointerRuntimeSource(t, start)
	goDriver, _, _ := x86CustomPointerRuntimeDrivers(t, start)
	dir := t.TempDir()
	for name, contents := range map[string]string{"go.mod": "module pointerroles386\n\ngo 1.20\n", "main.go": goDriver,
		"helper_386.s": assembly, "observer_386.s": observers} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local",
		"GOOS=linux", "GOARCH=386", "GO386=sse2", "CGO_ENABLED=0", "GOMAXPROCS=2", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	return original
}

// These references operate on bytes and Go/C integer conversions, not parsed
// instructions, LLVM values or a common translator result. A scalar true and
// false call differ only in the independent expected XOR argument. Vector
// equality toggles each one of the sixteen input bytes in turn.
const x86CustomPointerRuntimeGoDriver = `
var checks int

func view(kind int, b []byte, old uint32) uint32 {
	u16 := uint16(b[0]) | uint16(b[1])<<8
	u32 := uint32(u16) | uint32(b[2])<<16 | uint32(b[3])<<24
	switch kind {
	case 0:
		return old&0xffffff00 | uint32(b[0])
	case 1:
		return old&0xffff0000 | uint32(u16)
	case 2:
		return u32
	case 3:
		return old&0xffff0000 | uint32(uint16(int16(int8(b[0]))))
	case 4:
		return old&0xffff0000 | uint32(b[0])
	case 5:
		return uint32(int32(int8(b[0])))
	case 6:
		return uint32(b[0])
	case 7:
		return uint32(int32(int16(u16)))
	case 8:
		return uint32(u16)
	}
	panic("unknown scalar reference")
}

func run(name string, kind int, aligned bool,
	logical func(*byte, *byte, uint32) bool,
	raw func(*byte, *byte, uint32) uint64) {
	values := [...]uint32{0, 1, 0x7f, 0x80, 0x8001, 0x7fffffff, 0x80000000, 0xffffffff}
	offsets := []int{0, 1, 3}
	if aligned {
		offsets = []int{0}
	}

	for _, off := range offsets {
		count := 17
		if kind >= 0 {
			count = 64
		}
		for sample := 0; sample < count; sample++ {
			var p, q [64]byte
			for i := range p {
				p[i] = byte(17*i + 0x91)
				q[i] = byte(29*i + 0x43)
			}
			pi := 16 + int((-uintptr(unsafe.Pointer(&p[16])))&15) + off
			qi := 16 + int((-uintptr(unsafe.Pointer(&q[16])))&15) + off
			if kind >= 0 {
				a, b := values[sample/8], values[sample%8]
				for k := 0; k < 4; k++ {
					p[pi+k] = byte(a >> uint(8*k))
					q[qi+k] = byte(b >> uint(8*k))
				}
			} else {
				for k := 0; k < 16; k++ {
					p[pi+k] = byte(31*k + 0x80)
					q[qi+k] = p[pi+k]
				}
				if sample < 16 {
					q[qi+sample] ^= 0x81
				}
			}

			savedP, savedQ := p, q
			expected := uint32(0)
			variants := 1
			if kind >= 0 {
				expected = view(kind, p[pi:], 0x9632a5c7) ^ view(kind, q[qi:], 0x5a87bc91)
				variants = 2
			}
			for variant := 0; variant < variants; variant++ {
				n := expected ^ uint32(variant)
				want := sample == 16
				if kind >= 0 {
					want = variant == 0
				}
				byteWant := uint64(0)
				if want {
					byteWant = 1
				}

				if got := logical(&p[pi], &q[qi], n); got != want {
					panic(fmt.Sprintf("%s offset=%d sample=%d variant=%d logical=%t want=%t",
						name, off, sample, variant, got, want))
				}
				checks++
				if p != savedP || q != savedQ {
					panic("logical call mutated input/canaries: " + name)
				}

				if got := raw(&p[pi], &q[qi], n); got != 0x112233445a5a5a00|byteWant {
					panic(fmt.Sprintf("%s offset=%d sample=%d variant=%d raw=%x",
						name, off, sample, variant, got))
				}
				checks++
				if p != savedP || q != savedQ {
					panic("raw call mutated input/canaries: " + name)
				}
			}
		}
	}
}
`

const x86CustomPointerRuntimeCDriver = `
static unsigned checks;

static uint32_t view(int kind, const uint8_t *b, uint32_t old) {
    uint16_t u16 = (uint16_t)b[0] | (uint16_t)b[1] << 8;
    uint32_t u32 = (uint32_t)u16 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    switch (kind) {
    case 0:
        return (old & UINT32_C(0xffffff00)) | b[0];
    case 1:
        return (old & UINT32_C(0xffff0000)) | u16;
    case 2:
        return u32;
    case 3:
        return (old & UINT32_C(0xffff0000)) | (uint16_t)(int16_t)(int8_t)b[0];
    case 4:
        return (old & UINT32_C(0xffff0000)) | b[0];
    case 5:
        return (uint32_t)(int32_t)(int8_t)b[0];
    case 6:
        return b[0];
    case 7:
        return (uint32_t)(int32_t)(int16_t)u16;
    case 8:
        return u16;
    }
    fputs("unknown scalar reference\n", stderr);
    exit(1);
}

static void run(const char *name, int kind, int aligned,
    uint32_t (*logical)(uint8_t *, uint8_t *, uint32_t),
    uint64_t (*raw)(uint8_t *, uint8_t *, uint32_t)) {
    static const uint32_t values[] = {0, 1, 0x7f, 0x80, 0x8001, 0x7fffffff, 0x80000000, 0xffffffff};
    static const unsigned offsets[] = {0, 1, 3};

    for (unsigned oi = 0; oi < (aligned ? 1u : 3u); oi++) {
        unsigned off = offsets[oi], count = kind >= 0 ? 64 : 17;
        for (unsigned sample = 0; sample < count; sample++) {
            _Alignas(16) uint8_t p[64], q[64], savedP[64], savedQ[64];
            unsigned pi = 16 + off, qi = 16 + off;
            for (unsigned i = 0; i < 64; i++) {
                p[i] = (uint8_t)(17*i + 0x91);
                q[i] = (uint8_t)(29*i + 0x43);
            }
            if (kind >= 0) {
                uint32_t a = values[sample/8], b = values[sample%8];
                for (unsigned k = 0; k < 4; k++) {
                    p[pi+k] = (uint8_t)(a >> (8*k));
                    q[qi+k] = (uint8_t)(b >> (8*k));
                }
            } else {
                for (unsigned k = 0; k < 16; k++) {
                    p[pi+k] = (uint8_t)(31*k + 0x80);
                    q[qi+k] = p[pi+k];
                }
                if (sample < 16) {
                    q[qi+sample] ^= 0x81;
                }
            }

            memcpy(savedP, p, 64);
            memcpy(savedQ, q, 64);
            uint32_t expected = 0;
            unsigned variants = 1;
            if (kind >= 0) {
                expected = view(kind, p+pi, 0x9632a5c7) ^ view(kind, q+qi, 0x5a87bc91);
                variants = 2;
            }
            for (unsigned variant = 0; variant < variants; variant++) {
                uint32_t n = expected ^ variant, want = kind >= 0 ? variant == 0 : sample == 16;
                uint32_t got = logical(p+pi, q+qi, n);
                checks++;
                if (got != want || memcmp(p, savedP, 64) || memcmp(q, savedQ, 64)) {
                    fprintf(stderr, "%s offset=%u sample=%u variant=%u logical=%u want=%u or input/canary mutation\n",
                        name, off, sample, variant, got, want);
                    exit(1);
                }

                uint64_t observed = raw(p+pi, q+qi, n);
                checks++;
                if (observed != (UINT64_C(0x112233445a5a5a00) | want) ||
                    memcmp(p, savedP, 64) || memcmp(q, savedQ, 64)) {
                    fprintf(stderr, "%s offset=%u sample=%u variant=%u raw=%llx or input/canary mutation\n",
                        name, off, sample, variant, (unsigned long long)observed);
                    exit(1);
                }
            }
        }
    }
}
`
