package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawX87AliasFamilyMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	wantTables := map[Op]string{"FCLEX": "ynone", "FINIT": "ynone", "FSAVE": "ysvrs_om", "FSTCW": "ysvrs_om", "FSTENV": "ysvrs_om", "FSTSW": "ystsw"}
	if len(x86RawX87ControlAliases) != len(wantTables) {
		t.Fatalf("raw x87 control grammar has %d aliases, want %d", len(x86RawX87ControlAliases), len(wantTables))
	}
	for decoded, goOp := range x86RawX87ControlAliases {
		if decoded.String() != "FN"+string(goOp)[1:] || !isX87Op(goOp) {
			t.Fatalf("raw %s does not resolve to the Go x87 lowerer for %s", decoded, goOp)
		}
		row := regexp.MustCompile(`\{A` + string(goOp) + `,\s*(\w+),`).FindSubmatch(data)
		if len(row) != 2 || string(row[1]) != wantTables[goOp] {
			t.Fatalf("Go %s row = %q, want operand table %s", goOp, row, wantTables[goOp])
		}
	}
}

func TestX86RawX87EnvironmentAddressSpaces(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		source.WriteString("TEXT x87segments(SB),4,$0-0\n")
		for _, opcode := range [][]byte{{0xdd, 0x30}, {0xd9, 0x38}, {0xd9, 0x30}, {0xdd, 0x38}} {
			for _, segment := range []byte{0x64, 0x65} {
				for _, b := range append([]byte{segment}, opcode...) {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
			}
		}
		source.WriteString("RET\n")
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"x87segments": {Name: "x87segments", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "x87-segments.ll", "x87-segments.o", ir)
	}
}

func TestX86RawX87DoesNotWidenLegacyEnvironmentFormat(t *testing.T) {
	for _, code := range [][]byte{{0x66, 0xdd, 0x30}, {0x66, 0xd9, 0x30}} {
		inst, err := x86asm.Decode(code, 64)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodedX86GoSyntax(inst, code); err == nil {
			t.Fatalf("silently treated 16-bit environment %x as the Go 32-bit environment form", code)
		}
	}
}

// asm6.go's FCLEX/FINIT/FSAVE/FSTCW/FSTENV/FSTSW rows encode the
// no-wait forms, despite omitting Intel's N in their Go mnemonic.
func x87NoWaitFixtures() []struct {
	code []byte
	text string
} {
	return []struct {
		code []byte
		text string
	}{
		{[]byte{0xdb, 0xe2}, "FCLEX"},
		{[]byte{0xdb, 0xe3}, "FINIT"},
		{[]byte{0xdd, 0x30}, "FSAVE (AX)"},
		{[]byte{0xd9, 0x38}, "FSTCW (AX)"},
		{[]byte{0xd9, 0x30}, "FSTENV (AX)"},
		{[]byte{0xdd, 0x38}, "FSTSW (AX)"},
		{[]byte{0xdf, 0xe0}, "FSTSW AX"},
		{[]byte{0xdd, 0x74, 0x8b, 0xf9}, "FSAVE -7(BX)(CX*4)"},
		{[]byte{0xd9, 0x7c, 0x8b, 0xf9}, "FSTCW -7(BX)(CX*4)"},
		{[]byte{0xd9, 0x74, 0x8b, 0xf9}, "FSTENV -7(BX)(CX*4)"},
		{[]byte{0xdd, 0x7c, 0x8b, 0xf9}, "FSTSW -7(BX)(CX*4)"},
	}
}

func TestX86RawX87NoWaitCompleteGoForms(t *testing.T) {
	for _, goarch := range []string{"386", "amd64"} {
		t.Run(goarch, func(t *testing.T) {
			var named, raw strings.Builder
			named.WriteString("TEXT x87control(SB),4,$0-0\n")
			raw.WriteString("TEXT x87control(SB),4,$0-0\n")
			var expectedBytes []byte
			for _, test := range x87NoWaitFixtures() {
				fmt.Fprintln(&named, test.text)
				expectedBytes = append(expectedBytes, test.code...)
				for _, b := range test.code {
					fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
				}
				decoded, err := decodeX86RawDirectives(rawX86Function(test.code), goarch)
				if err != nil {
					t.Fatal(err)
				}
				want, err := Parse(ArchAMD64, "TEXT f(SB),$0-0\n"+test.text+"\n")
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != want.Funcs[0].Instrs[1].Op || !reflect.DeepEqual(decoded.Instrs[0].Args, want.Funcs[0].Instrs[1].Args) {
					t.Fatalf("decoded %x as %+v, want %s", test.code, decoded.Instrs, test.text)
				}
			}
			named.WriteString("RET\n")
			raw.WriteString("RET\n")
			expectedBytes = append(expectedBytes, 0xc3)
			code := assembleX87ControlBytes(t, goarch, named.String())
			if !bytes.HasPrefix(code, expectedBytes) {
				t.Fatalf("Go %s encoded no-wait family as %x, want prefix %x", goarch, code, expectedBytes)
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if (goarch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				for _, mode := range []X87Mode{X87Auto, X87Software} {
					var irs []string
					for _, source := range []string{named.String(), raw.String()} {
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						ir, err := Translate(file, Options{Goarch: goarch, TargetTriple: triple, X87Mode: mode, Sigs: map[string]FuncSig{"x87control": {Name: "x87control", Ret: Void}}})
						if err != nil {
							t.Fatal(err)
						}
						irs = append(irs, ir)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					for _, ir := range irs {
						compileLLVMToObject(t, llc, triple, "x87-control.ll", "x87-control.o", ir)
					}
				}
			}
		})
	}
}

func assembleX87ControlBytes(t *testing.T, goarch, source string) []byte {
	t.Helper()
	dir := t.TempDir()
	name := filepath.Join(dir, "control.s")
	if err := os.WriteFile(name, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-S", "-o", filepath.Join(dir, "control.o"), name)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go assembler: %v\n%s", err, out)
	}
	var code []byte
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseUint(fields[0][2:], 16, 32)
		if err != nil || int(offset) != len(code) {
			t.Fatalf("noncontiguous assembler bytes: %s", line)
		}
		for i, field := range fields[1:] {
			if i >= 16 || len(field) != 2 {
				break
			}
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil {
				break
			}
			code = append(code, byte(value))
		}
	}
	return code
}

func TestX86RawX87ClearExceptionRuntimeSemantics(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; all-host x86 object tests remain required")
	}
	const source = `TEXT rawClear(SB),$0-0
BYTE $0xdb; BYTE $0xe2
RET
TEXT namedClear(SB),$0-0
FCLEX
RET
TEXT rawInit(SB),$0-0
BYTE $0xdb; BYTE $0xe3
RET
TEXT namedInit(SB),$0-0
FINIT
RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, name := range []string{"rawClear", "namedClear", "rawInit", "namedInit"} {
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if crossRosetta {
		triple, prefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <stdio.h>
extern void rawClear(void), namedClear(void), rawInit(void), namedInit(void);
static void seed(void) {
  uint16_t cw=0x077f;
  __asm__ volatile("fninit; fldcw %0; fldz; fldz; fdivp; fstp %%st(0)" : : "m"(cw) : "st");
}
static uint16_t sw(void) { uint16_t v; __asm__ volatile("fnstsw %0":"=a"(v)); return v; }
static uint16_t cw(void) { uint16_t v; __asm__ volatile("fnstcw %0":"=m"(v)); return v; }
int main(void) {
  void (*f[])(void)={rawClear,namedClear,rawInit,namedInit};
  for (int i=0;i<4;i++) {
    seed();
    if (!(sw()&1) || cw()!=0x077f) return 20;
    f[i]();
    if ((sw()&0x80ff) || cw()!=(i<2 ? 0x077f : 0x037f)) {
      fprintf(stderr,"x87 operation %d did not update hardware: sw=%x cw=%x\n",i,sw(),cw());
      __asm__ volatile("fninit"); return 1;
    }
  }
  __asm__ volatile("fninit"); return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_x87_clear", triple, ir, mainC, prefix)
}

func TestX86RawX87SoftwareClearPreservesAllStatusFields(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("hardware status oracle requires amd64 or Rosetta")
	}
	const source = `TEXT clearModeledStatus(SB),4,$0-16
MOVQ env+0(FP),BX
FLDENV (BX)
BYTE $0xdb; BYTE $0xe2
XORL AX,AX
FSTSW AX
MOVQ AX,ret+8(FP)
RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if crossRosetta {
		triple, prefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, X87Mode: X87Software, Sigs: map[string]FuncSig{
		"clearModeledStatus": {Name: "clearModeledStatus", Args: []LLVMType{Ptr}, Ret: I64, Frame: FrameLayout{
			Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint64_t clearModeledStatus(const void *);
int main(void) {
  struct { unsigned char bytes[28]; } env={{0}};
  uint16_t control=0x037f, tags=0xffff;
  memcpy(env.bytes,&control,2); memcpy(env.bytes+8,&tags,2);
  for (unsigned v=0;v<=0xffff;v++) {
    uint16_t status=v, expected;
    memcpy(env.bytes+4,&status,2);
    __asm__ volatile("fldenv %1; fnclex; fnstsw %0" : "=a"(expected) : "m"(env) : "memory");
    uint64_t got=clearModeledStatus(&env);
    if (got!=expected) {
      fprintf(stderr,"status %x: got %llx, hardware %x\n",v,(unsigned long long)got,expected);
      __asm__ volatile("fninit"); return 1;
    }
  }
  __asm__ volatile("fninit"); return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "x87_software_clear", triple, ir, mainC, prefix)
}

func TestX86X87WordStoresToFPParametersAndResults(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"FSTCW", "FSTSW"} {
		for _, kind := range []string{"param", "result"} {
			name := op + kind
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-10\nFINIT\n", name)
			if kind == "param" {
				fmt.Fprintf(&source, "%s input+0(FP)\nMOVW input+0(FP),AX\nMOVW AX,ret+8(FP)\n", op)
			} else {
				fmt.Fprintf(&source, "%s ret+8(FP)\n", op)
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{I16}, Ret: I16, Frame: FrameLayout{
				Params: []FrameSlot{{Offset: 0, Type: I16, Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I16, Index: 0, Field: -1}},
			}}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern uint16_t FSTCWparam(uint16_t),FSTCWresult(uint16_t),FSTSWparam(uint16_t),FSTSWresult(uint16_t);
int main(void) {
  return FSTCWparam(0xffff)!=0x037f || FSTCWresult(0xffff)!=0x037f ||
         FSTSWparam(0xffff)!=0 || FSTSWresult(0xffff)!=0;
}
`
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc", "x86_64-w64-windows-gnu"} {
		goarch := "amd64"
		if strings.HasPrefix(triple, "i") {
			goarch = "386"
		}
		for _, mode := range []X87Mode{X87Auto, X87Software} {
			t.Run(fmt.Sprintf("%s/%d", triple, mode), func(t *testing.T) {
				ir, err := Translate(file, Options{Goarch: goarch, TargetTriple: triple, X87Mode: mode, Sigs: sigs})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "x87-fp.ll", "x87-fp.o", ir)
				crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && triple == "x86_64-apple-darwin" && rosettaAvailable()
				hostOS := map[string]string{"darwin": "apple-darwin", "linux": "linux-gnu", "windows": "windows-msvc"}[runtime.GOOS]
				if crossRosetta || (goarch == runtime.GOARCH && hostOS != "" && strings.Contains(triple, hostOS)) {
					var prefix []string
					if crossRosetta {
						prefix = []string{"/usr/bin/arch", "-x86_64"}
					}
					runtimeTriple := testTargetTriple(runtime.GOOS, goarch)
					// Windows CI provides MinGW, not the MSVC CRT. Retain the
					// MSVC object check above, but regenerate the runtime module
					// for the actual linker ABI instead of requesting MSVC libs.
					runtimeIR, err := Translate(file, Options{Goarch: goarch, TargetTriple: runtimeTriple, X87Mode: mode, Sigs: sigs})
					if err != nil {
						t.Fatal(err)
					}
					compileAndRunRuntimeTestForTarget(t, llc, clang, "x87_fp", runtimeTriple, runtimeIR, mainC, prefix)
				}
			})
		}
	}
}

func TestX86X87WordStoresRejectUnknownFPSlots(t *testing.T) {
	for _, op := range []string{"FSTCW", "FSTSW"} {
		file, err := Parse(ArchAMD64, "TEXT bad(SB),4,$0-0\n"+op+" unknown+24(FP)\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, arch := range []string{"386", "amd64"} {
			if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Fatalf("%s accepted %s store to an undeclared FP slot", arch, op)
			}
		}
	}
}
