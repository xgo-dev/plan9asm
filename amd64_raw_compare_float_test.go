package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Go's yxcmpi table uses X/m, X, signed-imm8 for all four legacy
// floating compares. Intel decoding instead returns destination, source,
// unsigned predicate; a generic operand reversal is not the Go grammar.
func TestX86RawLegacyFloatingCompareCompleteForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var named, raw strings.Builder
			named.WriteString("TEXT compareforms(SB),4,$0-0\n")
			raw.WriteString("TEXT compareforms(SB),4,$0-0\n")
			var expected []byte
			for _, family := range []struct {
				op     string
				prefix []byte
			}{{"CMPPS", nil}, {"CMPPD", []byte{0x66}}, {"CMPSS", []byte{0xf3}}, {"CMPSD", []byte{0xf2}}} {
				forms := []struct {
					source, destination string
					rex                 byte
					address             []byte
				}{{"X1", "X0", 0, []byte{0xc1}}, {"-7(BX)(CX*4)", "X7", 0, []byte{0x7c, 0x8b, 0xf9}}}
				if arch == "amd64" {
					forms = append(forms, struct {
						source, destination string
						rex                 byte
						address             []byte
					}{"X15", "X14", 0x45, []byte{0xf7}})
				}
				for _, form := range forms {
					for predicate := 0; predicate < 256; predicate++ {
						code := append([]byte(nil), family.prefix...)
						if form.rex != 0 {
							code = append(code, form.rex)
						}
						code = append(code, 0x0f, 0xc2)
						code = append(code, form.address...)
						code = append(code, byte(predicate))
						instruction := fmt.Sprintf("%s %s, %s, $%d", family.op, form.source, form.destination, int8(predicate))
						fmt.Fprintln(&named, instruction)
						expected = append(expected, code...)
						decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
						if err != nil {
							t.Fatal(err)
						}
						want, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+instruction+"\n")
						if err != nil {
							t.Fatal(err)
						}
						if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != want.Funcs[0].Instrs[1].Op || !reflect.DeepEqual(decoded.Instrs[0].Args, want.Funcs[0].Instrs[1].Args) {
							t.Fatalf("decoded %x as %+v, want %s", code, decoded.Instrs, instruction)
						}
						// All encodings are checked against Go above; compiling the
						// low predicates and signed boundary cases exercises every
						// semantic selector without bloating every target's IR.
						if predicate < 8 || predicate == 127 || predicate == 128 || predicate == 255 {
							for _, b := range code {
								fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
							}
						}
					}
				}
			}
			named.WriteString("RET\n")
			raw.WriteString("RET\n")
			expected = append(expected, 0xc3)
			if got := assembleX87ControlBytes(t, arch, named.String()); !bytes.HasPrefix(got, expected) {
				t.Fatalf("Go %s compare encodings disagree: got %d bytes, want prefix of %d bytes", arch, len(got), len(expected))
			}
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if (arch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"compareforms": {Name: "compareforms", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-compares.ll", "raw-compares.o", ir)
			}
		})
	}
}

func TestX86RawLegacyFloatingCompareRejectsMalformedPredicate(t *testing.T) {
	for _, predicate := range []x86asm.Arg{nil, x86asm.X0, x86asm.Imm(-1), x86asm.Imm(256)} {
		inst := x86asm.Inst{Op: x86asm.CMPPS, Mode: 64, Args: x86asm.Args{x86asm.X0, x86asm.X1, predicate}}
		if _, err := decodedX86GoSyntax(inst, nil); err == nil {
			t.Fatalf("accepted malformed decoded predicate %v", predicate)
		}
	}
}

func TestX86RawLegacyFloatingCompareRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("execution requires amd64 or Rosetta; five-target object coverage is required separately")
	}
	var source, declarations, functions strings.Builder
	sigs := make(map[string]FuncSig)
	for family, prefix := range [][]byte{nil, {0x66}, {0xf3}, {0xf2}} {
		for memory := 0; memory < 2; memory++ {
			for predicate := 0; predicate < 256; predicate++ {
				name := fmt.Sprintf("rawcmp_%d_%d_%d", family, memory, predicate)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ left+8(FP),AX\nMOVQ right+16(FP),BX\nMOVOU (AX),X0\nMOVOU (BX),X1\n", name)
				code := append([]byte(nil), prefix...)
				modrm := byte(0xc1)
				if memory == 1 {
					modrm = 0x03 // X0, (BX)
				}
				code = append(code, 0x0f, 0xc2, modrm, byte(predicate))
				for _, b := range code {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
				source.WriteString("MOVOU X0,(DI)\nRET\n")
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}}
				fmt.Fprintf(&declarations, "extern void %s(void *,const void *,const void *);\n", name)
				fmt.Fprintf(&functions, "%s,\n", name)
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple, runPrefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
` + declarations.String() + `
static void (*functions[])(void *,const void *,const void *)={
` + functions.String() + `};
static int predicate(double a,double b,int p) {
  int unordered=isnan(a)||isnan(b);
  switch(p&7) {
  case 0:return !unordered&&a==b; case 1:return !unordered&&a<b;
  case 2:return !unordered&&a<=b; case 3:return unordered;
  case 4:return unordered||a!=b; case 5:return unordered||a>=b;
  case 6:return unordered||a>b; default:return !unordered;
  }
}
int main(void) {
  uint32_t f[]={0,0x80000000u,0x3f800000u,0xbf800000u,0x7f800000u,0xff800000u,0x7fc12345u};
  uint64_t d[]={0,0x8000000000000000ull,0x3ff0000000000000ull,0xbff0000000000000ull,0x7ff0000000000000ull,0xfff0000000000000ull,0x7ff8123456789abcull};
  for(int family=0;family<4;family++) for(int mem=0;mem<2;mem++) for(int p=0;p<256;p++)
  for(int a=0;a<7;a++) for(int b=0;b<7;b++) {
    unsigned char left[16],right[16],expected[16],got[16];
    int bytes=family&1?8:4, lanes=16/bytes;
    for(int lane=0;lane<lanes;lane++) {
      int ai=(a+lane)%7,bi=(b+lane)%7;
      if(bytes==8) { memcpy(left+lane*bytes,&d[ai],8); memcpy(right+lane*bytes,&d[bi],8); }
      else { memcpy(left+lane*bytes,&f[ai],4); memcpy(right+lane*bytes,&f[bi],4); }
    }
    memcpy(expected,left,16);
    for(int lane=0;lane<(family>=2?1:lanes);lane++) {
      double x,y;
      if(bytes==8) { memcpy(&x,left+lane*bytes,8); memcpy(&y,right+lane*bytes,8); }
      else { float xf,yf; memcpy(&xf,left+lane*bytes,4); memcpy(&yf,right+lane*bytes,4); x=xf; y=yf; }
      memset(expected+lane*bytes,predicate(x,y,p)?255:0,bytes);
    }
    functions[(family*2+mem)*256+p](got,left,right);
    if(memcmp(got,expected,16)) { fprintf(stderr,"family=%d mem=%d predicate=%d a=%d b=%d\n",family,mem,p,a,b); return 1; }
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_compare_float", triple, ir, mainC, runPrefix)
}
