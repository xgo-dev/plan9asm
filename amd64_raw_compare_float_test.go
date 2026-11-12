package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
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
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if (arch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				ir := x86UnboundVoidRawScalarFormatObject(t, raw.String(), arch, triple)
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

func TestCrossLinuxRuntimeMatrixX86RawLegacyFloatingCompareRuntime(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, functions, originals, originalFunctions, goOpcodes strings.Builder
	goOpcodes.WriteString("TEXT originalopcodes(SB),4,$0-0\n")
	var expectedOpcodes []byte
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
				expectedOpcodes = append(expectedOpcodes, code...)
				sourceOperand := "X1"
				if memory == 1 {
					sourceOperand = "(BX)"
				}
				opcode := [...]string{"CMPPS", "CMPPD", "CMPSS", "CMPSD"}[family]
				fmt.Fprintf(&goOpcodes, "%s %s,X0,$%d\n", opcode, sourceOperand, int8(predicate))
				for _, b := range code {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
				source.WriteString("MOVOU X0,(DI)\nRET\n")
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}}
				fmt.Fprintf(&declarations, "extern void %s(void *,const void *,const void *);\n", name)
				fmt.Fprintf(&functions, "%s,\n", name)
				originals.WriteString(x86RawLegacyFloatingCompareOriginalKernel(name, code))
				fmt.Fprintf(&originalFunctions, "original_%s,\n", name)
			}
		}
	}
	goOpcodes.WriteString("RET\n")
	expectedOpcodes = append(expectedOpcodes, 0xc3)
	if got := assembleX87ControlBytes(t, "amd64", goOpcodes.String()); !bytes.HasPrefix(got, expectedOpcodes) {
		t.Fatalf("actual Go full imm8 register/(BX) opcode bytes differ: got=%d expected prefix=%d", len(got), len(expectedOpcodes))
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#ifndef _WIN32
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
` + declarations.String() + `
typedef void (*comparison)(void *,const void *,const void *);
static comparison functions[]={
` + functions.String() + `};
` + originals.String() + `
static comparison originals[]={
` + originalFunctions.String() + `};

// Only predicates 0..7 have the legacy IEEE truth table below. Bits 3..7
// are reserved: an observed machine result is not a mathematical definition.
static int predicate(double a,double b,int p) {
  int unordered=isnan(a)||isnan(b);
  switch(p) {
  case 0: return !unordered&&a==b;
  case 1: return !unordered&&a<b;
  case 2: return !unordered&&a<=b;
  case 3: return unordered;
  case 4: return unordered||a!=b;
  case 5: return unordered||a>=b;
  case 6: return unordered||a>b;
  case 7: return !unordered;
  default: return -1;
  }
}

static unsigned observe(comparison fn,void *out,const void *left,const void *right) {
  unsigned control=0x1f80,observed;
  __asm__ volatile("ldmxcsr %0"::"m"(control):"memory");
  fn(out,left,right);
  __asm__ volatile("stmxcsr %0":"=m"(observed)::"memory");
  return observed;
}

#ifndef _WIN32
// Preserve the original packed memory opcode's unaligned behavior. The
// outcome is an observation of this execution environment, not a new policy.
static int same_unaligned_outcome(comparison actual,comparison original) {
  int statuses[2];
  for(int which=0;which<2;which++) {
    pid_t child=fork();
    if(child<0) return 1;
    if(child==0) {
      struct rlimit no_core={0,0};
      if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
      _Alignas(16) unsigned char left[32]={0},right[32]={0},out[16];
      observe(which?original:actual,out,left,right+1);
      _exit(0);
    }
    if(waitpid(child,&statuses[which],0)!=child) return 1;
    if(WIFEXITED(statuses[which])) {
      if(WEXITSTATUS(statuses[which])!=0) return 1;
    } else if(!WIFSIGNALED(statuses[which]) ||
              (WTERMSIG(statuses[which])!=SIGSEGV && WTERMSIG(statuses[which])!=SIGBUS)) {
      return 1;
    }
  }
  if(WIFSIGNALED(statuses[0])!=WIFSIGNALED(statuses[1]) ||
     (WIFSIGNALED(statuses[1]) && WTERMSIG(statuses[0])!=WTERMSIG(statuses[1]))) {
    fprintf(stderr,"unaligned original opcode outcome differs actual=%x original=%x\n",statuses[0],statuses[1]);
    return 1;
  }
  return 0;
}
#endif

int main(void) {
  uint32_t f[]={0,0x80000000u,0x3f800000u,0xbf800000u,0x7f800000u,0xff800000u,0x7fc12345u};
  uint64_t d[]={0,0x8000000000000000ull,0x3ff0000000000000ull,0xbff0000000000000ull,0x7ff0000000000000ull,0xfff0000000000000ull,0x7ff8123456789abcull};
  for(int family=0;family<4;family++) {
    for(int mem=0;mem<2;mem++) {
      for(int p=0;p<256;p++) {
        for(int a=0;a<7;a++) {
          for(int b=0;b<7;b++) {
            _Alignas(16) unsigned char left_storage[64],right_storage[64];
            unsigned char actual_storage[48],original_storage[48],expected[16];
            unsigned char left_before[64],right_before[64];
            memset(left_storage,0xa7,sizeof(left_storage));
            memset(right_storage,0xb9,sizeof(right_storage));
            memset(actual_storage,0xc3,sizeof(actual_storage));
            memset(original_storage,0xd5,sizeof(original_storage));
            unsigned char *left=left_storage+16;
            // Packed memory remains aligned; scalar memory additionally
            // exercises a real unaligned address without inventing a shadow.
            unsigned char *right=right_storage+16+(family>=2 && mem?3:0);
            unsigned char *got=actual_storage+16,*observed=original_storage+16;
            int bytes=family&1?8:4,lanes=16/bytes;
            for(int lane=0;lane<lanes;lane++) {
              int ai=(a+lane)%7,bi=(b+lane)%7;
              if(bytes==8) {
                memcpy(left+lane*bytes,&d[ai],8);
                memcpy(right+lane*bytes,&d[bi],8);
              } else {
                memcpy(left+lane*bytes,&f[ai],4);
                memcpy(right+lane*bytes,&f[bi],4);
              }
            }
            memcpy(left_before,left_storage,sizeof(left_storage));
            memcpy(right_before,right_storage,sizeof(right_storage));
            int index=(family*2+mem)*256+p;
            unsigned original_csr=observe(originals[index],observed,left,right);
            unsigned actual_csr=observe(functions[index],got,left,right);
            if(memcmp(got,observed,16) || actual_csr!=original_csr) {
              fprintf(stderr,"original opcode mismatch family=%d mem=%d imm8=%d a=%d b=%d CSR=%x/%x\n",
                      family,mem,p,a,b,actual_csr,original_csr);
              return 1;
            }
            if(memcmp(left_storage,left_before,sizeof(left_storage)) ||
               memcmp(right_storage,right_before,sizeof(right_storage))) return 2;
            for(int byte=0;byte<16;byte++) {
              if(actual_storage[byte]!=0xc3 || actual_storage[32+byte]!=0xc3 ||
                 original_storage[byte]!=0xd5 || original_storage[32+byte]!=0xd5) return 3;
            }
            if(p<8) {
              memcpy(expected,left,16);
              for(int lane=0;lane<(family>=2?1:lanes);lane++) {
                double x,y;
                if(bytes==8) {
                  memcpy(&x,left+lane*bytes,8);
                  memcpy(&y,right+lane*bytes,8);
                } else {
                  float xf,yf;
                  memcpy(&xf,left+lane*bytes,4);
                  memcpy(&yf,right+lane*bytes,4);
                  x=xf;
                  y=yf;
                }
                memset(expected+lane*bytes,predicate(x,y,p)?255:0,bytes);
              }
              if(memcmp(got,expected,16)) {
                fprintf(stderr,"independent IEEE mismatch family=%d mem=%d predicate=%d a=%d b=%d\n",family,mem,p,a,b);
                return 4;
              }
            }
          }
        }
      }
#ifndef _WIN32
      if(mem && family<2) {
        const int predicates[]={0,8,255};
        for(int axis=0;axis<3;axis++) {
          int p=predicates[axis];
          int index=(family*2+mem)*256+p;
          if(same_unaligned_outcome(functions[index],originals[index])) return 5;
        }
      }
#endif
    }
  }
  return 0;
}
`
	execution.compileAndRunLLVM(t, "raw_compare_float", ir, mainC, "-O2")
	t.Logf("2048 exact original imm8 opcodes ×49 inputs: full X bytes, canaries and MXCSR agree; only 0..7 have independent IEEE truth; transport=%v", execution.prefix)
}

func x86RawLegacyFloatingCompareOriginalKernel(name string, code []byte) string {
	var directive strings.Builder
	for index, b := range code {
		if index != 0 {
			directive.WriteByte(',')
		}
		fmt.Fprintf(&directive, "0x%02x", b)
	}
	return fmt.Sprintf(`
static __attribute__((noinline)) void original_%s(void *out,const void *left,const void *right) {
  __asm__ volatile(
      "movdqu (%%1),%%%%xmm0\n\t"
      "movdqu (%%%%rbx),%%%%xmm1\n\t"
      ".byte %s\n\t"
      "movdqu %%%%xmm0,(%%0)"
      ::"r"(out),"r"(left),"b"(right)
      :"xmm0","xmm1","memory");
}
`, name, directive.String())
}

func TestX86RawLegacyFloatingCompareOriginalKernelRetainsReservedBytes(t *testing.T) {
	for _, prefix := range [][]byte{nil, {0x66}, {0xf3}, {0xf2}} {
		for _, modrm := range []byte{0xc1, 0x03} {
			for predicate := 0; predicate < 256; predicate++ {
				code := append([]byte(nil), prefix...)
				code = append(code, 0x0f, 0xc2, modrm, byte(predicate))
				kernel := x86RawLegacyFloatingCompareOriginalKernel("byte_identity", code)
				var exact strings.Builder
				for index, b := range code {
					if index != 0 {
						exact.WriteByte(',')
					}
					fmt.Fprintf(&exact, "0x%02x", b)
				}
				if strings.Count(kernel, ".byte ") != 1 || !strings.Contains(kernel, ".byte "+exact.String()+`\n\t`) {
					t.Fatalf("original kernel altered source bytes %x:\n%s", code, kernel)
				}
				for _, required := range []string{`movdqu (%1),%%xmm0`, `movdqu (%%rbx),%%xmm1`, `movdqu %%xmm0,(%0)`, `"b"(right)`, `"memory"`} {
					if !strings.Contains(kernel, required) {
						t.Fatalf("original register/memory/output binding lost %q: %x", required, code)
					}
				}
				if predicate >= 8 {
					folded := append([]byte(nil), code...)
					folded[len(folded)-1] &= 7
					if x86RawLegacyFloatingCompareOriginalKernel("byte_identity", folded) == kernel {
						t.Fatalf("reserved imm8 %d folded to a mathematical predicate", predicate)
					}
				}
			}
		}
	}
}
