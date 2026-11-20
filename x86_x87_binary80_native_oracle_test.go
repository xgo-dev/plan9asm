package plan9asm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86X87Binary80ConstantRuntimeIR(t *testing.T, arch, triple, api string, mode X87Mode) string {
	t.Helper()
	source, declarations := x86X87NativeConstantProgram(t, arch)
	statusSource, statusDeclarations := x86X87NativeClearStatusProgram(t, arch)
	source += statusSource
	declarations += statusDeclarations
	ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, triple, api, mode)
	if err != nil || ir == "" {
		t.Fatal("complete initialized constant source", err)
	}
	bits := x86X87NativeConstantBitsIR(t, arch, triple)
	_, body, found := strings.Cut(bits, "\n")
	if !found {
		t.Fatal("private observer has no module body")
	}
	return ir + body
}

func x86X87NativeClearStatusProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	result := 8
	if arch == "386" {
		result = 4
	}
	var source, declarations strings.Builder
	for index, row := range x86X87ClearStatusCases() {
		body := row.prefix + "FSTSW AX\nANDW $" + row.mask + ",AX\n" + fmt.Sprintf("MOVW AX,ret+%d(FP)\n", result) + row.suffix + "RET"
		_, _, _, complete := x86ResultInitializationFixture(t, arch, "func Value(input uint16) uint16", body)
		name := fmt.Sprintf("StatusClear%d", index)
		source.WriteString(strings.Replace(complete, "TEXT ·Value(SB)", "TEXT ·"+name+"(SB)", 1))
		fmt.Fprintf(&declarations, "func %s(input uint16) uint16\n", name)
	}
	return source.String(), declarations.String()
}

func x86X87Binary80ConstantCOracle() string {
	var declarations, observers, comparisons, cases strings.Builder
	for index, op := range x86X87NativeConstants {
		fmt.Fprintf(&declarations, "extern void NativeBits%s(unsigned char *, unsigned short);\nextern unsigned short Constant%s(unsigned short, double);\n", op, op)
		fmt.Fprintf(&observers, "NativeBits%s,", op)
		fmt.Fprintf(&comparisons, "Constant%s,", op)
		fmt.Fprintf(&cases, "case %d: __asm__ volatile(\"%s; fstl %%1; fstpt %%0\" : \"=m\"(*(unsigned char (*)[10])out), \"=m\"(*(double *)(out+16)) : : \"st\", \"memory\"); break;\n", index, strings.ToLower(string(op)))
	}
	for index := range x86X87ClearStatusCases() {
		fmt.Fprintf(&declarations, "extern unsigned short StatusClear%d(unsigned short);\n", index)
	}
	return declarations.String() + `
#ifdef X87_ORIGINAL_GO_RECORDS
#include <stdio.h>
#endif
typedef unsigned char State[512] __attribute__((aligned(16)));
static void save(State *s) { __asm__ volatile("fxsave %0" : "=m"(*s) : : "memory"); }
static void restore(const State *s) { __asm__ volatile("fxrstor %0" : : "m"(*s) : "memory"); }
static int equal(const unsigned char *a, const unsigned char *b, unsigned n) {
  for (unsigned i=0;i<n;i++) if(a[i]!=b[i]) return 0;
  return 1;
}
static void oracle(unsigned op, unsigned short cw, unsigned char *out) {
  __asm__ volatile("fldcw %0" : : "m"(cw) : "memory");
  switch(op) {` + cases.String() + `}
}
static unsigned short compare(unsigned op, unsigned short cw, double input) {
  unsigned char constant[24];
  oracle(op,cw,constant);
  unsigned short status;
  __asm__ volatile("fldl %1; fldt %2; fcompp; fnstsw %0" : "=m"(status) : "m"(input), "m"(*(unsigned char (*)[10])constant) : "st", "st(1)", "memory");
  return status&0x4500;
}
int main(int argc,char **argv) {
#ifdef X87_ORIGINAL_GO_RECORDS
  if(argc!=2)return 7;
  FILE *reference=fopen(argv[1],"rb");
  if(!reference)return 8;
#endif
  void (*const observe[])(unsigned char *,unsigned short)={` + observers.String() + `};
  unsigned short (*const public_compare[])(unsigned short,double)={` + comparisons.String() + `};
  unsigned short (*const clear_status[])(unsigned short)={StatusClear0,StatusClear1,StatusClear2};
  const unsigned short words[]={0x037f,0x077f,0x0b7f,0x0f7f};
  const union {unsigned long long bits; double value;} input={0x400921fb54442d18ULL};
  State original, baseline, after;
  save(&original);
  __asm__ volatile("fninit" : : : "memory");
  save(&baseline);
  unsigned checks=0;
  int failure=0;
  for(unsigned op=0;op<7&&!failure;op++) for(unsigned rc=0;rc<4&&!failure;rc++) {
    unsigned char expected[24]={0},actual[24]={0};
    restore(&baseline);
    oracle(op,words[rc],expected);
    restore(&baseline);
    observe[op](actual,words[rc]);
    save(&after);
    if(!equal(expected,actual,10)||!equal(expected+16,actual+16,8)) failure=1;
    if(after[4]!=0||(after[3]&0x38)!=0) failure=2;
    restore(&baseline);
    unsigned short status=compare(op,words[rc],input.value);
#ifdef X87_ORIGINAL_GO_RECORDS
    unsigned short original;
    if(fread(&original,sizeof(original),1,reference)!=1||original!=status) failure=7;
#endif
    restore(&baseline);
    if(public_compare[op](words[rc],input.value)!=status) failure=3;
    checks++;
  }
  unsigned cleared=0;
  for(unsigned i=0;i<3&&!failure;i++) {
    restore(&baseline);
    unsigned short status=clear_status[i](0);
    if(status!=0)failure=9;
#ifdef X87_ORIGINAL_GO_RECORDS
    unsigned short expected=0;
    if(fread(&expected,sizeof(expected),1,reference)!=1||expected!=status)failure=9;
#endif
    cleared++;
  }
  restore(&original);
  save(&after);
  if(!equal(original,after,5)||!equal(original+24,after+24,4)) failure=4;
  unsigned top=(original[3]>>3)&7;
  for(unsigned i=0;i<8;i++) if(original[4]&(1U<<((top+i)&7)))
    if(!equal(original+32+16*i,after+32+16*i,10)) failure=5;
  if(checks!=28) failure=6;
  if(cleared!=3)failure=9;
#ifdef X87_ORIGINAL_GO_RECORDS
  if(fgetc(reference)!=EOF||ferror(reference)||fclose(reference))failure=8;
#endif
  return failure;
}
`
}

func x86X87NativeConstantOriginalDriver(declarations string) string {
	var calls strings.Builder
	for _, op := range x86X87NativeConstants {
		fmt.Fprintf(&calls, "for _,cw:=range []uint16{0x037f,0x077f,0x0b7f,0x0f7f}{value:=Constant%s(cw,math.Float64frombits(0x400921fb54442d18));binary.LittleEndian.PutUint16(out[:],value);if _,err:=os.Stdout.Write(out[:]);err!=nil{panic(err)}}\n", op)
	}
	for index := range x86X87ClearStatusCases() {
		fmt.Fprintf(&calls, "{value:=StatusClear%d(0);binary.LittleEndian.PutUint16(out[:],value);if _,err:=os.Stdout.Write(out[:]);err!=nil{panic(err)}}\n", index)
	}
	return "package main\nimport(\"encoding/binary\";\"math\";\"os\";\"runtime\";\"unsafe\")\n" + declarations + `
func SaveState(state *byte)
func RestoreState(state *byte)
func main(){
runtime.LockOSThread()
var saved [528]byte
offset:=(-uintptr(unsafe.Pointer(&saved[0])))&15
SaveState(&saved[offset])
defer RestoreState(&saved[offset])
var out [2]byte
` + calls.String() + "}\n"
}

func TestX86X87NativeConstantNumericalArtifact(t *testing.T) {
	// This is source/artifact generation. Native execution is an independent
	// Linux owner; parsing or compiling this artifact is not a runtime PASS.
	ir := x86X87Binary80ConstantRuntimeIR(t, "amd64", "x86_64-unknown-linux-gnu", "Go", X87Hardware)
	t.Log("X87_BINARY80_CONSTANT_IR_BASE64=" + base64.StdEncoding.EncodeToString([]byte(ir)))
	t.Log("X87_BINARY80_CONSTANT_C_BASE64=" + base64.StdEncoding.EncodeToString([]byte(x86X87Binary80ConstantCOracle())))
}

func TestX86X87ValueBackendModes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, arch := range []string{"386", "amd64"} {
		source, declaration := x86X87NativeConstantProgram(t, arch)
		for _, target := range []string{"armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, mode := range []X87Mode{X87Auto, X87Software, X87Hardware} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%d/%s", arch, target, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declaration, arch, target, api, mode)
						if mode == X87Hardware {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("nonmatching hardware backend was not explicitly refused", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("portable Auto/Software constant source", err)
						}
						if strings.Contains(ir, "asm sideeffect") {
							t.Fatal("portable backend emitted x86 native assembly")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target, ir, level)
						}
					})
				}
			}
		}
	}
}
