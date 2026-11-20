package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

type x86FloatCompareOriginalVector struct {
	opcode      string
	bits, width int
	scalar      bool
}

func x86FloatCompareOriginalVectors() []x86FloatCompareOriginalVector {
	return []x86FloatCompareOriginalVector{
		{"VCMPPS", 32, 16, false}, {"VCMPPS", 32, 32, false},
		{"VCMPPD", 64, 16, false}, {"VCMPPD", 64, 32, false},
		{"VCMPSS", 32, 16, true}, {"VCMPSD", 64, 16, true},
	}
}

func x86FloatCompareOriginalVectorC() string {
	var source strings.Builder
	source.WriteString(x86FloatCompareIndependentC)
	for index, fixture := range x86FloatCompareOriginalVectors() {
		fmt.Fprintf(&source, `
__attribute__((target("avx"))) static void vector%d(uint8_t *out,const uint8_t *a,const uint8_t *b,unsigned predicate,unsigned csr){
 typedef uint8_t vector __attribute__((vector_size(%d)));
 vector x,y,result;memcpy(&x,a,sizeof(x));memcpy(&y,b,sizeof(y));
 unsigned saved,after;uint8_t carry;
 __asm__ volatile("stmxcsr %%0":"=m"(saved));
 __asm__ volatile("ldmxcsr %%0"::"m"(csr));
 switch(predicate){
`, index, fixture.width)
		for predicate := 0; predicate < 32; predicate++ {
			fmt.Fprintf(&source, " case %d: __asm__ volatile(\"stc; %s $%d,%%3,%%2,%%0; setc %%1\":\"=x\"(result),\"=qm\"(carry):\"x\"(x),\"x\"(y):\"cc\");break;\n",
				predicate, strings.ToLower(fixture.opcode), predicate)
		}
		source.WriteString(" }\n __asm__ volatile(\"stmxcsr %0\":\"=m\"(after));\n __asm__ volatile(\"ldmxcsr %0\"::\"m\"(saved));\n memcpy(out,&result,sizeof(result));memcpy(out+sizeof(result),&after,4);out[sizeof(result)+4]=carry;\n}\n")
	}
	source.WriteString("typedef void(*vector_fn)(uint8_t*,const uint8_t*,const uint8_t*,unsigned,unsigned);\nstatic vector_fn vectors[]={vector0,vector1,vector2,vector3,vector4,vector5};\n")
	return source.String()
}

// This original-Go driver and the C opcode reference execute complete native
// VEX instructions. In particular NaN/denormal pairs occur in both orders and
// the full instruction's CSR is compared, not a per-lane COMI/class union.
func x86FloatCompareOriginalVectorSources() (source, decls, calls, metadata string) {
	var assembly, declarations, functions, descriptors strings.Builder
	assembly.WriteString("#include \"textflag.h\"\n")
	for index, fixture := range x86FloatCompareOriginalVectors() {
		bank := "X"
		if fixture.width == 32 {
			bank = "Y"
		}
		for predicate := 0; predicate < 32; predicate++ {
			name := fmt.Sprintf("vector%d_%d", index, predicate)
			fmt.Fprintf(&assembly, `TEXT ·%s(SB),NOSPLIT,$8-32
MOVQ out+0(FP),AX
MOVQ a+8(FP),BX
MOVQ b+16(FP),CX
STMXCSR 0(SP)
LDMXCSR csr+24(FP)
VMOVUPS (BX),%s0
VMOVUPS (CX),%s1
STC
%s $%d,%s1,%s0,%s%d
VMOVUPS %s%d,(AX)
STMXCSR %d(AX)
SETCS %d(AX)
LDMXCSR 0(SP)
RET
`, name, bank, bank, fixture.opcode, predicate, bank, bank, bank, predicate%3,
				bank, predicate%3, fixture.width, fixture.width+4)
			fmt.Fprintf(&declarations, "func %s(out,a,b *[40]byte,csr uint32)\n", name)
			fmt.Fprintf(&functions, "%s,\n", name)
			fmt.Fprintf(&descriptors, "{%d,%d},\n", fixture.bits, fixture.width)
		}
	}
	return assembly.String(), declarations.String(), functions.String(), descriptors.String()
}

func TestX86FloatingCompareOriginalVectorAssemblerPrograms(t *testing.T) {
	assembly, _, _, _ := x86FloatCompareOriginalVectorSources()
	if strings.Count(assembly, "TEXT ·vector") != 192 {
		t.Fatal("incomplete native VEX predicate fixture inventory")
	}
	dir := t.TempDir()
	input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(input, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "tool", "asm", "-p", "originalvectorcompare", "-I",
		filepath.Join(runtime.GOROOT(), "pkg", "include"), "-o", object, input)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=local")
	x86FloatCompareCaptureCommand(t, command)
	if info, err := os.Lstat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("actual Go VEX assembler missing regular nonempty object: %v", err)
	}
}

// Exercise the generated first-party driver with ordinary Go callees before
// requiring an ISA. This is a buffer-lifetime/reset contract, not a comparison
// oracle: the original-opcode Go/C test independently checks those results.
func TestX86FloatingCompareOriginalVectorBufferLifetime(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_float_compare_original_vector_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var driver string
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "goDriver" {
			return true
		}
		literal, ok := declaration.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("original Go driver must retain its literal source")
		}
		driver, err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	if driver == "" {
		t.Fatal("missing original Go vector driver")
	}
	_, _, functions, descriptors := x86FloatCompareOriginalVectorSources()
	var callees strings.Builder
	for index, fixture := range x86FloatCompareOriginalVectors() {
		for predicate := 0; predicate < 32; predicate++ {
			fmt.Fprintf(&callees, "func vector%d_%d(out,a,b *[40]byte,csr uint32){check(%d,%d,%d,out,a,b,csr)}\n",
				index, predicate, index*32+predicate, fixture.bits, fixture.width)
		}
	}
	const check = `
var seen [192][3]*[40]byte
var calls int
func check(index,bits,width int,out,a,b *[40]byte,csr uint32){
 const perFunction=18*18*6
 if index!=calls/perFunction{panic("sample/function matrix order")}
 if calls%perFunction==0{seen[index]=[3]*[40]byte{out,a,b}}
 if seen[index]!=[3]*[40]byte{out,a,b}{panic("buffers allocated per sample")}
 for _,v:=range out{if v!=0xc3{panic("output was not fully reset")}}
 for i:=width;i<40;i++{if a[i]!=0||b[i]!=0{panic("input tail was not fully reset")}}
 for lane:=bits/8;lane<width;lane++{
  if a[lane]!=a[lane%(bits/8)]||b[lane]!=b[lane%(bits/8)]{panic("input lanes were not initialized")}
 }
 for i:=0;i<width+4;i++{out[i]=byte(calls+i)}
 out[width+4]=1
 calls++
}
`
	source := strings.NewReplacer("FUNCTIONS", functions, "DESCRIPTORS", descriptors).Replace(driver)
	source = strings.Replace(source, "fmt.Printf(\"%016x\\n\",hash)",
		"if calls!=192*18*18*6{panic(\"incomplete sample matrix\")};fmt.Printf(\"%016x\\n\",hash)", 1)
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module vectorbufferlifetime\n\ngo 1.20\n", "main.go": source + callees.String() + check,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("go", "run", "-p=2", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	output := x86FloatCompareCaptureCommand(t, command)
	if len(output) != 17 {
		t.Fatalf("buffer-lifetime oracle output: %q", output)
	}
	t.Log("192 functions ×1944 samples reuse independent input/output buffers with complete reset/canary checks")
}

func x86FloatCompareOriginalVectorRuntime(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	execution.requireAVX(t)
	x86FloatCompareVerifyArguments(t, execution)
	dir := t.TempDir()
	assembly, declarations, functions, descriptors := x86FloatCompareOriginalVectorSources()
	const goDriver = `package main
import("encoding/binary";"fmt")
func main(){
 functions:=[]func(*[40]byte,*[40]byte,*[40]byte,uint32){FUNCTIONS}
 descriptors:=[][2]int{DESCRIPTORS}
 edges32:=[]uint64{0,0x80000000,1,0x80000001,0x7fffff,0x800000,0x3f800000,0xbf800000,0x3f800001,0x7f7fffff,0xff7fffff,0x7f800000,0xff800000,0x7fc12345,0xffc45678,0x7f812345,0xff845678,0x7fffffff}
 edges64:=[]uint64{0,0x8000000000000000,1,0x8000000000000001,0xfffffffffffff,0x10000000000000,0x3ff0000000000000,0xbff0000000000000,0x3ff0000000000001,0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8123456789abc,0xfff8fedcba987654,0x7ff0123456789abc,0xfff0fedcba987654,0x7fffffffffffffff}
 controls:=[]uint32{0x1f80,0x1fc0,0x9f80,0x9fc0,0x1fbf,0x7fc5}
 hash:=uint64(1469598103934665603)
 for index,fn:=range functions{
  bits,width:=descriptors[index][0],descriptors[index][1]
 bytes,edges:=bits/8,edges32
  if bits==64{edges=edges64}
  var a,b [40]byte
  var output struct{before byte;data [40]byte;after byte}
  for _,av:=range edges{for _,bv:=range edges{for _,csr:=range controls{
   a,b=[40]byte{},[40]byte{}
   output=struct{before byte;data [40]byte;after byte}{before:0xa7,after:0xb9}
   for i:=range output.data{output.data[i]=0xc3}
   for i:=0;i<width;i+=bytes{
    if bits==32{
     binary.LittleEndian.PutUint32(a[i:],uint32(av));binary.LittleEndian.PutUint32(b[i:],uint32(bv))
    }else{
     binary.LittleEndian.PutUint64(a[i:],av);binary.LittleEndian.PutUint64(b[i:],bv)
    }
   }
   beforeA,beforeB:=a,b;fn(&output.data,&a,&b,csr)
   if a!=beforeA||b!=beforeB||output.before!=0xa7||output.after!=0xb9{panic("input/output canary mutation")}
   for _,v:=range output.data[width+5:]{if v!=0xc3{panic("output extent")}}
   if output.data[width+4]!=1{panic("EFLAGS carry")}
   for _,v:=range output.data[:width+5]{hash^=uint64(v);hash*=1099511628211}
  }}}
 }
 fmt.Printf("%016x\n",hash)
}
`
	goSource := strings.NewReplacer("FUNCTIONS", functions, "DESCRIPTORS", descriptors).Replace(goDriver)
	for name, source := range map[string]string{
		"go.mod": "module originalvectorcompare\n\ngo 1.20\n", "main.go": goSource + declarations,
		"original_amd64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goExecutable := filepath.Join(dir, gotoolchain.HostExecutable("original-go"))
	command := exec.Command("go", "build", "-p=2", "-o", goExecutable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0",
		"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	x86FloatCompareCaptureCommand(t, command)
	actualGo := execution.run(t, goExecutable)
	const main = `
int main(void){
 const unsigned bits[]={32,32,64,64,32,64},widths[]={16,32,16,32,16,16};
 uint64_t hash=UINT64_C(1469598103934665603);
 for(unsigned op=0;op<6;op++)for(unsigned predicate=0;predicate<32;predicate++){
  unsigned bytes=bits[op]/8,width=widths[op];const uint64_t *edges=bytes==4?edges32:edges64;
  for(unsigned i=0;i<18;i++)for(unsigned j=0;j<18;j++)for(unsigned c=0;c<6;c++){
   uint8_t a[40]={0},b[40]={0},storage[42],expected[32],beforeA[40],beforeB[40];
   uint8_t *out=storage+1;memset(storage,0xc3,sizeof(storage));
   for(unsigned lane=0;lane<width;lane+=bytes){memcpy(a+lane,edges+i,bytes);memcpy(b+lane,edges+j,bytes);}
   memcpy(beforeA,a,40);memcpy(beforeB,b,40);memcpy(expected,a,width);
   unsigned compared=op>=4?bytes:width;
   for(unsigned lane=0;lane<compared;lane+=bytes)
    memset(expected+lane,independent_compare(bits[op],edges[i],edges[j],predicate,controls[c])?255:0,bytes);
   vectors[op](out,a,b,predicate,controls[c]);
   if(memcmp(out,expected,width)||out[width+4]!=1||storage[0]!=0xc3||storage[41]!=0xc3||
      memcmp(a,beforeA,40)||memcmp(b,beforeB,40)){
    fprintf(stderr,"original VEX op=%u pred=%u i=%u j=%u csr=%x mask=%llx want=%llx\n",
     op,predicate,i,j,controls[c],(unsigned long long)read_bits(out,bytes),(unsigned long long)read_bits(expected,bytes));return 1;
   }
   for(unsigned byte=width+5;byte<40;byte++)if(out[byte]!=0xc3)return 2;
   for(unsigned byte=0;byte<width+5;byte++){hash^=out[byte];hash*=UINT64_C(1099511628211);}
  }
 }
 printf("%016llx\n",(unsigned long long)hash);return 0;
}
`
	cSource, cExecutable := filepath.Join(dir, "original.c"), filepath.Join(dir, "original-c")
	if err := os.WriteFile(cSource, []byte(x86FloatCompareOriginalVectorC()+main), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, cSource, cExecutable)
	actualC := execution.run(t, cExecutable)
	if string(actualGo) != string(actualC) || len(actualC) != 17 {
		t.Fatalf("actual Go/original VEX full result+MXCSR+CF mismatch: Go=%q C=%q", actualGo, actualC)
	}
	t.Logf("192 actual Go VEX programs ×1944 complete IEEE/DAZ/MXCSR pairs including NaN×denormal in both orders; same original native opcode C+integer truth agree: %s route=%v; EVEX execution not covered",
		strings.TrimSpace(string(actualC)), execution.prefix)
}
