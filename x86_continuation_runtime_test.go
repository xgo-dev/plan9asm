package plan9asm

import (
	"strings"
	"testing"
)

// Both independent callers use the complete original four-TEXT file. They
// observe the opaque out pointer, scalar result, zero/nonzero FLAGS edge,
// GP/X transport, unsigned wrap and neighboring caller canaries separately.
func x86ContinuationRuntimeFixture(t *testing.T, arch, dispatch string) (string, Options, string, string) {
	t.Helper()
	source, options := x86ContinuationResultFixture(t, arch, true)
	word, typ, ctyp := "Q", "uint64", "uint64_t"
	values := "0,1,7,0xffffffff,0x100000000,0x8000000000000000,^uint64(0)"
	cvalues := "0,1,7,UINT64_C(0xffffffff),UINT64_C(0x100000000),UINT64_C(0x8000000000000000),UINT64_MAX"
	if arch == "386" {
		word, typ, ctyp = "L", "uint32", "uint32_t"
		values = "0,1,7,0xffff,0x7fffffff,0x80000000,^uint32(0)"
		cvalues = "0,1,7,0xffff,0x7fffffff,0x80000000,UINT32_MAX"
	}
	if dispatch == "register" {
		source = strings.Replace(source, " JMP (SI)", " MOV"+word+" (SI),AX\n JMP AX", 1)
	} else if dispatch != "memory" {
		t.Fatal("unknown continuation runtime dispatch", dispatch)
	}
	goDriver := `package main
import "fmt"
func Prepare()
func Evaluate(out *@WORD, value @WORD) @WORD
func Advance()
func Finish()
func main() {
 Prepare()
 calls:=0
 for _,value:=range []@WORD{@VALUES} {
  want:=value
  if value!=0 {want++}
  out:=[3]@WORD{0x12345678,0,0x87654321}
  got:=Evaluate(&out[1],value)
  if got!=want || out[1]!=want || out[0]!=0x12345678 || out[2]!=0x87654321 {
   panic(fmt.Sprintf("continuation input=%x got=%x want=%x out=%x",value,got,want,out))
  }
  calls++
 }
 fmt.Printf("continuation original/LLVM: %d independent checks\n",calls)
}
`
	goDriver = strings.NewReplacer("@WORD", typ, "@VALUES", values).Replace(goDriver)
	cDriver := `#include <stdint.h>
#include <stdio.h>
extern void Prepare(void);
extern @WORD Evaluate(@WORD *, @WORD);
int main(void) {
 Prepare();
 const @WORD values[]={@VALUES};
 unsigned calls=0;
 for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
  @WORD value=values[i],want=value+(value!=0);
  @WORD out[]={0x12345678,0,0x87654321};
  @WORD got=Evaluate(out+1,value);
  if(got!=want || out[1]!=want || out[0]!=0x12345678 || out[2]!=0x87654321) {
   fprintf(stderr,"continuation sample=%u got=%llx want=%llx out=%llx\n",i,(unsigned long long)got,(unsigned long long)want,(unsigned long long)out[1]);
   return 1;
  }
  calls++;
 }
 printf("continuation original/LLVM: %u independent checks\n",calls);
 return 0;
}
`
	cDriver = strings.NewReplacer("@WORD", ctyp, "@VALUES", cvalues).Replace(cDriver)
	return source, options, goDriver, cDriver
}

func TestX86ContinuationRuntimeFixtureOwnsCompleteRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, dispatch := range []string{"memory", "register"} {
			source, options, original, llvm := x86ContinuationRuntimeFixture(t, arch, dispatch)
			if strings.Count(source, "TEXT ") != 4 || len(options.X86TailGroups) != 1 || len(options.X86TailGroups[0].Helpers) != 2 ||
				!strings.Contains(source, "X0") || !strings.Contains(source, "JEQ") ||
				!strings.Contains(original, "got!=want || out[1]!=want") || !strings.Contains(llvm, "got!=want || out[1]!=want") ||
				strings.Contains(original+llvm, "@WORD") || strings.Contains(original+llvm, "@VALUES") {
				t.Fatal("runtime fixture lost complete source/independent observable roles")
			}
		}
	}
}
