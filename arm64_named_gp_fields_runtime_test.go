package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// One whole original Go program and one C harness retain the complete family.
// No instruction/shift starts a separate compiler, linker or execution process.
func TestCrossLinuxRuntimeMatrixARM64NamedMoveWideAndBitfield(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	values := []uint64{0, 1, ^uint64(0), 0x0123456789abcdef,
		0xfedcba9876543210, 1 << 63, 0xffffffff, 0xffffffff00000000}
	rows := arm64NamedMoveBitfieldCases()
	var source, declarations, goCalls, cDeclarations, cCalls, goExpected, cExpected strings.Builder
	signatures := make(map[string]FuncSig)
	for index, row := range rows {
		name := fmt.Sprintf("Fields%d", index)
		result := row.destination
		if result == 31 {
			result = 2
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVD input+0(FP),R1\nMOVD initial+8(FP),R2\n%s\nMOVD R%d,ret+16(FP)\nRET\n",
			name, row.instruction(), result)
		fmt.Fprintf(&declarations, "func %s(uint64,uint64) uint64\n", name)
		fmt.Fprintf(&goCalls, "%s,\n", name)
		fmt.Fprintf(&cDeclarations, "extern uint64_t %s(uint64_t,uint64_t);\n", name)
		fmt.Fprintf(&cCalls, "%s,\n", name)
		goExpected.WriteString("{")
		cExpected.WriteString("{")
		for _, input := range values {
			for _, initial := range values {
				// The independent bit selector from the RED numerical test is
				// materialized before either original Go or LLVM executes.
				want := row.value(input, initial)
				fmt.Fprintf(&goExpected, "0x%x,", want)
				fmt.Fprintf(&cExpected, "UINT64_C(0x%x),", want)
			}
		}
		goExpected.WriteString("},\n")
		cExpected.WriteString("},\n")
		signatures[name] = FuncSig{Name: name, Args: []LLVMType{I64, I64}, Ret: I64, Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}},
			Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
		}}
	}
	const goValues = `var values=[]uint64{0,1,^uint64(0),0x0123456789abcdef,0xfedcba9876543210,1<<63,0xffffffff,0xffffffff00000000}
`
	goMain := "package main\n" + declarations.String() + goValues +
		"var calls=[]func(uint64,uint64)uint64{\n" + goCalls.String() + "}\n" +
		"var expected=[][64]uint64{\n" + goExpected.String() + "}\n" + `
func main(){ for n,call:=range calls { for i,a:=range values { for j,b:=range values {
  if call(a,b)!=expected[n][8*i+j] { panic("original named move/bitfield mismatch") }
} } } }
`
	runARM64GoInternalOracle(t, source.String(), goMain, len(runner) != 0)
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() +
		"static uint64_t (*calls[])(uint64_t,uint64_t)={\n" + cCalls.String() + "};\n" +
		"static const uint64_t expected[][64]={\n" + cExpected.String() + "};\n" + `
int main(void) {
  const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(1)<<63,UINT64_C(0xffffffff),UINT64_C(0xffffffff00000000)};
  for(unsigned n=0;n<sizeof(calls)/sizeof(calls[0]);n++) {
    for(unsigned i=0;i<8;i++) for(unsigned j=0;j<8;j++) {
      uint64_t got=calls[n](values[i],values[j]);
      if(got!=expected[n][8*i+j]) {
        fprintf(stderr,"named move/bitfield case=%u input=%u initial=%u got=%016llx expected=%016llx\n",n,i,j,(unsigned long long)got,(unsigned long long)expected[n][8*i+j]);
        return 1;
      }
    }
  }
  return 0;
}
`
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "test/namedfields", "package namedfields\n"+declarations.String())
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			context := llvm.NewContext()
			defer context.Dispose()
			var ir string
			options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: signatures, ResolveSym: resolve}
			switch api {
			case "text":
				ir, err = Translate(file, options)
			case "module":
				var module llvm.Module
				module, err = TranslateModuleInContext(context, file, options)
				if !module.IsNil() {
					ir = module.String()
					module.Dispose()
				}
			case "GoModule":
				var translated *GoModuleTranslation
				translated, err = translateGoModuleInContext(context, pkg, []byte(source.String()), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
				})
				if translated != nil {
					ir = translated.Module.String()
					translated.Module.Dispose()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []int{0, 2} {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "named_fields", triple, ir, cMain, runner, level)
			}
		})
	}
	t.Logf("all %d named move/bitfield cases x64 input pairs: original Go plus three LLVM APIs, O0/O2", len(rows))
}
