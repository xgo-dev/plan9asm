package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

// Only fixture layout uses the ordinary Go ABI derivation. Neither numerical
// truth nor MXCSR expectations use the production compare implementation.
type x86FloatCompareFPOracle struct {
	name, declaration, row string
	bits, predicate        int
	mask                   bool
	axis                   x86FloatCompareRuntimeISA
	sig                    FuncSig
}

func x86FloatCompareFPOracles(t *testing.T) []x86FloatCompareFPOracle {
	t.Helper()
	var fixtures []x86FloatCompareFPOracle
	var declarations strings.Builder
	declarations.WriteString("package oracle\n")
	for _, bits := range []int{32, 64} {
		for _, spelling := range []string{"legacy", "vex", "evex"} {
			for predicate := 0; predicate < 8; predicate++ {
				fixture := x86FloatCompareFPOracle{
					name: fmt.Sprintf("fp%d%s%d", bits, spelling, predicate),
					bits: bits, predicate: predicate, mask: spelling == "evex",
					axis: map[string]x86FloatCompareRuntimeISA{"legacy": x86FloatCompareSSE, "vex": x86FloatCompareVEX, "evex": x86FloatCompareEVEX}[spelling],
				}
				fixture.declaration = fmt.Sprintf("func %s(out *[20]byte,source [%d]byte,left uint%d)\n", fixture.name, bits/8, bits)
				declarations.WriteString(fixture.declaration)
				opcode := "CMPSS"
				if bits == 64 {
					opcode = "CMPSD"
				}
				fixture.row = fmt.Sprintf("%s source+8(FP),X0,$%d", opcode, predicate)
				if spelling == "vex" {
					fixture.row = fmt.Sprintf("V%s $%d,source+8(FP),X0,X2", opcode, predicate)
				} else if spelling == "evex" {
					fixture.row = fmt.Sprintf("V%s $%d,source+8(FP),X0,K1,K2", opcode, predicate)
				}
				fixtures = append(fixtures, fixture)
			}
		}
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "oracle.go", declarations.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	pkg, err := (&types.Config{Sizes: sizes}).Check("oracle", set, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := range fixtures {
		fixture := &fixtures[index]
		fixture.sig, err = DeriveGoFuncABI0Signature(fixture.name, pkg.Scope().Lookup(fixture.name).(*types.Func), "amd64", sizes)
		if err != nil {
			t.Fatal(err)
		}
		if len(fixture.sig.Frame.Params) != fixture.bits/8+2 {
			t.Fatalf("Go array did not derive independent byte fields: %+v", fixture.sig.Frame)
		}
	}
	return fixtures
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpans(t *testing.T) {
	x86FloatCompareFPScalarByteSpansRuntime(t, x86FloatCompareSSE)
}

func x86FloatCompareFPAssembly(fixtures []x86FloatCompareFPOracle) (string, map[string]FuncSig) {
	var assembly strings.Builder
	sigs := map[string]FuncSig{}
	for _, fixture := range fixtures {
		move, destination := "MOVSS", "X0"
		if fixture.bits == 64 {
			move = "MOVSD"
		}
		if fixture.axis == x86FloatCompareVEX {
			destination = "X2"
		}
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\nMOVQ out+0(FP),AX\n%s left+%d(FP),X0\nMOVQ $1,DX\nKMOVQ DX,K1\n%s\n",
			fixture.name, 8+2*(fixture.bits/8), move, 8+fixture.bits/8, fixture.row)
		if fixture.mask {
			assembly.WriteString("KMOVQ K2,(AX)\n")
		} else {
			fmt.Fprintf(&assembly, "MOVOU %s,(AX)\n", destination)
		}
		assembly.WriteString("STMXCSR 16(AX)\nRET\n")
		sigs[fixture.name] = fixture.sig
	}
	return assembly.String(), sigs
}

func x86FloatCompareFPScalarByteSpansRuntime(t *testing.T, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, axis)
	var fixtures []x86FloatCompareFPOracle
	for _, fixture := range x86FloatCompareFPOracles(t) {
		if fixture.axis == axis {
			fixtures = append(fixtures, fixture)
		}
	}
	if len(fixtures) != 16 {
		t.Fatal("incomplete scalar FP-byte-field execution axis", axis, len(fixtures))
	}
	assembly, sigs := x86FloatCompareFPAssembly(fixtures)
	var wrappers, declarations, checks strings.Builder
	for index, fixture := range fixtures {

		// A C bit carrier is converted into the precise LLVM array value. C's
		// aggregate calling convention is not assumed to match Go's signature.
		fmt.Fprintf(&wrappers, "define void @check_%s(ptr %%out,i64 %%right,i64 %%left){\n", fixture.name)
		packed := "poison"
		for field := 0; field < fixture.bits/8; field++ {
			fmt.Fprintf(&wrappers, " %%shift%d=lshr i64 %%right,%d\n %%byte%d=trunc i64 %%shift%d to i8\n %%pack%d=insertvalue [%d x i8] %s,i8 %%byte%d,%d\n",
				field, field*8, field, field, field, fixture.bits/8, packed, field, field)
			packed = fmt.Sprintf("%%pack%d", field)
		}
		left := "%left"
		if fixture.bits == 32 {
			wrappers.WriteString(" %left32=trunc i64 %left to i32\n")
			left = "%left32"
		}
		fmt.Fprintf(&wrappers, " call void @%s(ptr %%out,[%d x i8] %s,i%d %s)\n ret void\n}\n", fixture.name, fixture.bits/8, packed, fixture.bits, left)
		fmt.Fprintf(&declarations, "extern void check_%s(void*,uint64_t,uint64_t);\n", fixture.name)
		fmt.Fprintf(&checks, "if(check(check_%s,%d,%d,%d))return %d;\n", fixture.name, fixture.bits, fixture.predicate,
			x86FloatAddSubBoolInt(fixture.mask), index+1)
	}
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	const check = `
typedef void(*compare_fp)(void*,uint64_t,uint64_t);
static int check(compare_fp call,unsigned bits,unsigned predicate,unsigned mask_result){
 const uint64_t *edges=bits==32?edges32:edges64;
 unsigned saved;__asm__ volatile("stmxcsr %0":"=m"(saved));
 for(unsigned i=0;i<18;i++)for(unsigned j=0;j<18;j++)for(unsigned c=0;c<6;c++){
  uint8_t output[22],expected[20];memset(output,0xc3,sizeof(output));memset(expected,0,20);
  unsigned bytes=bits/8,csr=controls[c];
  int truth=independent_compare(bits,edges[i],edges[j],predicate,csr);
  if(mask_result){memset(expected+8,0xc3,8);expected[0]=(uint8_t)truth;}
  else memset(expected,truth?255:0,bytes);
  unsigned effect=original_effect(bits,edges[i],edges[j],predicate,csr);
  memcpy(expected+16,&effect,4);
  __asm__ volatile("ldmxcsr %0"::"m"(csr));
  call(output+1,edges[j],edges[i]);
  __asm__ volatile("ldmxcsr %0"::"m"(saved));
  if(output[0]!=0xc3||output[21]!=0xc3||memcmp(output+1,expected,20)){
   fprintf(stderr,"FP compare bits=%u pred=%u i=%u j=%u csr=%x mask=%u observed=%llx wanted=%llx\n",
    bits,predicate,i,j,csr,mask_result,(unsigned long long)read_bits(output+1,8),(unsigned long long)read_bits(expected,8));
   return 1;
  }
 }
 return 0;
}
`
	main := x86FloatCompareIndependentC + declarations.String() + check + "int main(void){\n" + checks.String() + "return 0;}\n"
	execution.compileAndRunLLVM(t, "compare-fp-scalar-bytes", ir+wrappers.String(), main, "-O2")
	t.Logf("%d scalar compare programs ISA-axis=%d, independently allocated 4/8 FP byte fields ×1944 inputs; actual transport=%v", len(fixtures), axis, execution.prefix)
}
