package plan9asm

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86SignedIntegerFloatFPFixture(t *testing.T) (string, string, map[string]FuncSig) {
	t.Helper()
	var declarations, assembly strings.Builder
	declarations.WriteString("package oracle\n")
	for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
		name := strings.ToLower(op)
		fmt.Fprintf(&declarations, "func %s(a,b,c,d,e,f,g,h byte,csr uint32)(value uint64,flags uint32)\n", name)
		args := "a+0(FP),X0"
		if strings.HasPrefix(op, "V") {
			args = "a+0(FP),X0,X1"
		}
		destination := "X0"
		if strings.HasPrefix(op, "V") {
			destination = "X1"
		}
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-28\nSTMXCSR saved-4(SP)\nLDMXCSR csr+8(FP)\n%s %s\nMOVQ %s,AX\n", name, op, args, destination)
		if strings.Contains(op, "SS") {
			assembly.WriteString("MOVL AX,AX\n")
		}
		assembly.WriteString("MOVQ AX,value+16(FP)\nSTMXCSR flags+24(FP)\nLDMXCSR saved-4(SP)\nRET\n")
	}
	source := assembly.String()
	pkg := mustGoPackage(t, "oracle", declarations.String())
	sigs := map[string]FuncSig{}
	for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
		name := strings.ToLower(op)
		decl := pkg.Types.Scope().Lookup(name).(*types.Func)
		sig, err := DeriveGoFuncABI0Signature(name, decl, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig.Frame.Params) != 9 || sig.Frame.Results[0].Offset != 16 || sig.Frame.Results[1].Offset != 24 {
			t.Fatalf("actual ABI0 parameter/result fields changed: %+v", sig.Frame)
		}
		sigs[name] = sig
	}
	return declarations.String(), source, sigs
}

func TestCrossLinuxRuntimeMatrixX86SignedIntegerScalarFloatOriginalGoRCAndFPFields(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	declarations, assembly, _ := x86SignedIntegerFloatFPFixture(t)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	var checks strings.Builder
	for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
		sourceBits := 32
		if strings.Contains(op, "Q") {
			sourceBits = 64
		}
		resultBits := 32
		if strings.Contains(op, "SD") {
			resultBits = 64
		}
		fmt.Fprintf(&checks, `for _,input:=range inputs { for mode:=0;mode<4;mode++ { for _,control:=range controls {
 csr:=control|uint32(mode)<<13
 got,flags:=%s(byte(input),byte(input>>8),byte(input>>16),byte(input>>24),byte(input>>32),byte(input>>40),byte(input>>48),byte(input>>56),csr)
 want,inexact:=rounded(input,%d,%d,mode);expectedFlags:=csr;if inexact{expectedFlags|=32}
 if got!=want||flags!=expectedFlags{t.Fatalf("%s input=%%x mode=%%d got=%%x want=%%x csr=%%x want=%%x",input,mode,got,want,flags,expectedFlags)}
 } } }
`, strings.ToLower(op), sourceBits, resultBits, op)
	}
	const reference = `package oracle
import("testing";"math";"math/big")
func rounded(input uint64,sourceBits,resultBits,mode int)(uint64,bool){
 value:=int64(input);if sourceBits==32{value=int64(int32(input))}
 precision:=uint(24);if resultBits==64{precision=53}
 modes:=[]big.RoundingMode{big.ToNearestEven,big.ToNegativeInf,big.ToPositiveInf,big.ToZero}
 exact:=new(big.Int).SetInt64(value)
 rounded:=new(big.Float).SetMode(modes[mode]).SetPrec(precision).SetInt(exact)
 f,_:=rounded.Float64();bits:=math.Float64bits(f);if resultBits==32{bits=uint64(math.Float32bits(float32(f)))}
 return bits,rounded.Acc()!=big.Exact
}
func TestActualGoSignedRCAndFP(t *testing.T){
 inputs:=[]uint64{0,1,0xffffffffffffffff,0x80000000,0x7fffffff,0xffffffff80000000,0x8000000000000000,0x7fffffffffffffff,0x1000001,0xfffffffffeffffff,0x20000000000001,0xffdfffffffffffff,0x100000001}
 for i:=uint64(0);i<256;i++{inputs=append(inputs,0xd31733a6287fbbc3*i+0x92c481352)}
 controls:=[]uint32{0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0}
`
	test := reference + checks.String() + "}\n"
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n", "oracle.go": declarations, "oracle_amd64.s": assembly, "oracle_test.go": test} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original Go signed conversion/RC/FP fields: %v\n%s", err, output)
	}
	t.Log("8 actual original Go opcodes x269 signed inputs x4 RC x6 DAZ/FTZ/sticky controls; genuine derived ABI0 FP fields")
}

func TestCrossLinuxRuntimeMatrixX86SignedIntegerScalarFloatTranslatedFPFields(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	_, source, sigs := x86SignedIntegerFloatFPFixture(t)
	// The normal callable implementation has no incoming hidden native ABI.
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	var declarations, checks, wrappers strings.Builder
	for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
		sourceBits, resultBits := 32, 32
		if strings.Contains(op, "Q") {
			sourceBits = 64
		}
		if strings.Contains(op, "SD") {
			resultBits = 64
		}
		name := strings.ToLower(op)
		// LLVM's logical multi-result aggregate is not C's struct-return
		// ABI (notably Win64's hidden sret pointer). Keep that call entirely
		// inside LLVM, crossing into C only through scalar/pointer arguments.
		fmt.Fprintf(&declarations, "extern void observe_%s(uint64_t*,uint32_t*,uint64_t,uint32_t);\n", name)
		fmt.Fprintf(&wrappers, "define void @observe_%s(ptr %%value, ptr %%flags, i64 %%input, i32 %%csr) {\nentry:\n", name)
		var arguments []string
		for index := 0; index < 8; index++ {
			fmt.Fprintf(&wrappers, "  %%shift%d = lshr i64 %%input, %d\n", index, index*8)
			fmt.Fprintf(&wrappers, "  %%byte%d = trunc i64 %%shift%d to i8\n", index, index)
			arguments = append(arguments, fmt.Sprintf("i8 %%byte%d", index))
		}
		arguments = append(arguments, "i32 %csr")
		fmt.Fprintf(&wrappers, "  %%result = call {i64, i32} @%s(%s)\n", name, strings.Join(arguments, ", "))
		wrappers.WriteString(`  %v = extractvalue {i64, i32} %result, 0
  %f = extractvalue {i64, i32} %result, 1
  store i64 %v, ptr %value
  store i32 %f, ptr %flags
  ret void
}
`)
		fmt.Fprintf(&checks, `for(unsigned sample=0;sample<256;sample++)for(unsigned mode=0;mode<4;mode++){
 uint64_t input=UINT64_C(0xd31733a6287fbbc3)*sample+UINT64_C(0x1000001);unsigned csr=0x9fc5|(mode<<13),before,after;
 __asm__ volatile("stmxcsr %%0":"=m"(before));
 uint64_t want=sse_convert(input,%d,%d,csr);unsigned wantCSR=sse_csr;
 struct {uint64_t before,value,after;} result={UINT64_C(0x123456789abcdef),0,UINT64_C(0xfedcba987654321)};
 struct {uint32_t before,value,after;} flags={0x12345678,0,0x87654321};
 observe_%s(&result.value,&flags.value,input,csr);
 __asm__ volatile("stmxcsr %%0":"=m"(after));
 if(result.before!=UINT64_C(0x123456789abcdef)||result.after!=UINT64_C(0xfedcba987654321)||flags.before!=0x12345678||flags.after!=0x87654321)return 2;
 if(result.value!=want||flags.value!=wantCSR||after!=before){fprintf(stderr,"FP %s input=%%llx got=%%llx want=%%llx flags=%%x want=%%x after=%%x before=%%x\n",(unsigned long long)input,(unsigned long long)result.value,(unsigned long long)want,flags.value,wantCSR,after,before);return 1;}
}
`, sourceBits, resultBits, name, name)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "signed-conversion-fp", triple, x86SignedIntegerFloatOptimize(t, ir+wrappers.String()), x86SignedIntegerFloatSSEOracle+declarations.String()+"int main(void){"+checks.String()+"return 0;}\n", prefix)
}

func TestX86SignedIntegerScalarFloatMode32PreservesNativeMXCSRInstruction(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc/objdump required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		const source = "TEXT f(SB),4,$0-16\nCVTSL2SS integer+0(FP),X0\nCVTSL2SD integer+0(FP),X1\nVCVTSI2SSL integer+0(FP),X2,X3\nVCVTSI2SDL integer+0(FP),X2,X3\nVCVTSI2SSQ integer+0(FP),X2,X3\nVCVTSI2SDQ integer+0(FP),X2,X3\nMOVSS X0,single+4(FP)\nMOVSD X1,double+8(FP)\nRET\n"
		goAssemblerOracleOutput(t, "386", source, "", true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		pkg := mustGoPackage(t, "oracle", "package oracle\nfunc f(integer int32)(single float32,double float64)\n")
		sig, err := DeriveGoFuncABI0Signature("f", pkg.Types.Scope().Lookup("f").(*types.Func), "386", types.SizesFor("gc", "386"))
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"f": sig}})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		input, object := filepath.Join(dir, "conversion.ll"), filepath.Join(dir, "conversion.o")
		if err := os.WriteFile(input, []byte(x86SignedIntegerFloatOptimize(t, ir)), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, llc, "-mtriple="+triple, "-filetype=obj", input, "-o", object)
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("mode32 object: %v\n%s", err, output)
		}
		ctx, cancel = runtimeOracleStageContext(t)
		command = exec.CommandContext(ctx, objdump, "-d", object)
		output, err = runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("mode32 native decode: %v\n%s", err, output)
		}
		if strings.Count(string(output), "cvtsi2ss") != 3 || strings.Count(string(output), "cvtsi2sd") != 3 || strings.Contains(string(output), "fild") {
			t.Fatalf("%s lost source SSE/MXCSR conversion to x87:\n%s", triple, output)
		}
		t.Logf("%s: original Go accepted all six mode32 default forms; optimized native object retains three signed32 SSE conversions per result width, no x87", triple)
	}
}
