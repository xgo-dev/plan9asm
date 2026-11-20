package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86AddSubLiteralNumericalSource() (declarations, assembly string) {
	var goSource, machine strings.Builder
	for _, opcode := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
		for _, value := range x86AddSubLiteralValues {
			name := strings.ToLower(opcode) + value.name
			fmt.Fprintf(&goSource, "func %s(input *[32]byte, output *[80]byte, csr uint32)\n", name)
			fmt.Fprintf(&machine, `TEXT ·%s(SB),4,$8-20
STMXCSR saved-4(SP)
LDMXCSR csr+16(FP)
MOVQ input+0(FP),AX
MOVQ output+8(FP),BX
VMOVUPS (AX),Y0
%s $%s,X0
MOVUPS X0,8(BX)
VMOVUPS Y0,24(BX)
STMXCSR 56(BX)
LDMXCSR saved-4(SP)
RET
`, name, opcode, value.text)
		}
	}
	return goSource.String(), machine.String()
}

func x86AddSubLiteralCOracle() string {
	var declarations, checks strings.Builder
	index := 0
	for _, opcode := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
		bits := 32
		if strings.HasSuffix(opcode, "SD") {
			bits = 64
		}
		for _, value := range x86AddSubLiteralValues {
			literal := value.bits64
			if bits == 32 {
				literal = uint64(value.bits32)
			}
			name := strings.ToLower(opcode) + value.name
			fmt.Fprintf(&declarations, "extern void %s(void*,void*,unsigned);\n", name)
			fmt.Fprintf(&checks, "    if (check_literal(%s,%q,%d,UINT64_C(0x%x),%d)) return %d;\n", name, name, bits, literal, x86FloatAddSubBoolInt(strings.HasPrefix(opcode, "SUB")), index+1)
			index++
		}
	}
	return x86FloatAddSubSSEOracle + declarations.String() + `
typedef void (*literal_fn)(void*,void*,unsigned);
static int check_literal(literal_fn fn,const char *name,unsigned bits,uint64_t literal,int subtract) {
    const uint64_t edge32[]={0,0x80000000,1,0x80000001,0x3f800000,0xbf800000,
        0x7f7fffff,0x7f800000,0xff800000,0x7fc12345,0x7f812345};
    const uint64_t edge64[]={0,UINT64_C(0x8000000000000000),1,UINT64_C(0x8000000000000001),
        UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x7fefffffffffffff),
        UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),
        UINT64_C(0x7ff8123456789abc),UINT64_C(0x7ff0123456789abc)};
    const unsigned controls[]={0x1f80,0x1f85,0x1fc0,0x9f80,0x9fc0,0x3f80,0x5f80,0x7f80};
    for(unsigned sample=0;sample<11;sample++) {
        unsigned char input[32],before[32],output[80],want[80];
        for(unsigned byte=0;byte<32;byte++) input[byte]=(unsigned char)(byte*37+19);
        uint64_t left=bits==32?edge32[sample]:edge64[sample];
        memcpy(input,&left,bits/8);
        memcpy(before,input,32);
        for(unsigned mode=0;mode<8;mode++) {
            unsigned ambient=0x3f85,after;
            memset(output,0xa7,80);
            memset(want,0xa7,80);
            uint64_t result=sse_result(bits,left,literal,subtract,controls[mode]);
            unsigned expectedCSR=last_sse_csr;
            memcpy(want+8,input,16);
            memcpy(want+24,input,32);
            memcpy(want+8,&result,bits/8);
            memcpy(want+24,&result,bits/8);
            memcpy(want+56,&expectedCSR,4);
            __asm__ volatile("ldmxcsr %0"::"m"(ambient));
            fn(input,output,controls[mode]);
            __asm__ volatile("stmxcsr %0":"=m"(after));
            if(memcmp(input,before,32)||memcmp(output,want,80)||after!=ambient) {
                fprintf(stderr,"%s bits=%u sample=%u csr=%x after=%x\n",name,bits,sample,controls[mode],after);
                return 1;
            }
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + `
    unsigned csr=0x1f80;
    __asm__ volatile("ldmxcsr %0"::"m"(csr));
    return 0;
}
`
}

func TestCrossLinuxRuntimeMatrixX86FloatAddSubLiteralNumerical(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	declarations, assembly := x86AddSubLiteralNumericalSource()
	x86ScalarLiteralGoListing(t, "amd64", assembly)
	pkg := x86AddSubLiteralPackage(t, "amd64", declarations)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			var ir string
			var err error
			switch api {
			case "text":
				ir, err = Translate(file, options)
			case "module":
				var module llvm.Module
				module, err = TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
					ir = module.String()
				}
			case "GoModule":
				var translation *GoModuleTranslation
				translation, err = translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{GOARCH: "amd64", TargetTriple: triple, ResolveSym: resolve})
				if translation != nil && !translation.Module.IsNil() {
					defer translation.Module.Dispose()
					ir = translation.Module.String()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "addsub-literal-"+api, triple, ir, x86AddSubLiteralCOracle(), prefix)
		})
	}
	t.Log("56 original literal forms × 11 independent SSE bit inputs × 8 full MXCSR controls × 3 translation APIs; whole X/Y bytes and canaries")
}

func TestCrossLinuxRuntimeMatrixX86FloatAddSubLiteralOriginalGo(t *testing.T) {
	x86FloatAddSubRuntimeTools(t)
	declarations, assembly := x86AddSubLiteralNumericalSource()
	var checks strings.Builder
	for _, opcode := range []string{"ADDSS", "ADDSD", "SUBSS", "SUBSD"} {
		bits := 32
		if strings.HasSuffix(opcode, "SD") {
			bits = 64
		}
		for _, value := range x86AddSubLiteralValues {
			literal := value.bits64
			if bits == 32 {
				literal = uint64(value.bits32)
			}
			fmt.Fprintf(&checks, "    check(t,%s,%d,0x%x,%t)\n", strings.ToLower(opcode)+value.name, bits, literal, strings.HasPrefix(opcode, "SUB"))
		}
	}
	goTest := `package literal
import("encoding/binary";"math";"testing")
type literalFn func(*[32]byte,*[80]byte,uint32)
func check(t *testing.T,fn literalFn,bits int,literal uint64,subtract bool) {
    t.Helper()
    for _,negative:=range []bool{false,true} {
        var input [32]byte
        var output [80]byte
        for i:=range input {input[i]=byte(i*37+19)}
        for i:=range output {output[i]=0xa7}
        var result uint64
        if bits==32 {
            left:=float32(4)
            if negative {left=-left}
            binary.LittleEndian.PutUint32(input[:4],math.Float32bits(left))
            right:=math.Float32frombits(uint32(literal))
            if subtract {left-=right}else{left+=right}
            result=uint64(math.Float32bits(left))
        }else{
            left:=float64(4)
            if negative {left=-left}
            binary.LittleEndian.PutUint64(input[:8],math.Float64bits(left))
            right:=math.Float64frombits(literal)
            if subtract {left-=right}else{left+=right}
            result=math.Float64bits(left)
        }
        before:=input
        fn(&input,&output,0x1f80)
        if input!=before {t.Fatal("input changed")}
        for i,got:=range output {
            if i>=56&&i<60 {continue} // CSR is checked independently by the C SSE oracle.
            want:=byte(0xa7)
            if i>=8&&i<24 {want=input[i-8]}
            if i>=24&&i<56 {want=input[i-24]}
            if i>=8&&i<8+bits/8 {want=byte(result>>(8*(i-8)))}
            if i>=24&&i<24+bits/8 {want=byte(result>>(8*(i-24)))}
            if got!=want {t.Fatalf("bits=%d literal=%x byte=%d got=%x want=%x",bits,literal,i,got,want)}
        }
    }
}
func TestOriginalLiteralNumerical(t *testing.T) {
` + checks.String() + "}\n"
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module literal\n\ngo 1.20\n", "literal.go": "package literal\n" + declarations,
		"literal_amd64.s": assembly, "literal_test.go": goTest,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go original literal numerical: %v\n%s", err, output)
	}
	t.Log("actual Go original 56 literal kernels × 2 initialized finite inputs; X/Y aliases and whole output canaries (host execution may be Rosetta)")
}
