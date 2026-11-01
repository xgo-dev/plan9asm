package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This is exactly the subset deliberately excluded by the portable byte
// oracle: E6NF masked memory destinations execute a physical native opcode.
func x86InsertExtractMaskedMemoryRows() []string {
	var rows []string
	for _, row := range x86InsertExtractFormats() {
		if strings.HasPrefix(row, "VEXTRACT") && strings.Contains(row, "(BX)") && strings.Contains(row, "K1") {
			rows = append(rows, row)
		}
	}
	return rows
}

func x86InsertExtractMaskedMemoryAssembly() (string, map[string]FuncSig) {
	var assembly strings.Builder
	signatures := map[string]FuncSig{}
	for index, row := range x86InsertExtractMaskedMemoryRows() {
		name := fmt.Sprintf("masked%d", index)
		row = strings.Replace(row, "(BX)", "(AX)", 1)
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),R9\nKMOVQ R9,K1\nVMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nSTC\n%s\nSETCS 64(AX)\nRET\n", name, row)
		signatures[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
	}
	return assembly.String(), signatures
}

func x86InsertExtractMaskedMemoryShape(row string) (chunk, width, lane int) {
	chunk, width, lane = 16, 32, 4
	if strings.Contains(row, "32X8") || strings.Contains(row, "64X4") {
		chunk = 32
	}
	if strings.Contains(row, ",Z") {
		width = 64
	}
	if strings.Contains(row, "64X") {
		lane = 8
	}
	return
}

func TestX86InsertExtractMaskedMemoryRequiredInventory(t *testing.T) {
	rows := x86InsertExtractMaskedMemoryRows()
	if len(rows) != 12 || len(x86InsertExtractFormats()) != 148 {
		t.Fatalf("changed complete/native fixture denominator: %d/%d", len(x86InsertExtractFormats()), len(rows))
	}
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_insert_extract_native_runtime_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == "TestCrossLinuxRuntimeMatrixX86InsertExtractMaskedNativeMemory" {
			body = fn.Body
		}
	}
	if body == nil || len(body.List) != 1 {
		t.Fatal("all masked-memory extract cases require the native execution consumer")
	}
	statement, ok := body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("native extract counterpart cannot return or skip")
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		t.Fatal("native extract counterpart does not consume its full fixture")
	}
	callee, ok := call.Fun.(*ast.Ident)
	if !ok || callee.Name != "x86InsertExtractMaskedMemoryRuntime" {
		t.Fatal("native extract counterpart substituted another consumer")
	}
	assembly, signatures := x86InsertExtractMaskedMemoryAssembly()
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	parsed, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		ir, err := Translate(parsed, Options{Goarch: "amd64", TargetTriple: triple, Sigs: signatures})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "masked-extract.ll", "masked-extract.o", ir)
	}
	// The complete original Go oracle must compile even on a portable host;
	// only its required native counterpart may execute these AVX512 bytes.
	dir := x86InsertExtractMaskedOriginalPackage(t)
	command := exec.Command("go", "test", "-p=2", "-c", "-o", filepath.Join(dir, "original"), ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOARCH=amd64", "GOOS=linux")
	x86FloatCompareCaptureCommand(t, command)
	t.Log("148 original formats preserved: all 12 excluded native memory-mask cases now have stock Go objects, 3 LLVM target objects and a mandatory Linux AMD64 runtime counterpart (not executed here)")
}

// Intel Vol2 KMOVQ r64,k requires AVX512BW; the extract forms additionally
// require F/DQ/VL. Checking F alone cannot authorize this existing bridge.
const x86InsertExtractNativePreflightC = `
#undef main
__attribute__((target("avx512f,avx512dq,avx512bw,avx512vl")))
static int original_extract(void) {
    uint8_t input[64],output[34];
    for (unsigned i=0;i<64;i++) input[i]=(uint8_t)(i*13+0x27);
    for (unsigned i=0;i<34;i++) output[i]=0xc3;
    uint64_t mask=1;
    __asm__ volatile("vmovdqu64 (%0),%%zmm0; kmovq %1,%%k1; "
                     "vextracti32x8 $1,%%zmm0,(%2)%{%%k1%}"
                     :: "r"(input),"r"(mask),"r"(output+1) : "zmm0","k1","memory");
    for (unsigned i=0;i<34;i++) {
        uint8_t want=i>=1 && i<=4 ? input[31+i] : 0xc3;
        if (output[i]!=want) return 0;
    }
    return 1;
}
static int extract_required_state(unsigned dq,unsigned bw) { return dq && bw; }
int main(void) {
    int failure=compare_preflight_main();
    if (failure) return failure;
    unsigned a,b,c,d,dq=0,bw=0;
    if (__get_cpuid_count(7,0,&a,&b,&c,&d)) { dq=(b>>17)&1; bw=(b>>30)&1; }
    printf("masked extract AVX512DQ=%u AVX512BW=%u\n",dq,bw);
    fflush(stdout);
    if (!extract_required_state(dq,bw)) return 81;
    return original_extract() ? 0 : 82;
}
`

func x86InsertExtractMaskedMemoryRuntime(t *testing.T) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "extract-preflight.c"), filepath.Join(dir, "extract-preflight")
	program := "#define REQUIRED_AXIS 3\n#define main compare_preflight_main\n" + x86FloatCompareOpcodePreflightC + x86InsertExtractNativePreflightC
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, binary)
	t.Logf("original native extract preflight: %s", execution.run(t, binary))
	original := x86InsertExtractMaskedOriginalPackage(t)
	command := exec.Command("go", "test", "-p=2", "-count=1", "-run", "^TestOriginalMaskedExtract$", "-v", ".")
	command.Dir = original
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOARCH=amd64", "GOOS=linux")
	t.Logf("original Go native masked extract: %s", x86FloatCompareCaptureCommand(t, command))
	assembly, signatures := x86InsertExtractMaskedMemoryAssembly()
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: signatures})
	if err != nil {
		t.Fatal(err)
	}
	var declarations, calls strings.Builder
	for index, row := range x86InsertExtractMaskedMemoryRows() {
		chunk, width, lane := x86InsertExtractMaskedMemoryShape(row)
		fmt.Fprintf(&declarations, "extern void masked%d(void*,const void*,const void*,uint64_t);\n", index)
		fmt.Fprintf(&calls, "    if (check(masked%d,%d,%d,%d)) return %d;\n", index, chunk, width, lane, index+1)
	}
	execution.compileAndRunLLVM(t, "masked-native-extract", ir, x86InsertExtractMaskedMemoryC+declarations.String()+"int main(void) {\n"+calls.String()+"    return 0;\n}\n", "-O2")
	t.Log("all 12 native masked-memory extract programs x40 byte/MXCSR/CF/input-output-canary cases executed by original Go and translated LLVM")
}

func TestX86InsertExtractNativeOpcodePreflightContract(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "extract-capabilities.c"), filepath.Join(dir, "extract-capabilities")
	// Compile the actual original-opcode preflight, but execute only its exact
	// extra capability predicate here. Synthetic bits never permit ISA execution.
	program := "#define REQUIRED_AXIS 3\n#define main compare_preflight_main\n" + x86FloatCompareOpcodePreflightC +
		strings.Replace(x86InsertExtractNativePreflightC, "int main(void)", "int actual_extract_main(void)", 1) + `
int main(void) {
    if (!extract_required_state(1,1) || extract_required_state(0,1) ||
        extract_required_state(1,0) || extract_required_state(0,0)) return 1;
    return 0;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, binary)
	execution.run(t, binary)
}

func x86InsertExtractMaskedOriginalPackage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	assembly, _ := x86InsertExtractMaskedMemoryAssembly()
	assembly = strings.ReplaceAll(assembly, "TEXT masked", "TEXT ·masked")
	assembly += "TEXT ·setCSR(SB),4,$0-4\nLDMXCSR csr+0(FP)\nRET\nTEXT ·getCSR(SB),4,$0-4\nSTMXCSR ret+0(FP)\nRET\n"
	var declarations, cases strings.Builder
	for index, row := range x86InsertExtractMaskedMemoryRows() {
		chunk, width, lane := x86InsertExtractMaskedMemoryShape(row)
		fmt.Fprintf(&declarations, "func masked%d(out *[65]byte,a,b *[64]byte,mask uint64)\n", index)
		fmt.Fprintf(&cases, "        {masked%d,%d,%d,%d},\n", index, chunk, width, lane)
	}
	for name, contents := range map[string]string{
		"go.mod": "module nativemaskedextract\n\ngo 1.20\n", "original_amd64.s": assembly,
		"original_test.go": "package original\nimport (\"testing\"; \"runtime\")\n" + declarations.String() + "func setCSR(csr uint32)\nfunc getCSR() uint32\n" + strings.Replace(x86InsertExtractMaskedMemoryGo, "REQUIRED_CASES", cases.String(), 1),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const x86InsertExtractMaskedMemoryGo = `
func TestOriginalMaskedExtract(t *testing.T) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    defer setCSR(getCSR())
    cases:=[]struct{fn func(*[65]byte,*[64]byte,*[64]byte,uint64); chunk,width,lane int}{
REQUIRED_CASES
    }
    masks:=[]uint64{0,1,0xaaaaaaaaaaaaaaaa,0xffffffffffffffff,0xffff000000000000}
    for index,fixture:=range cases {
        for vector:=0;vector<8;vector++ {
            for _,mask:=range masks {
                var a,b,out [67]byte
                for i:=range a {
                    a[i]=0xa7
                    b[i]=0xb9
                    out[i]=0xc3
                }
                for i:=0;i<64;i++ {
                    a[i+1]=byte((i*31+vector*17)^0x81)
                    b[i+1]=byte((i*13+vector*29)^0x27)
                }
                aCopy,bCopy:=a,b
                want:=out
                offset:=(255&(fixture.width/fixture.chunk-1))*fixture.chunk
                for i:=0;i<fixture.chunk;i++ {
                    if mask&(uint64(1)<<uint(i/fixture.lane))!=0 {
                        want[i+1]=b[offset+i+1]
                    }
                }
                want[65]=1
                setCSR(0x9fc5)
                fixture.fn((*[65]byte)(out[1:66]),(*[64]byte)(a[1:65]),(*[64]byte)(b[1:65]),mask)
                if out!=want || a!=aCopy || b!=bCopy || getCSR()!=0x9fc5 {
                    t.Fatalf("original extract %d mask=%x out=%x want=%x",index,mask,out,want)
                }
            }
        }
    }
}
`

// The old reference's byte selection and five masks are preserved. A masked
// memory destination leaves inactive output bytes untouched (0xc3), unlike
// the old register-destination cases which merge their prior vector value.
const x86InsertExtractMaskedMemoryC = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef void(*transfer)(void*,const void*,const void*,uint64_t);
static int check(transfer fn,unsigned chunk,unsigned width,unsigned laneBytes) {
    const uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX,UINT64_C(0xffff000000000000)};
    for (unsigned vector=0;vector<8;vector++) {
        for (unsigned m=0;m<5;m++) {
            uint8_t as[67],bs[67],out[67],want[67],aCopy[67],bCopy[67];
            uint8_t *a=as+1,*b=bs+1;
            memset(as,0xa7,67); memset(bs,0xb9,67); memset(out,0xc3,67);
            for (unsigned i=0;i<64;i++) {
                a[i]=(i*31+vector*17)^0x81;
                b[i]=(i*13+vector*29)^0x27;
            }
            memcpy(aCopy,as,67); memcpy(bCopy,bs,67); memcpy(want,out,67);
            unsigned offset=(255&(width/chunk-1))*chunk;
            for (unsigned i=0;i<chunk;i++) {
                if (masks[m]&(UINT64_C(1)<<(i/laneBytes))) want[i+1]=b[offset+i];
            }
            want[65]=1;
            unsigned csr=0x9fc5,observed;
            __asm__ volatile("ldmxcsr %0"::"m"(csr));
            fn(out+1,a,b,masks[m]);
            __asm__ volatile("stmxcsr %0":"=m"(observed));
            if (memcmp(out,want,67)||memcmp(as,aCopy,67)||memcmp(bs,bCopy,67)||observed!=csr) {
                fprintf(stderr,"native extract chunk=%u width=%u lane=%u mask=%llx CSR=%x\n",chunk,width,laneBytes,(unsigned long long)masks[m],observed);
                return 1;
            }
        }
    }
    return 0;
}
`
