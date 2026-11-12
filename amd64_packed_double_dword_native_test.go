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
	"strings"
	"testing"
)

func x86PackedDoubleDwordGoAssemblerSource(source string) string {
	// Preserve the original NOSPLIT spelling and let this actual driver's
	// original textflag.h define it, rather than silently rewriting TEXT.
	return fmt.Sprintf("#include %q\n", filepath.Join(runtime.GOROOT(), "pkg", "include", "textflag.h")) + source
}

const x86PackedDoubleDwordMaskPreflightC = `
#undef main
__attribute__((target("avx512f,avx512bw"))) static int original_mask64(void) {
    uint64_t input=0xa5,output;
    __asm__ volatile("kmovq %1,%%k1; kmovq %%k1,%0" : "=r"(output) : "r"(input) : "k1");
    return output==input;
}
static int mask64_required_state(unsigned bw) { return bw!=0; }
int main(void) {
    int failure=compare_preflight_main();
    if (failure) return failure;
    unsigned a,b,c,d,bw=0;
    if (__get_cpuid_count(7,0,&a,&b,&c,&d)) bw=(b>>30)&1;
    printf("original double/dword mask transport AVX512BW=%u\n",bw);
    fflush(stdout);
    if (!mask64_required_state(bw)) return 83;
    return original_mask64() ? 0 : 84;
}
`

func x86PackedDoubleDwordNativeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "mask-preflight.c"), filepath.Join(dir, "mask-preflight")
	program := "#define REQUIRED_AXIS 3\n#define main compare_preflight_main\n" + x86FloatCompareOpcodePreflightC + x86PackedDoubleDwordMaskPreflightC
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, binary)
	t.Logf("actual source KMOVQ preflight: %s", execution.run(t, binary))
	return execution
}

func TestX86PackedDoubleDwordNativeMaskPreflight(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "mask-capabilities.c"), filepath.Join(dir, "mask-capabilities")
	program := "#define REQUIRED_AXIS 3\n#define main compare_preflight_main\n" + x86FloatCompareOpcodePreflightC +
		strings.Replace(x86PackedDoubleDwordMaskPreflightC, "int main(void)", "int actual_mask_main(void)", 1) + `
int main(void) { return !mask64_required_state(1) || mask64_required_state(0); }
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, binary)
	execution.run(t, binary)
}

func TestX86PackedDoubleDwordRuntimeRequiresNativeUnion(t *testing.T) {
	full, local := x86PackedDoubleDwordOriginalAssembly(), x86PackedDoubleDwordSSEAssembly(t)
	for _, opcode := range []string{"VCVTDQ2PD (CX), K1, Z1", "VCVTTPD2DQY (BX), X2", "VCVTPD2DQ.RD_SAE.Z Z0, K1, Y3", "CVTPD2PL X4, X0"} {
		if strings.Count(full, opcode) != 1 {
			t.Fatal("lost or repeated original conversion", opcode)
		}
	}
	parsed, err := Parse(ArchAMD64, local)
	if err != nil {
		t.Fatal(err)
	}
	for _, instruction := range parsed.Funcs[0].Instrs {
		if strings.HasPrefix(string(instruction.Op), "V") || strings.HasPrefix(string(instruction.Op), "KMOV") {
			t.Fatal("portable SSE counterpart borrowed a wide opcode", instruction.Op)
		}
	}
	if strings.Count(local, "CVTPD2PL X4, X0") != 1 {
		t.Fatal("portable SSE counterpart borrowed a wide ISA or lost its original legacy conversion")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_packed_double_dword_native_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == "TestCrossLinuxRuntimeMatrixAMD64PackedDoubleDwordNativeAVX512" {
			body = fn.Body
		}
	}
	if body == nil || len(body.List) != 3 {
		t.Fatal("complete original Go and named/raw LLVM runtime must consume native transport")
	}
	for index, name := range []string{"x86PackedDoubleDwordNativeTools", "x86PackedDoubleDwordOriginalGo", "amd64PackedDoubleDwordRuntime"} {
		var call *ast.CallExpr
		if index == 0 {
			if assignment, ok := body.List[index].(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 {
				call, _ = assignment.Rhs[0].(*ast.CallExpr)
			}
		} else if statement, ok := body.List[index].(*ast.ExprStmt); ok {
			call, _ = statement.X.(*ast.CallExpr)
		}
		if call == nil {
			t.Fatal("required conversion consumer cannot skip or return", name)
		}
		callee, ok := call.Fun.(*ast.Ident)
		if !ok || callee.Name != name {
			t.Fatal("required conversion consumer missing", name)
		}
		if index > 0 {
			route, ok := call.Args[1].(*ast.Ident)
			if !ok || route.Name != "execution" {
				t.Fatal("conversion consumer lost its exact preflight route")
			}
		}
		if index == 2 {
			if len(call.Args) != 3 {
				t.Fatal("complete wide conversion execution was omitted")
			}
			wide, ok := call.Args[2].(*ast.Ident)
			if !ok || wide.Name != "true" {
				t.Fatal("complete wide conversion assertions cannot be disabled")
			}
		}
	}
}

func x86PackedDoubleDwordOriginalGo(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	if execution.triple != "x86_64-unknown-linux-gnu" || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("original packed double/dword requires actual native Linux AMD64")
	}
	dir := x86PackedDoubleDwordOriginalPackage(t)
	command := exec.Command("go", "test", "-p=2", "-count=1", "-run", "^TestOriginalDoubleDword$", "-v", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOARCH=amd64", "GOOS=linux")
	t.Logf("actual original Go named/raw double/dword: %s", x86FloatCompareCaptureCommand(t, command))
}

func TestX86PackedDoubleDwordCompleteOriginalGoCompiles(t *testing.T) {
	dir := x86PackedDoubleDwordOriginalPackage(t)
	command := exec.Command("go", "test", "-p=2", "-c", "-o", filepath.Join(dir, "original"), ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOARCH=amd64", "GOOS=linux")
	x86FloatCompareCaptureCommand(t, command)
}

func x86PackedDoubleDwordOriginalPackage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	named := strings.Replace(x86PackedDoubleDwordOriginalAssembly(), "packeddoubledword(SB)", "·named(SB)", 1)
	raw := strings.Replace(x86PackedDoubleDwordRawAssembly(x86PackedDoubleDwordOriginalAssembly()), "packeddoubledword(SB)", "·raw(SB)", 1)
	assembly := "#include \"textflag.h\"\n" + named + raw + "TEXT ·setCSR(SB),4,$0-4\nLDMXCSR csr+0(FP)\nRET\nTEXT ·getCSR(SB),4,$0-4\nSTMXCSR ret+0(FP)\nRET\n"
	for name, contents := range map[string]string{
		"go.mod": "module originaldoubledword\n\ngo 1.20\n", "original_amd64.s": assembly,
		"original_test.go": x86PackedDoubleDwordOriginalGoTest,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// This is output-only numerical evidence, not an MMX/x87 TAG/TOS identity
// claim. The original fixture's MM0 conversion remains unchanged.
const x86PackedDoubleDwordOriginalGoTest = `package original

import (
    "encoding/binary"
    "math"
    "runtime"
    "testing"
)

func named(out *[120]byte, doubles *[8]float64, dwords *[8]int32, old *[8]float64, mask uint64)
func raw(out *[120]byte, doubles *[8]float64, dwords *[8]int32, old *[8]float64, mask uint64)
func setCSR(csr uint32)
func getCSR() uint32

func TestOriginalDoubleDword(t *testing.T) {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    defer setCSR(getCSR())

    doubles := [8]float64{
        1.75, -2.75, 2147483648.0, math.Float64frombits(0x7ff8000000000000),
        -2147483648.0, -2147483649.0, 3.0, math.Float64frombits(0x8000000000000000),
    }
    dwords := [8]int32{0, 1, -1, 2147483647, -2147483648, 123456789, -987654321, 42}
    old := [8]float64{100.5, 101.5, 102.5, 103.5, 104.5, 105.5, 106.5, 107.5}
    truncated := [4]int32{1, -2, -2147483648, -2147483648}
    down := [8]int32{1, 0, -2147483648, 0, 0, -2147483648, 0, 0}

    for index, fn := range []func(*[120]byte, *[8]float64, *[8]int32, *[8]float64, uint64){named, raw} {
        var guarded [122]byte
        for i := range guarded {
            guarded[i] = 0xcc
        }
        setCSR(0x1f80)
        fn((*[120]byte)(guarded[1:121]), &doubles, &dwords, &old, 0xa5)
        output := guarded[1:121]
        if guarded[0] != 0xcc || guarded[121] != 0xcc {
            t.Fatal("original conversion output canary", index)
        }

        for i := 0; i < 8; i++ {
            want := old[i]
            if 0xa5&(1<<uint(i)) != 0 {
                want = float64(dwords[i])
            }
            if math.Float64frombits(binary.LittleEndian.Uint64(output[8*i:])) != want ||
                int32(binary.LittleEndian.Uint32(output[80+4*i:])) != down[i] {
                t.Fatalf("original named/raw %d lane %d: %x", index, i, output)
            }
        }
        for i := 0; i < 4; i++ {
            if int32(binary.LittleEndian.Uint32(output[64+4*i:])) != truncated[i] {
                t.Fatal("original truncation", index, i)
            }
        }
        if int32(binary.LittleEndian.Uint32(output[112:])) != 2 || int32(binary.LittleEndian.Uint32(output[116:])) != -3 {
            t.Fatal("original legacy conversion", index)
        }
    }
}
`
