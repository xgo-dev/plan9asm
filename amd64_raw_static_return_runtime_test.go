package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// The Go oracle uses an ordinary declared result slot. It does not pretend
// that Go ABI0 returns a scalar in AX. The translated raw-RIP counterpart has
// the same fixed-width read and data, transported through its typed C result.
func runX86StaticReadNumericOracle(t *testing.T, arch, triple string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	values := []uint64{0, 1, 0x80000001, 0xffffffff, 0x89abcdef01234567, 0xfedcba9876543210}
	var raw, native, declarations, goMain, cMain strings.Builder
	goMain.WriteString("package main\nfunc main(){\n")
	cMain.WriteString("typedef unsigned int u32; typedef unsigned long long u64;\n")
	var cChecks strings.Builder
	cChecks.WriteString("int main(void){\n")
	sigs := make(map[string]FuncSig)
	count := 0
	for _, width := range []int{4, 8} {
		if arch == "386" && width == 8 {
			continue // The 386 scalar MOVQ spelling is not an integer GP read.
		}
		for index, value := range values {
			name := fmt.Sprintf("Read%d_%d", width, index)
			typ, goType, cType, move := I32, "uint32", "u32", "MOVL"
			if width == 8 {
				typ, goType, cType, move = I64, "uint64", "u64", "MOVQ"
			} else {
				value = uint64(uint32(value))
			}
			fmt.Fprintf(&declarations, "func %s()(r %s)\n", name, goType)
			fmt.Fprintf(&goMain, "if got:=%s(); got!=%s(0x%x){panic(\"%s\")}\n", name, goType, value, name)
			fmt.Fprintf(&cMain, "extern %s %s(void);\n", cType, name)
			fmt.Fprintf(&cChecks, "if(%s()!=0x%xULL)return %d;\n", name, value, count+1)
			fmt.Fprintf(&native, "DATA pool%d_%d<>+0(SB)/%d,$0x%x\nGLOBL pool%d_%d<>(SB),8,$%d\nTEXT ·%s(SB),4,$0-%d\n%s pool%d_%d<>(SB),AX\n%s AX,r+0(FP)\nBYTE $0xc3\n",
				width, index, width, value, width, index, width, name, width, move, width, index, move)
			if arch == "amd64" {
				code := []byte{0x8b, 0x05, 1, 0, 0, 0, 0xc3}
				if width == 8 {
					code = append([]byte{0x48}, code...)
				}
				data := make([]byte, 8)
				binary.LittleEndian.PutUint64(data, value)
				raw.WriteString(x86StaticReturnSource(name, append(code, data[:width]...)))
			} else {
				// Same-file DATA allocations are architecture-neutral. In 386
				// mode these are static absolute references, never RIP reads.
				fmt.Fprintf(&raw, "DATA pool%d_%d<>+0(SB)/%d,$0x%x\nTEXT %s(SB),4,$0-0\n%s pool%d_%d<>(SB),AX\nBYTE $0xc3\n",
					width, index, width, value, name, move, width, index)
			}
			sigs[name] = FuncSig{Name: name, Ret: typ}
			count++
		}
	}
	if arch == "amd64" {
		// A source-local LEA makes the pool mutable through its returned
		// address. The shared read proof must not resurrect specialization.
		declarations.WriteString("func Mutable()(p *uint64,v uint64)\n")
		native.WriteString("DATA mutable<>+0(SB)/8,$0x123456789abcdef\nGLOBL mutable<>(SB),16,$8\nTEXT ·Mutable(SB),4,$0-16\nLEAQ mutable<>(SB),AX\nMOVQ AX,p+0(FP)\nMOVQ mutable<>(SB),BX\nMOVQ BX,v+8(FP)\nBYTE $0xc3\n")
		goMain.WriteString("p,v:=Mutable();if p==nil||v!=0x123456789abcdef{panic(\"initial mutable\")}\n*p=0xfedcba9876543210\nq,v:=Mutable();if p!=q||v!=0xfedcba9876543210{panic(\"changed mutable\")}\n")
		code := []byte{
			0x48, 0x8d, 0x1d, 0x08, 0, 0, 0, // LEAQ pool,BX.
			0x48, 0x8b, 0x05, 0x01, 0, 0, 0, // MOVQ pool,AX.
			0xc3,
		}
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, 0x123456789abcdef)
		raw.WriteString(x86StaticReturnSource("Mutable", append(code, data...)))
		sigs["Mutable"] = FuncSig{Name: "Mutable", Ret: I64}
		cMain.WriteString("extern u64 Mutable(void); extern u64 MutablePool[];\n")
		cChecks.WriteString("if(Mutable()!=0x123456789abcdefULL)return 98;\nMutablePool[0]=0xfedcba9876543210ULL;\nif(Mutable()!=0xfedcba9876543210ULL)return 99;\n")
	}
	goMain.WriteString("}\n")
	cChecks.WriteString("return 0;}\n")
	cMain.WriteString(cChecks.String())
	goSource := strings.Replace(goMain.String(), "func main", declarations.String()+"func main", 1)
	project := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/static-read-oracle\ngo 1.20\n",
		"main.go": goSource, "read_" + arch + ".s": native.String(),
	} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(project, gotoolchain.HostExecutable("oracle"))
	cmd := exec.Command("go", "build", "-o", executable, ".")
	cmd.Dir = project
	goos := runtime.GOOS
	if len(runner) != 0 {
		goos = "linux"
	}
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0", "GOWORK=off", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual Go static-read oracle build: %v\n%s", err, output)
	}
	run := append(append([]string(nil), runner...), executable)
	if output, err := exec.Command(run[0], run[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("actual Go static-read oracle run: %v\n%s", err, output)
	}
	t.Logf("actual Go %s: %d ordinary static scalar result cases", arch, count)
	file := mustParseX86RawReturn(t, raw.String())
	opt := Options{Goarch: arch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string {
			if strings.HasPrefix(symbol, "·__plan9asm_raw_address_") {
				return "MutablePool"
			}
			return symbol
		}}
	for _, api := range []string{"text", "module", "owned-module"} {
		var ir string
		switch api {
		case "text":
			var err error
			ir, err = Translate(file, opt)
			if err != nil {
				t.Fatal(err)
			}
		case "module":
			module, err := TranslateModule(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			ir = module.String()
			module.Dispose()
		default:
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				ctx.Dispose()
				t.Fatal(err)
			}
			ir = module.String()
			module.Dispose()
			ctx.Dispose()
		}
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "static-read-"+api, triple, ir, cMain.String(), runner)
		t.Logf("LLVM 22 %s/%s: %d scalar cases", arch, api, count)
	}
}

func TestX86RawReturnStaticReadNumericOracle(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("host-inapplicable: x86 scalar oracle runs in the required Linux/amd64 cross-runtime gate")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	compiler := []string{clang, "-target", triple}
	if runtime.GOOS == "darwin" {
		output, err := exec.Command("xcrun", "--show-sdk-path").CombinedOutput()
		if err != nil {
			t.Fatalf("required Darwin SDK: %v\n%s", err, output)
		}
		compiler = append(compiler, "-isysroot", strings.TrimSpace(string(output)))
	}
	runX86StaticReadNumericOracle(t, "amd64", triple, compiler, nil)
}

func TestCrossLinuxRuntimeMatrixX86RawStaticRead(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		return // The explicit cross job runs this required counterpart.
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross static-read oracle requires Linux/amd64 runner")
	}
	qemu, err := exec.LookPath("qemu-i386")
	if err != nil {
		t.Fatal("required pinned qemu-i386:", err)
	}
	output, err := exec.Command(qemu, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "version 10.2.3") {
		t.Fatalf("required QEMU 10.2.3: %v\n%s", err, output)
	}
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal("required 386 cross compiler:", err)
	}
	runX86StaticReadNumericOracle(t, "386", "i386-unknown-linux-gnu", []string{compiler, "-no-pie"}, []string{qemu, "-L", "/usr/i686-linux-gnu"})
}
