package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type x86RawLEAAddressRuntimeForm struct {
	name                      string
	addressBits, width, shape int
	scale                     int
	alias                     bool
}

func x86RawLEAAddressRuntimeForms(arch string) []x86RawLEAAddressRuntimeForm {
	mode := 64
	if arch == "386" {
		mode = 32
	}
	var forms []x86RawLEAAddressRuntimeForm
	for _, addressBits := range []int{mode, mode / 2} {
		for _, width := range []int{16, 32, 64} {
			if width > mode {
				continue
			}
			for _, shape := range []int{0, 1, 2, 3} {
				if addressBits == 16 && shape != 0 {
					continue // The physical fixture here is BX+SI, not a SIB.
				}
				for scale := 0; scale < 4; scale++ {
					if (shape == 0 || shape == 3) && scale != 0 {
						continue
					}
					for _, alias := range []bool{false, true} {
						name := fmt.Sprintf("leaA%dW%dS%dC%d", addressBits, width, shape, scale)
						if alias {
							name += "Alias"
						}
						forms = append(forms, x86RawLEAAddressRuntimeForm{
							name: name, addressBits: addressBits, width: width,
							shape: shape, scale: scale, alias: alias,
						})
					}
				}
			}
		}
	}
	return forms
}

func x86RawLEAAddressRuntimeSources(arch string) (string, string, string, string, map[string]FuncSig) {
	mode, word, move, typ, ctype, cmax := 64, 8, "MOVQ", "uint64", "uint64_t", "UINT64_MAX"
	seed := uint64(0x1122334455667788)
	if arch == "386" {
		mode, word, move, typ, ctype, cmax = 32, 4, "MOVL", "uint32", "uint32_t", "UINT32_MAX"
		seed = 0x55667788
	}
	var declarations, assembly, goTest, c strings.Builder
	declarations.WriteString("package rawlea\n")
	fmt.Fprintf(&goTest, "package rawlea\nimport \"testing\"\nfunc TestPhysicalAddressMathematics(t *testing.T) {\n"+
		" values := []%s{0,1,63,64,65,65535,65536,1<<31-1,1<<31,1<<32-1,^%s(0)}\n", typ, typ)
	if mode == 64 {
		goTest.WriteString(" values = append(values,1<<32,1<<63,0x1122334455667788)\n")
	}
	c.WriteString("#include <stdint.h>\n#if defined(__APPLE__)\n#define LABEL(name) \"_\" name\n#else\n#define LABEL(name) name\n#endif\n")
	sigs := make(map[string]FuncSig)
	for _, form := range x86RawLEAAddressRuntimeForms(arch) {
		fmt.Fprintf(&declarations, "func %s(x %s) %s\n", form.name, typ, typ)
		encoding := x86RawLEADisplacementEncoding(mode, form.width, form.addressBits, form.shape, form.scale, -64)
		destination, initial := "CX", fmt.Sprintf("0x%x", seed)
		if form.alias {
			destination, initial = "AX", "x"
			register := byte(0)
			if form.addressBits == 16 {
				destination, register = "BX", 3
			}
			opcode := bytes.IndexByte(encoding, 0x8d)
			encoding[opcode+1] = encoding[opcode+1]&^0x38 | register<<3
		}
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),AX\n%s $3,BX\n%s $0x%x,CX\n",
			form.name, 2*word, move, move, move, seed)
		if form.addressBits == 16 {
			fmt.Fprintf(&assembly, "%s AX,BX\n%s $3,SI\n", move, move)
		}
		assembly.WriteString(x86RawDisplacementDirectives(encoding))
		fmt.Fprintf(&assembly, "%s %s,ret+%d(FP)\nRET\n", move, destination, word)
		sig := crossUnarySig(arch, "rawlea."+form.name)
		sigs[sig.Name] = sig

		// These two independent scalar oracles model effective-address width
		// first and destination width second, never decoded IR or GoSyntax.
		effective := "x - 64"
		if form.addressBits == 16 {
			effective = "x + 3 - 64"
		} else if form.shape == 1 {
			effective = fmt.Sprintf("x + 3*%d - 64", 1<<form.scale)
		} else if form.shape == 2 {
			effective = fmt.Sprintf("x*%d - 64", 1<<form.scale)
		} else if form.shape == 3 {
			effective = "^" + typ + "(63)"
		}
		fmt.Fprintf(&goTest, " for _, x := range values {\n  want := %s(%s)\n", typ, effective)
		if form.addressBits != mode {
			fmt.Fprintf(&goTest, "  want = %s(uint%d(want))\n", typ, form.addressBits)
		}
		if form.width == 16 {
			fmt.Fprintf(&goTest, "  want = %s(%s)&^%s(65535) | %s(uint16(want))\n", typ, initial, typ, typ)
		} else if form.width == 32 {
			fmt.Fprintf(&goTest, "  want = %s(uint32(want))\n", typ)
		}
		fmt.Fprintf(&goTest, "  if got := %s(x); got != want { t.Fatalf(\"%s x=%%#x got=%%#x want=%%#x\",x,got,want) }\n }\n", form.name, form.name)
		fmt.Fprintf(&c, "extern %s %s(%s) __asm__(LABEL(\"rawlea.%s\"));\n", ctype, form.name, ctype, form.name)
	}
	goTest.WriteString("}\n")
	fmt.Fprintf(&c, "int main(void) {\n const %s values[] = {0,1,63,64,65,65535,65536,UINT32_MAX/2,UINT32_MAX/2+1,UINT32_MAX,%s",
		ctype, cmax)
	if mode == 64 {
		c.WriteString(",UINT64_C(1)<<32,UINT64_C(1)<<63,UINT64_C(0x1122334455667788)")
	}
	c.WriteString("};\n")
	for _, form := range x86RawLEAAddressRuntimeForms(arch) {
		effective := "x - 64"
		if form.addressBits == 16 {
			effective = "x + 3 - 64"
		} else if form.shape == 1 {
			effective = fmt.Sprintf("x + 3*%d - 64", 1<<form.scale)
		} else if form.shape == 2 {
			effective = fmt.Sprintf("x*%d - 64", 1<<form.scale)
		} else if form.shape == 3 {
			effective = fmt.Sprintf("(%s)0 - 64", ctype)
		}
		fmt.Fprintf(&c, " for (unsigned i=0; i<sizeof(values)/sizeof(values[0]); i++) {\n  %s x=values[i], want=%s;\n", ctype, effective)
		if form.addressBits != mode {
			fmt.Fprintf(&c, "  want = (uint%d_t)want;\n", form.addressBits)
		}
		if form.width == 16 {
			initial := fmt.Sprintf("(%s)0x%x", ctype, seed)
			if form.alias {
				initial = "x"
			}
			fmt.Fprintf(&c, "  want = (%s & ~(%s)65535) | (uint16_t)want;\n", initial, ctype)
		} else if form.width == 32 {
			c.WriteString("  want = (uint32_t)want;\n")
		}
		fmt.Fprintf(&c, "  if (%s(x)!=want) return 1;\n }\n", form.name)
	}
	c.WriteString(" return 0;\n}\n")
	return declarations.String(), assembly.String(), goTest.String(), c.String(), sigs
}

func TestX86RawDisplacementLEAAllAddressWidthsAndAliasesFiveObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			_, source, _, _, sigs := x86RawLEAAddressRuntimeSources(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: sigs, ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "rawlea.", 1) }})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-lea-all-ea.ll", "raw-lea-all-ea.o", ir)
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86RawLEAAddressWidthAndAliases(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("raw LEA execution requires its mandatory Linux/amd64 counterpart")
	}
	testX86RawLEAAddressRuntime(t, "amd64")
}

func testX86RawLEAAddressRuntime(t *testing.T, arch string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	goSource, source, goTest, mainC, sigs := x86RawLEAAddressRuntimeSources(arch)
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":   "module rawlea\n\ngo 1.20\n",
		"value.go": goSource, "value_" + arch + ".s": source, "value_test.go": goTest,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := []string{"test", "-p=2", "-vet=off", "-count=1"}
	if arch == "386" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			t.Fatal("386 original/raw LEA execution requires the Linux cross driver")
		}
		args = append(args, "-exec", "qemu-i386 -L /usr/i686-linux-gnu")
	}
	command := exec.CommandContext(ctx, "go", append(args, ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go raw LEA address/alias mathematics: %v\n%s", err, output)
	}
	triple := testTargetTriple(runtime.GOOS, arch)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "rawlea.", 1) }})
	if err != nil {
		t.Fatal(err)
	}
	if arch == "386" {
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc", "-no-pie"},
			"raw_lea_addresses", triple, ir, mainC, []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
		return
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang required")
	}
	var prefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_lea_addresses", triple, ir, mainC, prefix)
}
