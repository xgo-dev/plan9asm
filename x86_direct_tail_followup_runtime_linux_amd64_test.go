//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86OfficialBranches(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, declarations := x86OfficialBackwardBranchProgram()
	const goMain = `
func main() {
    for _, value := range []uint32{BelowPC(), BelowLabel(), JumpPC(), JumpLabel(), CountLoop()} {
        if value != 3 {
            panic("incorrect backward branch")
        }
    }
    if SymbolOffset() != 37 || SymbolIndex() != 37 {
        panic("incorrect Go symbol entry")
    }
    fmt.Println("7 Go branch results")
}
`
	const cMain = `#include <stdint.h>
#include <stdio.h>

extern uint32_t BelowPC(void), BelowLabel(void), JumpPC(void), JumpLabel(void), CountLoop(void);
extern uint32_t SymbolOffset(void), SymbolIndex(void);

int main(void) {
    if (BelowPC() != 3 || BelowLabel() != 3 || JumpPC() != 3 ||
        JumpLabel() != 3 || CountLoop() != 3 || SymbolOffset() != 37 || SymbolIndex() != 37) {
        return 1;
    }
    puts("7 Go branch results");
    return 0;
}
`
	x86DirectTailCheckCallRuntime(t, "amd64", execution, source+x86OfficialSymbolJumpSource,
		declarations+x86OfficialSymbolJumpDeclarations, goMain, cMain, "7 Go branch results\n")
	t.Run("ADJSP", func(t *testing.T) {
		x86ADJSPCarryRuntime(t, "amd64", execution)
		x86ADJSPVectorCopyRuntime(t, "amd64", execution)
	})
}

func TestCrossLinuxRuntimeMatrixX86Official386CarryAndFrame(t *testing.T) {
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatal("386 carry/frame owner needs LLVM 22 llc and the i686 compiler", err)
	}
	qemu, err := exec.LookPath("qemu-i386")
	if err != nil {
		t.Fatal("386 carry/frame owner needs pinned qemu-i386", err)
	}
	identity, err := runtimeOracleGuestRunnerSHA(qemu)
	if err != nil || identity != runtimeOraclePinnedQEMUSHA("qemu-i386") {
		t.Fatal("386 carry/frame owner could not authenticate qemu-i386", identity, err)
	}
	execution := x86FloatCompareExecution{
		llc: llc, triple: "i386-unknown-linux-gnu", compiler: []string{compiler, "-static", "-no-pie"},
		prefix: []string{qemu, "-cpu", "max"}, preserveArgv0: true,
	}
	const goMain = `
func main() {
    for _, test := range [][2]uint32{{0, 1}, {17, 18}, {0xfffffffe, 0xffffffff}, {0xffffffff, 1}} {
        if CarryLabel(test[0]) != test[1] || CarryPC(test[0]) != test[1] {
            panic("incorrect 386 carry branch")
        }
    }
    if InsertFrameLane(17, 0x80706050) != 0x80706050 || InsertFrameLane(0x80706050, 17) != 17 {
        panic("incorrect 386 frame lane")
    }
    fmt.Println("10 Go 386 results")
}
`
	const cMain = `#include <stdint.h>
#include <stdio.h>

extern uint32_t CarryLabel(uint32_t), CarryPC(uint32_t);
extern uint32_t InsertFrameLane(uint32_t, uint32_t);

int main(void) {
    const uint32_t tests[][2] = {{0, 1}, {17, 18}, {0xfffffffe, 0xffffffff}, {0xffffffff, 1}};
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (CarryLabel(tests[i][0]) != tests[i][1] || CarryPC(tests[i][0]) != tests[i][1]) {
            return 1;
        }
    }
    if (InsertFrameLane(17, 0x80706050) != 0x80706050 || InsertFrameLane(0x80706050, 17) != 17) {
        return 2;
    }
    puts("10 Go 386 results");
    return 0;
}
`
	x86DirectTailCheckCallRuntime(t, "386", execution, x86Official386ContextSource,
		x86Official386ContextDeclarations, goMain, cMain, "10 Go 386 results\n")
	t.Run("ADJSP", func(t *testing.T) {
		x86ADJSPCarryRuntime(t, "386", execution)
		x86ADJSPVectorCopyRuntime(t, "386", execution)
	})
}

func x86ADJSPCarryRuntime(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	flags, value, memory, named := x86ADJSPMixedStackSources(arch)
	source := x86ADJSPCarrySource("BelowBoundary", 127) + x86ADJSPCarrySource("AtBoundary", 128) +
		x86ADJSPCarrySource("AboveBoundary", 129) + x86ADJSPLogicalFrameSource("Framed", arch) +
		x86ADJSPPhysicalScratchSource("Scratch") + strings.Replace(flags, "·Value(SB)", "·MixedFlags(SB)", 1) +
		strings.Replace(value, "·Value(SB)", "·MixedValue(SB)", 1) +
		strings.Replace(memory, "·Value(SB)", "·MixedMemory(SB)", 1) +
		strings.Replace(named, "·Value(SB)", "·MixedNamed(SB)", 1)
	const declarations = "func BelowBoundary() uint32\nfunc AtBoundary() uint32\nfunc AboveBoundary() uint32\n" +
		"func Framed(value uint32) uint32\nfunc Scratch() uint32\n" +
		"func MixedFlags() uint32\nfunc MixedValue() uint32\nfunc MixedMemory() uint32\nfunc MixedNamed() uint32\n"
	const goMain = `
func main() {
    if BelowBoundary() != 0 || AtBoundary() != 3 || AboveBoundary() != 0 || Framed(41) != 42 || Framed(0xffffffff) != 0 || Scratch() != 7 {
        panic("incorrect carry on a stack adjustment")
    }
    if MixedFlags() != 2 || MixedValue() != 7 || MixedMemory() != 7 || MixedNamed() != 7 {
        panic("incorrect mixed stack transfer")
    }
    fmt.Println("ADJSP carry 0 3 0, frame 42 0, scratch 7, mixed 2 7 7 7")
}
`
	const cMain = `#include <stdint.h>
#include <stdio.h>

extern uint32_t BelowBoundary(void), AtBoundary(void), AboveBoundary(void);
extern uint32_t Framed(uint32_t);
extern uint32_t Scratch(void);
extern uint32_t MixedFlags(void), MixedValue(void), MixedMemory(void), MixedNamed(void);

int main(void) {
    if (BelowBoundary() != 0 || AtBoundary() != 3 || AboveBoundary() != 0 || Framed(41) != 42 || Framed(0xffffffff) != 0 || Scratch() != 7) {
        return 1;
    }
    if (MixedFlags() != 2 || MixedValue() != 7 || MixedMemory() != 7 || MixedNamed() != 7) {
        return 2;
    }
    puts("ADJSP carry 0 3 0, frame 42 0, scratch 7, mixed 2 7 7 7");
    return 0;
}
`
	x86DirectTailCheckCallRuntime(t, arch, execution, source, declarations, goMain, cMain,
		"ADJSP carry 0 3 0, frame 42 0, scratch 7, mixed 2 7 7 7\n")
}

func x86ADJSPVectorCopyRuntime(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	var source, declarations, goChecks, cDeclarations, cChecks strings.Builder
	for index, row := range x86ADJSPVectorCopyCases() {
		name := fmt.Sprintf("Copy%d", index)
		source.WriteString(row.source(name))
		fmt.Fprintf(&declarations, "func %s() uint64\n", name)
		fmt.Fprintf(&cDeclarations, "extern uint64_t %s(void);\n", name)
		if !strings.HasPrefix(row.opcode, "V") {
			// Original Go execution on the ordinary x86 runners uses SSE2.
			// The independent native AVX512 suite owns original EVEX execution.
			fmt.Fprintf(&goChecks, "if %s() != %#x { panic(%q) }\n", name, row.want(), row.opcode)
		}
		fmt.Fprintf(&cChecks, "if (%s() != UINT64_C(%#x)) { fprintf(stderr, %q); return 1; }\n",
			name, row.want(), fmt.Sprintf("%s %s %s\n", row.opcode, row.register, row.mode))
	}
	const message = "ADJSP vector copies match"
	goMain := "func main() {\n" + goChecks.String() + "fmt.Println(\"" + message + "\")\n}\n"
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() +
		"int main(void) {\n" + cChecks.String() + "puts(\"" + message + "\");\nreturn 0;\n}\n"
	x86DirectTailCheckCallRuntime(t, arch, execution, source.String(), declarations.String(), goMain, cMain, message+"\n")
}

// The Linux AMD64 owner must execute both native ISA modes. Other hosts retain
// portable objects and source checks; no missing compiler/ISA counts as a pass.
func TestCrossLinuxRuntimeMatrixX86DirectTailPCResultAliasesAndExternal(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			goType, cType, values := "uint64", "uint64_t", "0,1,7,0x80000000,0xffffffff,0xffffffffffffffff"
			triple, compiler := "x86_64-unknown-linux-gnu", []string{clang, "-target", "x86_64-unknown-linux-gnu"}
			checks := 24
			if arch == "386" {
				goType, cType, values = "uint32", "uint32_t", "0,1,7,0x80000000,0xffffffff"
				triple = "i386-unknown-linux-gnu"
				cross, err := exec.LookPath("i686-linux-gnu-gcc")
				if err != nil {
					t.Fatal("native i386 owner requires the static cross compiler", err)
				}
				compiler, checks = []string{cross, "-static", "-no-pie"}, 20
			}
			execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
			source, declarations := x86DirectTailFollowupFixture(arch)
			declarations = strings.Replace(declarations, "func ordinary(a "+goType+") "+goType+"\n",
				"func ordinary(a "+goType+") "+goType+" {return a*3+11}\n", 1)
			goDriver := fmt.Sprintf(`package main
import "fmt"
%s
//go:noinline
func snapshot(p *[2]uint64) [2]uint64 {return *p}
func main() {
 values:=[]%s{%s}
 canaries:=[2]uint64{0x1122334455667788,0xaabbccddeeff0099}
 before:=snapshot(&canaries)
 for _,a:=range values {
  forward:=a*3+11; if a==0 {forward=7}
  b:=a^%s(0x87654321)
  n:=(a&7)+1
  got:=[]%s{Forward(a),Address(a),Alternate(a,b),Backward(n)}
  want:=[]%s{forward,a+7,a+b+7,n+7}
  for i:=range got {if got[i]!=want[i] {panic(fmt.Sprintf("case %%d got %%x want %%x",i,got[i],want[i]))}}
  if snapshot(&canaries)!=before {panic("original caller canary changed")}
 }
 fmt.Println("direct-tail followup: %d checks")
}
`, declarations, goType, values, goType, goType, goType, checks)
			dir := t.TempDir()
			for name, contents := range map[string]string{"go.mod": "module directfollowup\n\ngo 1.20\n", "main.go": goDriver, "tail_" + arch + ".s": source} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			original := filepath.Join(dir, "original")
			command := exec.Command("go", "build", "-p=1", "-o", original, ".")
			command.Dir = dir
			command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
			x86FloatCompareCaptureCommand(t, command)
			want := fmt.Sprintf("direct-tail followup: %d checks\n", checks)
			if output := execution.run(t, original); string(output) != want {
				t.Fatalf("incomplete original Go: %s", output)
			}
			cDriver := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
typedef %s U;
extern U Forward(U),Address(U),Alternate(U,U),Backward(U);
U ordinary(U a) {return a*3+11;}
int main(void) {
 const U values[]={%s};
 volatile uint64_t canaries[]={UINT64_C(0x1122334455667788),UINT64_C(0xaabbccddeeff0099)};
 for(unsigned v=0;v<sizeof(values)/sizeof(values[0]);v++) {
  U a=values[v], b=a^(U)0x87654321, n=(a&7)+1;
  U actual[]={Forward(a),Address(a),Alternate(a,b),Backward(n)};
  U reference[]={a==0?7:a*3+11,a+7,a+b+7,n+7};
  for(unsigned i=0;i<4;i++) if(actual[i]!=reference[i]) {fprintf(stderr,"case %%u got %%llx want %%llx\n",i,(unsigned long long)actual[i],(unsigned long long)reference[i]);return 1;}
  if(canaries[0]!=UINT64_C(0x1122334455667788)||canaries[1]!=UINT64_C(0xaabbccddeeff0099)) return 1;
 }
 puts("direct-tail followup: %d checks");
 return 0;
}
`, cType, values, checks)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					if output := execution.compileAndRunLLVM(t, "direct-tail-followup", ir, cDriver, level); string(output) != want {
						t.Fatalf("%s/%s incomplete LLVM: %s", api, level, output)
					}
					t.Log(api, level, strings.TrimSpace(want))
				}
			}
			t.Run("InteriorByteEntry", func(t *testing.T) {
				x86DirectTailInteriorCallRuntime(t, arch, execution)
			})
			t.Run("NamedByteEntry", func(t *testing.T) {
				x86DirectTailNamedInteriorCallRuntime(t, arch, execution)
			})
			t.Run("OfficialPCBranches", func(t *testing.T) {
				x86OfficialPCBranchRuntime(t, arch, execution)
			})
		})
	}
}

func x86OfficialPCBranchRuntime(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	source, declarations, names, _ := x86OfficialPCBranchSource(t, arch)
	var goChecks, cDeclarations, cChecks strings.Builder
	for _, name := range names {
		fmt.Fprintf(&goChecks, "if %s(0) != 19 || %s(^uint32(0)) != 11 { panic(%q) }\n", name, name, name)
		fmt.Fprintf(&cDeclarations, "extern uint32_t %s(uint32_t);\n", name)
		fmt.Fprintf(&cChecks, "if (%s(0) != 19 || %s(UINT32_MAX) != 11) return 1;\n", name, name)
	}
	message := fmt.Sprintf("official branches: %d taken and %d fallthrough paths", len(names), len(names))
	goMain := "func main() {\n" + goChecks.String() + fmt.Sprintf("fmt.Println(%q)\n}\n", message)
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() +
		"int main(void) {\n" + cChecks.String() + fmt.Sprintf("puts(%q);\nreturn 0;\n}\n", message)
	x86DirectTailCheckCallRuntime(t, arch, execution, source, declarations, goMain, cMain, message+"\n")
}

func x86DirectTailInteriorCallRuntime(t *testing.T, arch string, execution x86FloatCompareExecution) {
	source, declarations := x86DirectTailInteriorCallFixture()
	const goMain = `
func main() {
 if Entry() != 11 || Interior() != 73 || Grouped() != 73 || Starred() != 73 {
  panic("incorrect original byte entry")
 }
 fmt.Println("four byte entries passed")
}
`
	const cMain = `#include <stdint.h>
#include <stdio.h>
extern uint32_t Entry(void), Interior(void), Grouped(void), Starred(void);
int main(void) {
 if (Entry() != 11 || Interior() != 73 || Grouped() != 73 || Starred() != 73) return 1;
 puts("four byte entries passed");
 return 0;
}
`
	x86DirectTailCheckCallRuntime(t, arch, execution, source, declarations, goMain, cMain, "four byte entries passed\n")
}

func x86DirectTailNamedInteriorCallRuntime(t *testing.T, arch string, execution x86FloatCompareExecution) {
	const goMain = `
func main() {
 Target()
 for _, value := range []uint32{0, 1, 3, 0x80000000, 0xffffffff} {
  if got := Interior(value); got != value+73 {
   panic(fmt.Sprintf("byte entry with AX=%#x: got %#x", value, got))
  }
 }
 fmt.Println("ordinary entry and five interior inputs passed")
}
`
	const cMain = `#include <stdint.h>
#include <stdio.h>
extern void Target(void);
extern uint32_t Interior(uint32_t);
int main(void) {
 const uint32_t values[] = {0, 1, 3, 0x80000000, 0xffffffff};
 Target();
 for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
  if (Interior(values[i]) != values[i] + 73u) return 1;
 }
 puts("ordinary entry and five interior inputs passed");
 return 0;
}
`
	for _, frame := range []struct {
		name  string
		flags int
	}{
		{"explicit-frameless", 516},
		{"implicit-frameless", 4},
	} {
		t.Run(frame.name, func(t *testing.T) {
			source, declarations := x86DirectTailNamedInteriorCallFixture(arch, "·Target", frame.flags)
			x86DirectTailCheckCallRuntime(t, arch, execution, source, declarations, goMain, cMain, "ordinary entry and five interior inputs passed\n")
		})
	}
}

func x86DirectTailCheckCallRuntime(t *testing.T, arch string, execution x86FloatCompareExecution,
	source, declarations, goMain, cMain, want string, goImports ...string) {
	t.Helper()
	dir := t.TempDir()
	header := "package main\nimport \"fmt\"\n"
	for _, path := range goImports {
		header += fmt.Sprintf("import %q\n", path)
	}
	files := map[string]string{
		"go.mod":                 "module privateentries\n\ngo 1.20\n",
		"main.go":                header + declarations + goMain,
		"entries_" + arch + ".s": source,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original")
	command := exec.Command("go", "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	x86FloatCompareCaptureCommand(t, command)
	if output := execution.run(t, original); string(output) != want {
		t.Fatalf("incomplete original Go: %s", output)
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			if output := execution.compileAndRunLLVM(t, "call-entries", ir, cMain, level); string(output) != want {
				t.Fatalf("%s/%s incomplete LLVM: %s", api, level, output)
			}
		}
	}
}
