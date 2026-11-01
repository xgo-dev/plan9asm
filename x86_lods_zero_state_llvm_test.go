package plan9asm

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/llvm"
)

var x86LODSStateTargets sync.Once

// The observer loads a real target pointer from a machine-word output cell.
// Obtain that layout from the selected LLVM target, not the host or an assumed
// pointer width, before optimizing either architecture's complete module.
func x86LODSStateTargetLayout(t *testing.T, ir, triple string, word int) string {
	t.Helper()
	x86LODSStateTargets.Do(func() {
		llvm.InitializeAllTargetInfos()
		llvm.InitializeAllTargets()
		llvm.InitializeAllTargetMCs()
	})
	target, err := llvm.GetTargetFromTriple(triple)
	if err != nil {
		t.Fatal("LODS observer requires its actual LLVM target", err)
	}
	machine := target.CreateTargetMachine(triple, "", "", llvm.CodeGenLevelDefault,
		llvm.RelocDefault, llvm.CodeModelDefault)
	if machine.C == nil {
		t.Fatal("LODS observer target machine is missing", triple)
	}
	defer machine.Dispose()
	data := machine.CreateTargetData()
	defer data.Dispose()
	if data.PointerSize() != word {
		t.Fatal("LODS output cells do not match the actual target pointer", triple, data.PointerSize(), word)
	}
	if strings.Contains(ir, "target datalayout") {
		t.Fatal("LODS observer must not replace an existing module layout")
	}
	t.Logf("actual LLVM target %s pointer=%d datalayout=%q", triple, word, data.String())
	return fmt.Sprintf("target datalayout = %q\n", data.String()) + ir
}

// This test-only LLVM caller observes the actual translated void function's
// four output cells. Its fresh alloca is not an ASM frame/backing certificate.
// It compares the opaque source pointer by identity, never as numerical data.
func x86LODSZeroStateObserver(row x86LODSStateCase) string {
	typ := "i64"
	if row.arch == "386" {
		typ = "i32"
	}
	result := fmt.Sprintf("{ %s, i1, %s, %s }", typ, typ, typ)
	return fmt.Sprintf(`
define %s @observe_%s(ptr %%source) {
entry:
  %%out = alloca [4 x %s]
  call void @%s(ptr %%out, ptr %%source)
  %%si_cell = getelementptr [4 x %s], ptr %%out, i32 0, i32 1
  %%cx_cell = getelementptr [4 x %s], ptr %%out, i32 0, i32 2
  %%flags_cell = getelementptr [4 x %s], ptr %%out, i32 0, i32 3
  %%ax = load %s, ptr %%out
  %%si = load ptr, ptr %%si_cell
  %%same_si = icmp eq ptr %%si, %%source
  %%cx = load %s, ptr %%cx_cell
  %%flags = load %s, ptr %%flags_cell
  %%r0 = insertvalue %s undef, %s %%ax, 0
  %%r1 = insertvalue %s %%r0, i1 %%same_si, 1
  %%r2 = insertvalue %s %%r1, %s %%cx, 2
  %%r3 = insertvalue %s %%r2, %s %%flags, 3
  ret %s %%r3
}
`, result, row.name, typ, row.name, typ, typ, typ, typ, typ, typ,
		result, typ, result, result, typ, result, typ, result)
}

func TestX86LODSZeroCountOriginalGoAndLLVMWholeState(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete LODS state objects require LLVM22 llc")
	}
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86LODSStateFixture(arch)
		goAssemblerOracleOutput(t, arch, source, "", true)
		triple, word := "x86_64-unknown-linux-gnu", 8
		if arch == "386" {
			triple, word = "i386-unknown-linux-gnu", 4
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil {
					t.Fatal("complete original fixture did not reach its state observer", err)
				}
				for _, row := range x86LODSStateCases(arch) {
					if row.prefix != "" && row.count == 0 {
						ir += x86LODSZeroStateObserver(row)
					}
				}
				ir = x86LODSStateTargetLayout(t, ir, triple, word)
				optimized := x86UndefinedTrapOptimizedIR(t, ir)
				for _, row := range x86LODSStateCases(arch) {
					// Keep the complete original matrix in this same module. The
					// nonzero/bare cases are not silently replaced by zero cases.
					x86StringMemoryFunction(t, optimized, row.name)
					if row.prefix == "" || row.count != 0 {
						continue
					}
					body := x86StringMemoryFunction(t, optimized, "observe_"+row.name)
					if err := x86LODSCheckZeroOutputStores(body, row); err != nil {
						t.Errorf("zero count changed complete AX, source SI, CX or initialized FLAGS: %s/%s/count0/backward=%t\n%v\n%s",
							arch, row.op, row.backward, err, body)
					}
				}
				for _, stage := range []struct{ name, ir string }{{"ir0", ir}, {"ir2", optimized}} {
					for _, backend := range []string{"-O0", "-O2"} {
						t.Run(stage.name+"/backend"+backend[2:], func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, triple, stage.ir, backend)
						})
					}
				}
			})
		}
	}
}
