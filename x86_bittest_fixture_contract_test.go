package plan9asm

import (
	"errors"
	"testing"
)

// The legacy composite fixtures enumerate syntax; they supply no incoming
// values or external storage. Their original Go object and public Context are
// distinct from private formatter objects. Initialized three-API/five-target
// counterparts belong to TestX86BitTestCompleteFormsFiveTargetsThreeAPIs.
func x86BitTestCompositeFormatObjects(t *testing.T, source, name, arch, triple string) {
	t.Helper()
	goAssemblerOracleOutput(t, arch, "#include \"textflag.h\"\n"+source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("original composite bit-test source changed", err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, "func "+name+"()", arch, triple, api)
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unbound original bit-test source acquired inputs/storage", api, err)
		}
	}
	formats := *file
	formats.Funcs = append([]Func(nil), file.Funcs...)
	formats.Funcs[0].Instrs = nil
	physicalWrites := 0
	for _, instruction := range file.Funcs[0].Instrs {
		if form, known, err := x86BitTestProperties(instruction.Op, instruction, arch); known {
			if err != nil {
				t.Fatal("original Go bit-test grammar changed", err)
			}
			if arch == "386" && form.stem != "BT" && form.destination.Kind == OpReg && form.destination.Reg == SP {
				// The independent complete-form owner checks the emitter's
				// explicit physical ESP-write refusal. Keep the original Go
				// case above, without claiming an object for that entry role.
				physicalWrites++
				continue
			}
		}
		formats.Funcs[0].Instrs = append(formats.Funcs[0].Instrs, instruction)
	}
	wantPhysical := 0
	if arch == "386" {
		wantPhysical = 6
	}
	if physicalWrites != wantPhysical {
		t.Fatal("original physical ESP boundary changed", physicalWrites, wantPhysical)
	}
	signatures := map[string]FuncSig{name: {Name: name, Ret: Void}}
	ir := x86ScalarFormatObjectUnit(t, &formats, signatures, arch, triple, 0)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, level := range []string{"-O0", "-O2"} {
		x86PackedStringCompileObject(t, llc, triple, ir, level)
	}
}
