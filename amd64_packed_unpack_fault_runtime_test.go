package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86PackedUnpackFaultProgram() (string, map[string]FuncSig, string, string) {
	var assembly, declarations, rows strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range []struct {
		instruction string
		bytes       int
	}{
		{"VPUNPCKLBW.Z (BX),Z0,K1,Z1", 64},
		{"VPUNPCKHWD.Z (BX),Y0,K1,Y1", 32},
		{"VUNPCKHPS.BCST.Z (BX),X0,K1,X1", 4},
		{"VUNPCKHPD.BCST.Z (BX),Z0,K1,Z1", 8},
	} {
		name := fmt.Sprintf("unpackfault%d", index)
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-16\nMOVQ input+0(FP),BX\nMOVQ out+8(FP),AX\nVPXORD Z0,Z0,Z0\nMOVL $0,CX\nKMOVQ CX,K1\n%s\nVMOVUPS Z1,(AX)\nRET\n", name, row.instruction)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(const uint8_t*,uint8_t*);\n", name)
		fmt.Fprintf(&declarations, `static int observe%d(const uint8_t *input) {
    uint8_t output[66];
    memset(output, 0xc3, sizeof(output));
    %s(input, output + 1);
    if (output[0] != 0xc3 || output[65] != 0xc3) return 1;
    for (unsigned i = 1; i <= 64; ++i) if (output[i]) return 2;
    return 0;
}
`, index, name)
		fmt.Fprintf(&rows, "{observe%d, %d, %d},\n", index, row.bytes, row.bytes-1)
	}
	return assembly.String(), sigs, declarations.String(), rows.String()
}

func TestCrossLinuxRuntimeMatrixX86PackedUnpackZeroMaskStillFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, sigs, declarations, rows := x86PackedUnpackFaultProgram()
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := x86MemoryFaultDriver(declarations, rows)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := execution.compileLLVM(t, "unpack-e4nf-fault", ir, main, level)
			x86CheckMemoryFaultMatrix(t, execution, executable, 4)
		})
	}
}
