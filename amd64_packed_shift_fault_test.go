package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86PackedShiftFaultProgram() (string, map[string]FuncSig, string, string, []bool) {
	var source, declarations, rows strings.Builder
	sigs := map[string]FuncSig{}
	var required []bool
	for i, row := range []struct {
		instruction       string
		bytes, accessible int
	}{
		{"VPSRLW.Z (CX),Y0,K1,Y1", 16, 8},
		{"VPSRLD.Z (CX),Y0,K1,Y1", 16, 8},
		{"VPSRLQ.Z (CX),Y0,K1,Y1", 16, 8},
		{"VPSRLW.Z $1,(CX),K1,Y1", 0, 0},
		{"VPSRLDQ $1,(CX),Y1", 32, 8},
		{"VPSRLD.Z $1,(CX),K1,Y1", 0, 0},
		{"VPSRLQ.BCST.Z $1,(CX),K1,Y1", 0, 0},
		{"VPSRLVW.Z (CX),Y0,K1,Y1", 0, 0},
		{"VPSRLVD.BCST.Z (CX),Y0,K1,Y1", 0, 0},
		{"VPSRLD $255,(CX),Y1", 32, 8},
		{"VPSRLVD (CX),Y0,Y1", 32, 8},
		{"VPSRLVD.Z (CX),Y0,K1,Y1", 4, 3},
	} {
		name := fmt.Sprintf("faultshift%d", i)
		mask := 0
		if i == 11 {
			mask = 1
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ data+8(FP),BX\nMOVQ count+16(FP),CX\nVMOVUPS (BX),Y0\nVPXOR Y0,Y0,Y0\nMOVQ $%d,DX\nKMOVQ DX,K1\n%s\nVMOVUPS Y1,(AX)\nRET\n", name, mask, row.instruction)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*);\n", name)
		want := "0"
		if i == 4 {
			// VPSRLDQ shifts each independent 128-bit memory lane. The
			// newly added readable control also checks its actual bytes.
			want = "i % 16 == 15 ? 0 : input[i + 1]"
		}
		fmt.Fprintf(&declarations, `static int observe%d(const uint8_t *input) {
    uint8_t data[32], output[34];
    memset(data, 0x71, sizeof(data));
    memset(output, 0xa7, sizeof(output));
    %s(output + 1, data, input);
    if (output[0] != 0xa7 || output[33] != 0xa7) return 3;
    for (unsigned i = 0; i < 32; ++i) {
        uint8_t want = %s;
        if (output[i + 1] != want || data[i] != 0x71) return 4;
    }
    return 0;
}
`, i, name, want)
		fmt.Fprintf(&rows, "{observe%d, %d, %d},\n", i, row.bytes, row.accessible)
		required = append(required, row.bytes != 0)
	}
	return source.String(), sigs, declarations.String(), rows.String(), required
}

func TestCrossLinuxRuntimeMatrixX86PackedShiftNativeReadFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, sigs, declarations, rows, required := x86PackedShiftFaultProgram()
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	driver := x86MemoryFaultDriver(declarations, rows)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := execution.compileLLVM(t, "packed-shift-memory-faults", ir, driver, level)
			x86CheckMemoryAccessMatrix(t, execution, executable, required)
		})
	}
	t.Log("7 full/active native reads and 5 lane-mask suppression cases, including readable controls")
}
