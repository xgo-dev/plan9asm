package plan9asm

import "testing"

func TestARM64ControlMemoryAddressLiteralsAreNotMemoryLoads(t *testing.T) {
	for _, instruction := range []string{
		"MOVD $4(R10),R11",
		"MOVD $-4097(R2),R3",
		"MOVD $external(SB),R11",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT addressKind(SB),516,$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, accepted := arm64RawPrivateMemory(file.Funcs[0].Instrs[1]); accepted {
				t.Fatal("address materialization was classified as a memory read")
			}
		})
	}
}

func TestARM64ControlMemorySymbolLoadsAndStoresRemainTyped(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD", "FMOVS", "FMOVD", "FMOVQ"} {
		reg := "R11"
		if op[0] == 'F' {
			reg = "F11"
		}
		for _, store := range []bool{false, true} {
			instruction := op + " external(SB)," + reg
			if store {
				instruction = op + " " + reg + ",external(SB)"
			}
			t.Run(instruction, func(t *testing.T) {
				source := "TEXT memoryKind(SB),516,$0-0\n" + instruction + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				form, accepted := arm64RawPrivateMemory(file.Funcs[0].Instrs[1])
				if !accepted || form.store != store || form.elementBytes != arm64RawPrivateScalarBytes(Op(op)) {
					t.Fatalf("actual symbol memory lost its typed direction/width: %+v", form)
				}
			})
		}
	}
}
