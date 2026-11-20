package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86OrdinaryIntegerFPStoreKeepsIndependentStorageConsumers(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, lea, stackWord := 8, "LEAQ", "Q"
		if target.arch == "386" {
			word, lea, stackWord = 4, "LEAL", "L"
		}
		for _, row := range []struct {
			name, declaration, body string
			extent                  int
			accepted                bool
		}{
			{"direct-defined", "func Value() uint32", "MOVL $9,AX\nMOVL AX,ret+0(FP)", 4, true},
			{"direct-unknown", "func Value() uint32", "MOVL AX,ret+0(FP)", 4, false},
			{"existing-virtual-SP", "func Value() uint32", "MOVL $9,-4(SP)\nMOVL -4(SP),AX\nMOVL AX,ret+0(FP)", 4, true},
			{"existing-implicit-stack", "func Value() uint32", fmt.Sprintf("MOVL $9,AX\nPUSH%s AX\nPOP%s AX\nMOVL AX,ret+0(FP)", stackWord, stackWord), 4, true},
			// Mode32 owns one checked logical frame. AMD64's independent
			// parameter allocations do not supply contiguous neighbor storage.
			// Retain the original Go source/object, not an out-of-bounds
			// private alloca write disguised as successful translation.
			{"FP-neighbor-needs-contiguous-storage", "func Value(a,b uint32) uint32", lea + " a+0(FP),SI\nMOVL $41,4(SI)\nMOVL b+4(FP),AX\nMOVL AX,ret+8(FP)", 12, target.arch == "386"},
			{"existing-FP-field-address", "func Value(a,b uint32) uint32", lea + " b+4(FP),SI\nMOVL $41,(SI)\nMOVL b+4(FP),AX\nMOVL AX,ret+8(FP)", 12, true},
			{"existing-FP-input-shadow", "func Value(x uint32) uint32", fmt.Sprintf("MOVL $41,x+0(FP)\nMOVL x+0(FP),AX\nMOVL AX,ret+%d(FP)", word), word + 4, true},
			{"partial-cannot-borrow-SP", "func Value() uint32", "MOVL $9,-4(SP)\nMOVB $1,ret+0(FP)", 4, false},
			{"partial-cannot-borrow-implicit-stack", "func Value() uint32", fmt.Sprintf("MOVL $0,AX\nMOVL $0,DX\nMOVL $0,BX\nPUSH%s $0\nPOPF%s\nUMWAIT BX\nMOVB $1,ret+0(FP)", stackWord, stackWord), 4, false},
			{"partial-cannot-borrow-FP-address", "func Value(x uint32) uint32", fmt.Sprintf("%s x+0(FP),SI\nMOVB $1,ret+%d(FP)", lea, word), word + 4, false},
			{"interior-cannot-borrow-SP", "func Value() (uint32,uint8)", "MOVL $9,-4(SP)\nMOVL $0x04030201,ret+0(FP)\nMOVB ret+1(FP),AX\nMOVB AX,ret+4(FP)", 5, false},
			{"cross-field-defined-FP-address", "func Value(x uint32) (uint16,uint16)", fmt.Sprintf("%s x+0(FP),SI\nMOVL $0x04030201,ret+%d(FP)", lea, word), word + 4, true},
			{"cross-field-unknown-cannot-borrow-FP-address", "func Value(x uint32) (uint16,uint16)", fmt.Sprintf("%s x+0(FP),SI\nMOVL AX,ret+%d(FP)", lea, word), word + 4, false},
		} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\nRET\n", row.extent, row.body)
			if row.name == "FP-neighbor-needs-contiguous-storage" || row.name == "existing-FP-field-address" {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
					if row.accepted {
						if err != nil || ir == "" {
							t.Fatal("existing logical storage consumer was replaced by another role", err)
						}
						if row.name == "direct-defined" {
							x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{9})
						} else if row.name == "existing-FP-field-address" {
							const observe = `
define i32 @ObserveField() {
    %value = call i32 @Value(i32 11, i32 23)
    ret i32 %value
}
`
							// The optimizer must use the selected target's actual
							// pointer layout, not its default host-sized pointer.
							observed := x86LODSStateTargetLayout(t, ir+observe, target.triple, word)
							x86ScalarFPNamedConstantResult(t, observed, "ObserveField", []uint64{41})
						} else if row.name == "cross-field-defined-FP-address" {
							// The existing checked unused-address effect grants no
							// address bits, but does not invalidate unrelated data.
							x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{0x0201, 0x0403})
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("new byte view borrowed an independent storage role: output=%t, error=%v", ir != "", err)
					}
				})
			}
		}
		// Independent width/mode/segment witnesses for every value/FLAGS stack
		// row. This tests cost separation only, not native segment permission.
		for _, instruction := range []string{
			"PUSHW AX", "POPW AX", "PUSHFW", "POPFW",
			"PUSH" + stackWord + " AX", "POP" + stackWord + " AX", "PUSHF" + stackWord, "POPF" + stackWord,
			"PUSHL FS", "POPL GS", "PUSHQ FS", "POPQ GS",
		} {
			t.Run(target.triple+"/typed-storage/"+instruction, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-4\n"+instruction+"\nMOVL $9,AX\nMOVL AX,ret+0(FP)\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				sig := FuncSig{Name: "Value", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}
				if x86OrdinaryIntegerFPStoreNeedsProof(file.Funcs[0], sig, target.arch) {
					t.Fatal("complete typed stack row was stolen by direct GP/FP admission")
				}
			})
		}
	}
}
