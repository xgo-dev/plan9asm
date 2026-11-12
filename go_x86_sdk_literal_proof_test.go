package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

const x86SDKLiteralBoundedFixture = `TEXT ·entry<ABIInternal>(SB),4,$0-16
CMPQ AX,$16
JAE done
ADDQ AX,AX
MOVQ $numericTable<>(SB),BX
MOVOU (BX)(AX*8),X0
MOVQ X0,AX
RET
done:
MOVQ $0,AX
RET
`

func TestGoX86SDKLiteralIndependentBoundedAddressProof(t *testing.T) {
	sig := FuncSig{Name: "example.invalid/tableowner.entry", Args: []LLVMType{I64}, Ret: I64}
	file, err := Parse(ArchAMD64, x86SDKLiteralBoundedFixture)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"numericTable<>": 256})
	if err != nil || len(facts) != 2 || !facts[0].Address || facts[1].Address ||
		facts[1].Width != 16 || facts[1].Minimum != 0 || facts[1].Maximum != 240 {
		t.Fatal("literal-only complete source did not close its exact index envelope", facts, err)
	}
}

func TestGoX86SDKLiteralPreservesOnlyTypedUnwrittenRegisters(t *testing.T) {
	for _, inserted := range []string{
		"MOVQ AX,X0", "PINSRW $0,AX,X0", "PSHUFHW $0,X0,X0", "TESTW $15,AX", "PXOR X0,X0",
	} {
		t.Run(inserted, func(t *testing.T) {
			text := strings.Replace(x86SDKLiteralBoundedFixture, "ADDQ AX,AX", inserted+"\nADDQ AX,AX", 1)
			file, err := Parse(ArchAMD64, text)
			if err != nil {
				t.Fatal(err)
			}
			sig := FuncSig{Name: "example.invalid/tableowner.entry", Args: []LLVMType{I64}, Ret: I64}
			if _, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"numericTable<>": 256}); err != nil {
				t.Fatal("shared complete operand effect lost an unrelated numerical register", err)
			}
		})
	}
}

func TestGoX86SDKLiteralBoundedAddressCannotGrantAnotherContract(t *testing.T) {
	for name, source := range map[string]string{
		"no bound":                   strings.ReplaceAll(x86SDKLiteralBoundedFixture, "CMPQ AX,$16\nJAE done\n", ""),
		"wrong edge":                 strings.ReplaceAll(x86SDKLiteralBoundedFixture, "JAE done", "JB done"),
		"stale flags":                strings.ReplaceAll(x86SDKLiteralBoundedFixture, "JAE done", "ADDQ $1,AX\nJAE done"),
		"underflow":                  strings.ReplaceAll(x86SDKLiteralBoundedFixture, "ADDQ AX,AX", "SUBQ $1,AX"),
		"write":                      strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "MOVOU X0,(BX)(AX*8)"),
		"pointer to numerical index": strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "MOVOU (BX)(BX*8),X0"),
		"vector escape":              strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "MOVQ BX,X0"),
		"pointer return":             strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVQ X0,AX", "MOVQ BX,AX"),
		"partial pointer overwrite":  strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "MOVB $0,BL\nMOVOU (BX)(AX*8),X0"),
		"cyclic use":                 strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "again:\nMOVOU (BX)(AX*8),X0\nCMPQ AX,$1\nJE again"),
		"narrow comparison":          strings.ReplaceAll(x86SDKLiteralBoundedFixture, "CMPQ AX,$16", "CMPL AX,$16"),
		"native raw source":          strings.ReplaceAll(x86SDKLiteralBoundedFixture, "ADDQ AX,AX", "BYTE $0x90\nADDQ AX,AX"),
		"source address escape":      strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "MOVQ BX,(CX)"),
		"source FP escape":           strings.ReplaceAll(x86SDKLiteralBoundedFixture, "MOVOU (BX)(AX*8),X0", "MOVQ BX,ret+8(FP)"),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := FuncSig{Name: "example.invalid/tableowner.entry", Args: []LLVMType{I64}, Ret: I64}
			facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"numericTable<>": 256})
			if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("literal address supplied unproved caller/pointer/index/escape/loop authority", facts, err)
			}
		})
	}
}

func TestGoX86SDKLiteralMixedOriginCannotBorrowAnotherPath(t *testing.T) {
	text := strings.Replace(x86SDKLiteralBoundedFixture, "MOVQ $numericTable<>(SB),BX\nMOVOU (BX)(AX*8),X0", `CMPQ BX,$0
JE incoming
MOVQ $numericTable<>(SB),DX
JMP join
incoming:
MOVQ CX,DX
join:
MOVOU (DX)(AX*8),X0`, 1)
	file, err := Parse(ArchAMD64, text)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "example.invalid/tableowner.entry", Args: []LLVMType{I64, I64, Ptr}, Ret: I64}
	facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"numericTable<>": 256})
	if facts != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "mixed origin") {
		t.Fatal("literal path authorized another path's incoming pointer", facts, err)
	}
}

func TestGoX86SDKLiteralBytesCannotSupplyLinkedAddressBits(t *testing.T) {
	for _, target := range []struct {
		arch Arch
		word string
	}{
		{ArchAMD64, "Q"}, {Arch("386"), "L"},
	} {
		for _, operation := range []string{
			"CMP%s BX,$16", "TEST%s $15,BX", "AND%s $15,BX", "OR%s BX,BX", "XOR%s $15,BX",
		} {
			text := "TEXT ·entry(SB),4,$0-0\nMOV" + target.word + " $numericTable<>(SB),BX\n" +
				strings.Replace(operation, "%s", target.word, 1) + "\nRET\n"
			t.Run(string(target.arch)+"/"+operation, func(t *testing.T) {
				file, err := Parse(target.arch, text)
				if err != nil {
					t.Fatal(err)
				}
				facts, err := proveX86SDKLiteralAccesses(file.Funcs[0], FuncSig{Name: "example.invalid/tableowner.entry", Ret: Void},
					string(target.arch), map[string]int64{"numericTable<>": 256})
				if facts != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "linked address-bit observation") {
					t.Fatal("readonly bytes or a 256-byte extent supplied original linked address bits", facts, err)
				}
			})
		}
	}
}

func TestGoX86SDKLiteralTemporaryReaderDoesNotEscapeTransfer(t *testing.T) {
	operand := Operand{Kind: OpMem, Mem: MemRef{Base: BX, Index: AX, Scale: 8}}
	state := x86ResultState{literalMemoryOperand: &operand, literalMemoryBytes: 16}
	if !x86ResultRead(operand, 16, &state, nil, "amd64") || x86ResultRead(operand, 17, &state, nil, "amd64") {
		t.Fatal("instruction-local reader changed its exact native byte width")
	}
	changed := operand
	changed.Mem.Off = 1
	if x86ResultRead(changed, 16, &state, nil, "amd64") {
		t.Fatal("another displacement borrowed the literal reader")
	}
	cloned := state.clone()
	if cloned.literalMemoryOperand != nil || cloned.literalMemoryBytes != 0 || x86ResultRead(operand, 16, &cloned, nil, "amd64") {
		t.Fatal("temporary literal memory authority escaped through a CFG clone")
	}
}
