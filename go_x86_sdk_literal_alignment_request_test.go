package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoX86SDKLiteralAlignmentRequestGlobalInventoryBound(t *testing.T) {
	file, options := sdkLiteralAlignmentRequestFixture(t, "MOVQ $one<>(SB),AX\nTESTQ $15,AX\nSETEQ AX", I1)
	globals := make([]GloblStmt, gostaticstorage.ObjectSymbolInventoryLimit+1)
	copy(globals, file.Globl)
	for index := len(file.Globl); index < len(globals); index++ {
		globals[index] = GloblStmt{Sym: fmt.Sprintf("extra%d<>", index), Flags: "RODATA", Size: 32}
	}
	file.Globl = globals[:gostaticstorage.ObjectSymbolInventoryLimit]
	if !GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("existing object-symbol inventory boundary was rejected")
	}
	file.Globl = globals
	options.ResolveSym = func(string) string { t.Error("oversized inventory reached the resolver"); return "arbitrary/sdk.view" }
	if GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("unbounded global inventory requested a Go link")
	}
}

func TestGoX86SDKLiteralAlignmentRequestTypedPredicateOnly(t *testing.T) {
	for _, move := range []string{"MOVQ", "MOVD", "MOVDQ2Q", "LEAQ"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			materialize := move + " $one<>(SB),BX"
			if move == "LEAQ" {
				materialize = "LEAQ one<>(SB),BX"
			}
			body := materialize + "\nMOVQ BX,DX\nMOVQ $two<>(SB),CX\nORQ CX,DX\nTEST" + width + " $15,DX\nSETEQ AX"
			file, options := sdkLiteralAlignmentRequestFixture(t, body, I1)
			original := append([]Instr(nil), file.Funcs[0].Instrs...)
			if !GoX86SDKLiteralAlignmentRequested(file, options) {
				t.Errorf("%s/TEST%s lost the typed literal-address predicate cost", move, width)
			}
			if !reflect.DeepEqual(original, file.Funcs[0].Instrs) || options.NumericalReads != nil {
				t.Fatal("cost query changed original instructions or manufactured a binding")
			}
		}
	}
	file, options := sdkLiteralAlignmentRequestFixture(t, "MOVQ $one<>+3(SB),AX\nTESTB $15,AX\nSETEQ AX", I1)
	if !GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("direct displaced literal predicate did not request its independent minimum")
	}
}

func TestGoX86SDKLiteralAlignmentRequestDoesNotLinkOrdinaryReads(t *testing.T) {
	for name, body := range map[string]string{
		"readonly-scalar":   "MOVQ one<>(SB),AX\nTESTQ $15,AX\nSETEQ AX",
		"readonly-vector":   "MOVOU one<>(SB),X0\nTESTQ AX,AX\nSETEQ AX",
		"incoming-pointer":  "TESTW $0xff0,AX\nSETEQ AX",
		"unrelated-address": "MOVQ $one<>(SB),BX\nTESTW $15,AX\nSETEQ AX",
		"partial-carrier":   "MOVQ $one<>(SB),BX\nMOVW $0,BX\nTESTW $15,BX\nSETEQ AX",
		"numeric-OR":        "MOVQ $one<>(SB),BX\nORQ AX,BX\nTESTQ $15,BX\nSETEQ AX",
		"no-predicate":      "MOVQ $one<>(SB),BX\nMOVQ (BX),AX",
		"escaped-address":   "MOVQ $one<>(SB),BX\nMOVQ BX,X0\nTESTQ $15,BX\nSETEQ AX",
		"raw":               "BYTE $0x90\nMOVQ $one<>(SB),BX\nTESTQ $15,BX\nSETEQ AX",
	} {
		t.Run(name, func(t *testing.T) {
			file, options := sdkLiteralAlignmentRequestFixture(t, body, I1)
			if GoX86SDKLiteralAlignmentRequested(file, options) {
				t.Fatal("unrelated/unsupported source requested an additional Go link")
			}
		})
	}
	file, options := sdkLiteralAlignmentRequestFixture(t, "MOVQ $one<>(SB),AX\nTESTQ $15,AX\nSETEQ AX", I64)
	if GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("a non-bool logical result borrowed the masked predicate class")
	}
	file.Globl[0].Flags = "NOPTR"
	options.Sigs["arbitrary/sdk.view"] = FuncSig{Name: "arbitrary/sdk.view", Ret: I1}
	if GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("mutable pointer-free data requested the readonly linked-layout role")
	}
}

func sdkLiteralAlignmentRequestFixture(t *testing.T, body string, result LLVMType) (*File, Options) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT ·view<ABIInternal>(SB),4,$0-1\n"+body+"\nRET\nGLOBL one<>(SB),RODATA,$32\nGLOBL two<>(SB),8,$64\n")
	if err != nil {
		t.Fatal(err)
	}
	return file, Options{Goarch: "amd64", ResolveSym: func(symbol string) string {
		return "arbitrary/sdk." + strings.TrimPrefix(strings.TrimSuffix(symbol, "<ABIInternal>"), "·")
	}, Sigs: map[string]FuncSig{"arbitrary/sdk.view": {Name: "arbitrary/sdk.view", Args: []LLVMType{Ptr}, Ret: result}}}
}
