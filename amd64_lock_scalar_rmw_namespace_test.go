package plan9asm

import (
	"strings"
	"testing"
)

func TestX86LockScalarRMWNoCandidateDoesNotResolveLocals(t *testing.T) {
	for _, body := range []string{
		"MOVQ value+0(FP),AX\nloop:\nRET",
		"LOCK\nADDL AX,BX\nRET",
	} {
		file, err := Parse(ArchAMD64, "TEXT ·f(SB),4,$0-8\n"+body+"\n")
		if err != nil {
			t.Fatal(err)
		}
		var calls []string
		namespace := x86LockScalarNamespace(file, "amd64", func(symbol string) string {
			calls = append(calls, symbol)
			return strings.TrimPrefix(symbol, "·")
		}, map[string]FuncSig{"f": {Name: "f", Ret: Void}})
		if namespace != "" || len(calls) != 0 {
			t.Fatalf("no legal helper must not allocate names or call the user resolver: namespace=%q calls=%v", namespace, calls)
		}
	}
}

func TestX86LockScalarRMWNamespaceUsesFinalGlobalsOnly(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT ·f(SB),4,$0-8
	MOVQ value+0(FP),SI
	MOVL $1,AX
	LOCK
	ADDL AX,(SI)
done:
	RET
DATA ·table+0(SB)/8,$·imported(SB)
GLOBL ·table(SB),8,$8
`)
	if err != nil {
		t.Fatal(err)
	}
	final := map[string]string{
		"·f":        "__plan9asm_lock_rmw_0_amd64_add32_native",
		"·table":    "__plan9asm_lock_rmw_1_amd64_add32_native",
		"·imported": "imported",
	}
	var unknown []string
	resolve := func(symbol string) string {
		if name, ok := final[symbol]; ok {
			return name
		}
		unknown = append(unknown, symbol)
		return symbol
	}
	sigs := map[string]FuncSig{
		final["·f"]: {Name: final["·f"], Ret: Void},
		"imported":  {Name: "__plan9asm_lock_rmw_2_amd64_add32_native", Ret: Void},
	}
	if namespace := x86LockScalarNamespace(file, "amd64", resolve, sigs); namespace != "__plan9asm_lock_rmw_3_" || len(unknown) != 0 {
		t.Fatalf("helper namespace must bind final function/data/import names, not FP or local labels: namespace=%q unknown=%v", namespace, unknown)
	}
}

func TestX86LockScalarRMWUnrelatedTranslationKeepsResolverDomain(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT ·f(SB),4,$0-8
	MOVQ value+0(FP),AX
done:
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	var calls, unknown []string
	resolve := func(symbol string) string {
		calls = append(calls, symbol)
		if symbol != "·f" {
			unknown = append(unknown, symbol)
		}
		return strings.TrimPrefix(symbol, "·")
	}
	sig := FuncSig{Name: "f", Args: []LLVMType{I64}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}
	ir, err := Translate(file, Options{Goarch: "amd64", ResolveSym: resolve, Sigs: map[string]FuncSig{"f": sig}})
	if err != nil || len(unknown) != 0 || len(calls) != 6 || strings.Contains(ir, "__plan9asm_lock_rmw_") {
		t.Fatalf("a no-LOCK translation changed its existing resolver domain/count: error=%v calls=%v", err, calls)
	}
}
