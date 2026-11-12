package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARMKernelHelperContinuationRequiresSourceLRAndFrameProof(t *testing.T) {
	tests := []struct {
		name, text, body string
	}{
		{"frame4", "NOSPLIT,$4", "B gate<>(SB)"},
		{"frame16", "NOSPLIT,$16", "JMP gate<>(SB)"},
		{"frame32", "NOSPLIT,$32", "B gate<>(SB)"},
		{"implicit_call_frame", "NOSPLIT,$0", "BL other<>(SB)\n B gate<>(SB)"},
		{"unreachable_call_frame", "NOSPLIT,$0", "B gate<>(SB)\n BL other<>(SB)"},
		{"implicit_div_frame", "NOSPLIT,$0", "MOVW $2,R0\n DIV R0,R0\n B gate<>(SB)"},
		{"implicit_divu_frame", "NOSPLIT,$0", "MOVW $2,R0\n DIVU R0,R0\n B gate<>(SB)"},
		{"implicit_mod_signed_frame", "NOSPLIT,$0", "MOVW $2,R0\n MOD R0,R0\n B gate<>(SB)"},
		{"implicit_mod_frame", "NOSPLIT,$0", "MOVW $2,R0\n MODU R0,R0\n B gate<>(SB)"},
		{"implicit_bx_frame", "NOSPLIT,$0", "BX (R0)\n B gate<>(SB)"},
		{"implicit_duffzero_frame", "NOSPLIT,$0", "DUFFZERO $0\n B gate<>(SB)"},
		{"implicit_duffcopy_frame", "NOSPLIT,$0", "DUFFCOPY $0\n B gate<>(SB)"},
		{"noframe_native_call", "NOSPLIT|NOFRAME,$0", "BL gate<>(SB)\n RET"},
		{"numeric_noframe_native_call", "516,$0", "CALL gate<>(SB)\n RET"},
		{"historical_noframe_call", "NOSPLIT,$-4", "BL gate<>(SB)\n RET"},
		{"unknown_flags", "UNKNOWN,$0", "BL gate<>(SB)\n RET"},
		{"lr_write_tail", "NOSPLIT,$0", "MOVW $123,R14\n B gate<>(SB)"},
		{"lr_read_call", "NOSPLIT,$0", "BL gate<>(SB)\n MOVW R14,R0\n RET"},
		{"lr_memory_base", "NOSPLIT,$0", "MOVW (R14),R0\n BL gate<>(SB)\n RET"},
		{"lr_shift_source", "NOSPLIT,$0", "MOVW R0<<R14,R1\n BL gate<>(SB)\n RET"},
		{"lr_register_list", "NOSPLIT,$0", "MOVM [R0,R14],(R1)\n BL gate<>(SB)\n RET"},
		{"tail_sp_read", "NOSPLIT,$0", "MOVW R13,R0\n B gate<>(SB)"},
		{"tail_sp_store", "NOSPLIT,$0", "MOVW.W R0,-4(R13)\n B gate<>(SB)"},
		{"call_sp_read", "NOSPLIT,$0", "MOVW R13,R0\n BL gate<>(SB)\n RET"},
		{"call_sp_store", "NOSPLIT,$16", "MOVW R0,4(R13)\n BL gate<>(SB)\n RET"},
		{"raw_lr_write", "NOSPLIT,$0", "WORD $0xe3a0e000\n B gate<>(SB)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT gate<>(SB),NOSPLIT,$0\n MOVW $0xffff0fa0,R15\n" +
				"TEXT other<>(SB),NOSPLIT,$0\n RET\n" +
				"TEXT caller(SB)," + test.text + "\n " + test.body + "\n"
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{
				"gate<>":  {Name: "gate<>", Ret: Void},
				"other<>": {Name: "other<>", Ret: Void},
				"caller":  {Name: "caller", Ret: Void},
			}
			_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("source LR/frame continuation cannot be replaced by an ordinary LLVM return: %v", err)
			}
		})
	}
}

func TestARMKernelHelperContinuationKeepsProvedLeafTailAndFramedCalls(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, text := range []string{"NOSPLIT,$0", "NOSPLIT|NOFRAME,$0", "516,$0", "NOSPLIT,$-4"} {
		for _, branch := range []string{"B", "JMP"} {
			source := "TEXT gate<>(SB),NOSPLIT,$0\n MOVW $0xffff0fa0,R15\n" +
				"TEXT caller(SB)," + text + "\n " + branch + " gate<>(SB)\n"
			requireARMGoAssemblerResult(t, strings.NewReplacer("NOSPLIT", "4", "NOFRAME", "512").Replace(source), true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"gate<>": {Name: "gate<>", Ret: Void}, "caller": {Name: "caller", Ret: Void},
			}})
			if err != nil {
				t.Fatalf("proved zero-frame native tail %s / %s: %v", text, branch, err)
			}
			compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "leaf-tail.ll", "leaf-tail.o", ir)
		}
	}
	for _, frame := range []string{"0", "4", "16", "32"} {
		source := strings.Replace(armKernelHelperSource, "TEXT oracle(SB),$0-16", "TEXT oracle(SB),NOSPLIT,$"+frame+"-16", 1)
		requireARMGoAssemblerResult(t, strings.ReplaceAll(source, "NOSPLIT", "4"), true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armKernelHelperSigs()})
		if err != nil {
			t.Fatalf("Go saves and restores source LR around ordinary framed BL / RET: %v", err)
		}
		compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "framed-call.ll", "framed-call.o", ir)
	}
}
