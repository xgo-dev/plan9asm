package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARMCorePCStateRequiresContext(t *testing.T) {
	tests := []struct {
		instruction, reason string
	}{
		{"MOVW $0xffff0fc0,R15", "control-flow"},
		{"MOVW R14,R15", "control-flow"},
		{"MOVW.P 192(R13),R15", "control-flow"},
		{"MOVW 0(R15),R0", "source instruction layout"},
		{"MOVW R0,0(R15)", "source instruction layout"},
		{"MOVW $4(R15),R0", "source instruction layout"},
		{"MOVW $4(R0),R15", "control-flow"},
		{"MOVW R15<<2,R0", "source instruction layout"},
		{"ADD R15,R0,R1", "source instruction layout"},
		{"ADD R0,R1,R15", "control-flow"},
		{"CMP R15,R0", "source instruction layout"},
		{"MOVM [R0,R15],(R1)", "source instruction layout"},
		{"MOVM (R1),[R0,R15]", "control-flow"},
		{"WORD $0xe1a0000f", "source instruction layout"},
		{"WORD $0xe1a0f000", "control-flow"},
		// x/arch's GoSyntax aliases these physical PC loads to RET. A
		// textual alias is not a proof of the caller's stack-return contract.
		{"WORD $0xe49df004", "control-flow"},
		{"WORD $0xe49df0c0", "control-flow"},
		{"WORD $0x149df0c0", "control-flow"},
		{"WORD $0xe8bd8001", "control-flow"},
	}
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		tests = append(tests,
			struct{ instruction, reason string }{op + " R15,R0", "source instruction layout"},
			struct{ instruction, reason string }{op + " R0,R15", "control-flow"},
			struct{ instruction, reason string }{op + " R15,0(R0)", "source instruction layout"},
			struct{ instruction, reason string }{op + " 0(R0),R15", "control-flow"},
		)
	}
	for _, test := range tests {
		t.Run(test.instruction, func(t *testing.T) {
			source := "TEXT pcstate(SB),$256-0\nCMP R2,R2\n" + test.instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[2]
			if err := ProbeInstruction(ArchARM, "arm", instruction); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("PC instruction probe silently accepts an unproved machine-state contract: %v", err)
			}
			if err := ProbeInstructionSequence(ArchARM, "arm", file.Funcs[0].Instrs[1:]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("sequence probe lost the PC contract failure: %v", err)
			}
			for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
				options := Options{Goarch: "arm", TargetTriple: triple,
					Sigs: map[string]FuncSig{"pcstate": {Name: "pcstate", Ret: Void}},
				}
				if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), test.reason) {
					t.Fatalf("%s full translation must retain %s failure: %v", triple, test.reason, err)
				}
				module, err := TranslateModule(file, options)
				if err == nil {
					module.Dispose()
					t.Fatal("direct module translation accepted an unproved PC contract")
				}
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), test.reason) {
					t.Fatalf("direct module lost architectural context failure: %v", err)
				}
			}
		})
	}
}

func TestARMCorePCPseudoRegisterIsNotContext(t *testing.T) {
	for _, instruction := range []string{"MOVW PC,R0", "MOVW R0,PC", "MOVW $4,PC", "ADD PC,R0,R1", "ADD R0,R1,PC"} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT illegalpc(SB),$0-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				return
			}
			for _, err := range []error{
				ProbeInstruction(ArchARM, "arm", file.Funcs[0].Instrs[1]),
				func() error {
					_, err := Translate(file, Options{Goarch: "arm", Sigs: map[string]FuncSig{"illegalpc": {Name: "illegalpc", Ret: Void}}})
					return err
				}(),
			} {
				if err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("Go-illegal pseudo PC must not succeed or become contextual: %v", err)
				}
			}
		})
	}
}

func TestARMCorePCGuardKeepsOrdinaryRegistersAndVFPFlags(t *testing.T) {
	const source = "TEXT normal(SB),$0-0\nMOVW $123,R14\nMOVW R14,R0\nADD R0,R1,R2\nCMP R1,R2\nWORD $0xeef1fa10\nRET\n"
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple,
			Sigs: map[string]FuncSig{"normal": {Name: "normal", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "pc-ordinary.ll", "pc-ordinary.o", ir)
	}
	t.Log("ordinary register and VMRS-to-NZCV contracts retain LLVM22 objects")
}
