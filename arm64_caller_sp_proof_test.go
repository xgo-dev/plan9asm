package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64CallerReturnRequiresRestoredSP(t *testing.T) {
	for _, header := range []struct {
		name  string
		flags int
		frame int
	}{
		{"noframe", 516, 0}, {"zero_leaf", 4, 0}, {"auto_frame", 4, 32},
	} {
		for _, instruction := range []string{"B (R30)", "WORD $0xd65f03c0", "RET"} {
			t.Run(header.name+"/"+instruction, func(t *testing.T) {
				source := fmt.Sprintf("TEXT callerSP(SB),%d,$%d-0\nSUB $32,RSP\n%s\n", header.flags, header.frame, instruction)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
					"callerSP": {Name: "callerSP", Ret: Void},
				}})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("caller return must not repair an unbalanced explicit SP delta: %v", err)
				}
			})
		}
	}
}

func TestARM64CallerReturnRejectsUnknownOrMixedSP(t *testing.T) {
	for name, body := range map[string]string{
		"unknown": `MOVD a+0(FP),R0
MOVD R0,RSP
B (R30)`,
		"mixed": `MOVD a+0(FP),R0
CBZ R0,done
SUB $32,RSP
done:
WORD $0xd65f03c0`,
	} {
		t.Run(name, func(t *testing.T) {
			source := "TEXT callerSP(SB),516,$0-8\n" + body + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"callerSP": {
					Name: "callerSP", Args: []LLVMType{I64}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
				},
			}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown/mixed caller SP needs context: %v", err)
			}
		})
	}
}

func TestARM64CallerReturnSymbolCallHasAutomaticGoFrame(t *testing.T) {
	for _, instruction := range []string{"B (R30)", "WORD $0xd65f03c0"} {
		for _, pop := range []string{"", "ADD $16,RSP\n"} {
			t.Run(instruction+"/"+pop, func(t *testing.T) {
				// TEXT $0 is not frameless after a symbol CALL: Go allocates
				// its LR/FP frame. A register branch has no automatic epilogue.
				source := "TEXT callerSP(SB),4,$0-0\nMOVD R30,8(RSP)\nCALL anchor(SB)\nMOVD 8(RSP),R30\n" + pop + instruction + "\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
					"callerSP": {Name: "callerSP", Ret: Void},
					"anchor":   {Name: "anchor", Ret: Void},
				}})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("symbol call introduces an implicit Go frame: %v", err)
				}
			})
		}
	}
}

func TestARM64CallerReturnRejectsEscapedSPInKnownCell(t *testing.T) {
	// An unknown alias may overwrite the saved entry-SP cell with a different
	// SP value. Reading the old exact cell must not reestablish a false proof.
	source := `TEXT callerSP(SB),516,$0-8
MOVD RSP,R20
MOVD R20,0(RSP)
SUB $32,RSP
MOVD RSP,R21
ADD $32,RSP
MOVD a+0(FP),R0
MOVD R21,(R0)
MOVD 0(RSP),R22
MOVD R22,RSP
B (R30)
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
		"callerSP": {
			Name: "callerSP", Args: []LLVMType{I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
		},
	}})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("escaped SP must invalidate a known-cell restoration proof: %v", err)
	}
}

func TestARM64CallerReturnSymbolTailsRequireRestoredSP(t *testing.T) {
	for _, instruction := range []string{"B anchor(SB)", "JMP anchor(SB)", "RET anchor(SB)"} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT callerSP(SB),516,$0-0\nSUB $32,RSP\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"callerSP": {Name: "callerSP", Ret: Void}, "anchor": {Name: "anchor", Ret: Void},
			}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("symbol tail must not bypass the caller SP proof: %v", err)
			}
		})
	}
}

func TestARM64UnreachableCallerReturnsRetainCFGProof(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, instruction := range []string{"RET", "B (R30)", "B (R0)", "WORD $0xd65f0000"} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT callerSP(SB),516,$0-0\nRET\ndead:\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{
				"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
				"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
			} {
				ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"callerSP": {Name: "callerSP", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				start := strings.Index(ir, "\nbb_dead:")
				if start == -1 {
					t.Fatal("dead source block was dropped instead of retaining its terminator")
				}
				block := strings.SplitN(ir[start+1:], "\n\n", 2)[0]
				if !strings.Contains(block, "unreachable") || strings.Contains(block, "ret void") || strings.Contains(block, "indirectbr") {
					t.Fatalf("dead terminator must retain an unreachable block, not a synthetic return:\n%s", block)
				}
				compileLLVMToObject(t, llc, triple, "unreachable-control.ll", "unreachable-control.o", ir)
			}
			// A conditional incoming edge makes the same block reachable.
			source = "TEXT callerSP(SB),516,$0-0\nCBZ R1,dead\nRET\ndead:\nSUB $32,RSP\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err = Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"callerSP": {Name: "callerSP", Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("reachable unproved exit must not become unreachable: %v", err)
			}
		})
	}
	for _, instruction := range []string{"B R0", "RET.P R30", "BOGUS"} {
		source := "TEXT callerSP(SB),516,$0-0\nRET\ndead:\n" + instruction + "\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"callerSP": {Name: "callerSP", Ret: Void}}})
		if err == nil {
			t.Fatalf("unreachable source must still reject invalid/unsupported instruction %q", instruction)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64CallerSPRestore(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecl, cDecl, goChecks, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, flags := range []int{4, 516} {
		for _, instruction := range []string{"B (R30)", "WORD $0xd65f03c0", "RET"} {
			for _, restore := range []string{
				"SUB $32,RSP\nADD $32,RSP",
				"MOVD RSP,R20\nSUB $32,RSP\nMOVD R20,RSP",
				"STP.W (R0,R6),-32(RSP)\nDMB $11\nMOVD $0,R0\nLDP.P 32(RSP),(R0,R6)",
			} {
				name := fmt.Sprintf("callerSPRestore%d", index)
				index++
				fmt.Fprintf(&source, `TEXT ·%s(SB),%d,$0-16
MOVD a+0(FP),R0
ADD $11,R0
%s
MOVD R0,ret+8(FP)
%s
`, name, flags, restore, instruction)
				sigs[name] = arm64LocalRegisterBranchSig(name)
				fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
				fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
				fmt.Fprintf(&goChecks, `
for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
	if got := %s(a); got != a+11 {
		println(got)
		panic("caller SP restore mismatch")
	}
}
`, name)
				fmt.Fprintf(&cChecks, `
for (unsigned i=0;i<5;i++) {
	if (%s(inputs[i])!=inputs[i]+11) {
		fprintf(stderr,"caller SP restore mismatch\n");
		return 1;
	}
}
`, name)
			}
		}
	}
	for _, frame := range []int{0, 32} {
		name := fmt.Sprintf("callerSPRestore%d", index)
		index++
		call := ""
		if frame == 0 {
			call = "CALL ·callerSPAnchor(SB)\n"
		}
		fmt.Fprintf(&source, `TEXT ·%s(SB),4,$%d-16
SUB $32,RSP
ADD $32,RSP
%sMOVD a+0(FP),R0
ADD $11,R0
MOVD R0,ret+8(FP)
RET
`, name, frame, call)
		sigs[name] = arm64LocalRegisterBranchSig(name)
		fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&goChecks, `
for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
	if got := %s(a); got != a+11 {
		panic("automatic Go frame return mismatch")
	}
}
`, name)
		fmt.Fprintf(&cChecks, `
for (unsigned i=0;i<5;i++) {
	if (%s(inputs[i])!=inputs[i]+11) {
		fprintf(stderr,"automatic Go frame return mismatch\n");
		return 1;
	}
}
`, name)
	}
	source.WriteString("TEXT ·callerSPAnchor(SB),4,$0-0\nRET\n")
	goDecl.WriteString("func callerSPAnchor()\n")
	sigs["callerSPAnchor"] = FuncSig{Name: "callerSPAnchor", Ret: Void}
	for _, instruction := range []string{"B", "JMP", "RET"} {
		name := fmt.Sprintf("callerSPRestore%d", index)
		index++
		fmt.Fprintf(&source, `TEXT ·%s(SB),516,$0-16
SUB $32,RSP
ADD $32,RSP
%s ·callerSPValueAnchor(SB)
`, name, instruction)
		sigs[name] = arm64LocalRegisterBranchSig(name)
		fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&goChecks, `
for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
	if got := %s(a); got != a+11 {
		panic("typed symbol SP restoration mismatch")
	}
}
`, name)
		fmt.Fprintf(&cChecks, `
for (unsigned i=0;i<5;i++) {
	if (%s(inputs[i])!=inputs[i]+11) {
		fprintf(stderr,"typed symbol SP restoration mismatch\n");
		return 1;
	}
}
`, name)
	}
	source.WriteString(`TEXT ·callerSPValueAnchor(SB),4,$0-16
MOVD a+0(FP),R0
ADD $11,R0
MOVD R0,ret+8(FP)
RET
`)
	goDecl.WriteString("func callerSPValueAnchor(uint64) uint64\n")
	sigs["callerSPValueAnchor"] = arm64LocalRegisterBranchSig("callerSPValueAnchor")
	requireARM64GoAssemblerResult(t, source.String(), true)
	runARM64LocalRegisterGoOracle(t, source.String(), "package main\n"+goDecl.String()+"func main(){\n"+goChecks.String()+"}\n", len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + "int main(void){ uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};\n" + cChecks.String() + "return 0;}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "caller_sp_restore", triple, ir, main, runner)
	t.Logf("%d SP restoration fixtures x 5 inputs passed native Go and LLVM22", index)
}
