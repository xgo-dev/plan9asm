package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64NativeTailRejectsUnprovedABI(t *testing.T) {
	for _, instruction := range []string{
		"B (R9)", "JMP *0(R(9))", "RET R9", "RET 8(R9)",
		"WORD $0xd61f0120", // BR X9: raw branches have no Go epilogue.
		"WORD $0xd65f0120", // RET X9, not the caller's proved link.
	} {
		for _, frame := range []int{0, 32} {
			t.Run(fmt.Sprintf("%s/frame_%d", instruction, frame), func(t *testing.T) {
				flags := 4
				if frame == 0 {
					flags |= 512 // Go NOFRAME.
				}
				source := fmt.Sprintf("TEXT nativeTail(SB),%d,$%d-8\nMOVD fn+0(FP),R9\n%s\n", flags, frame, instruction)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
					"nativeTail": {
						Name: "nativeTail", Args: []LLVMType{I64}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
					},
				}})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved native tail target needs an ABI/frame/register contract: %v", err)
				}
			})
		}
	}
}

func TestARM64NativeTailRejectsMissingGoCallerEpilogue(t *testing.T) {
	for _, instruction := range []string{
		"B (R30)", "JMP (LR)", "WORD $0xd61f03c0", "WORD $0xd65f03c0",
	} {
		t.Run(instruction, func(t *testing.T) {
			// Go creates a native frame for TEXT $32, but only its source
			// RET pseudo instruction gets the automatic frame epilogue.
			source := "TEXT framedCallerTail(SB),4,$32-0\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"framedCallerTail": {Name: "framedCallerTail", Ret: Void},
			}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("caller-link proof alone cannot synthesize a missing Go epilogue: %v", err)
			}
		})
	}
}

func TestARM64NativeTailZeroBranchesAreRealFaultingTerminators(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, instruction := range []string{
		"B (ZR)", "JMP (RSP)", "RET ZR", "RET (RSP)",
		"WORD $0xd61f03e0", // BR XZR.
		"WORD $0xd65f03e0", // RET XZR.
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT zeroTail(SB),516,$0-0\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
				"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
			} {
				ir, err := Translate(file, Options{
					Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"zeroTail": {Name: "zeroTail", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ir, `asm sideeffect "br $0", "r,~{memory}"(i64 0)`+"\n  unreachable") {
					t.Fatal("zero target must keep the real faulting branch with no synthetic return")
				}
				compileLLVMToObject(t, llc, triple, "zero-tail.ll", "zero-tail.o", ir)
			}
		})
	}
}

func TestARM64RawBranchRegisterCompleteFields(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	forms := 0
	for _, family := range []struct {
		name string
		word uint32
	}{
		{"BR", 0xd61f0000}, {"BLR", 0xd63f0000}, {"RET", 0xd65f0000},
	} {
		for index := 0; index < 32; index++ {
			word := family.word | uint32(index)<<5
			decoded, err := decodeARM64RawWordInstruction(Instr{
				Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}},
				Raw: fmt.Sprintf("WORD $%#x", word),
			})
			if err != nil {
				t.Fatal(err)
			}
			decoded = arm64HardwareReturnAsBranch(decoded)
			if len(decoded.Args) != 1 {
				t.Fatalf("%s X%d decoded without one target: %#v", family.name, index, decoded)
			}
			reg := decoded.Args[0].Reg
			if decoded.Args[0].Kind == OpMem {
				reg = decoded.Args[0].Mem.Base
			}
			want := Reg(fmt.Sprintf("R%d", index))
			if index == 31 {
				want = ZR
			}
			if reg != want {
				t.Fatalf("%s field %d targets %s, want %s", family.name, index, reg, want)
			}

			name := fmt.Sprintf("rawBranch%d", forms)
			forms++
			sigs[name] = FuncSig{Name: name, Ret: Void}
			fmt.Fprintf(&source, "TEXT %s(SB),516,$0-0\n", name)
			if index == 31 {
				fmt.Fprintf(&source, "WORD $%#x\n", word)
				if family.name == "BLR" {
					source.WriteString("B (ZR)\n")
				}
				continue // Real faulting terminator; not an executed success.
			}
			spelling := string(want)
			if index == 18 {
				spelling = "R18_PLATFORM"
			}
			if index == 28 {
				spelling = "g"
			}
			save := "R19"
			if index == 19 {
				save = "R20"
			}
			fmt.Fprintf(&source, "MOVD R30,%s\nADR localTarget,%s\nWORD $%#x\n", save, spelling, word)
			if family.name == "BLR" {
				fmt.Fprintf(&source, "MOVD %s,R30\nRET\nlocalTarget:\nB (R30)\n", save)
			} else {
				fmt.Fprintf(&source, "localTarget:\nMOVD %s,R30\nRET\n", save)
			}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "raw-branch-register.ll", "raw-branch-register.o", ir)
	}
	t.Logf("All %d BR/BLR/RET register fields retain local/caller or zero-target context on four LLVM22 targets", forms)
}

func TestCrossLinuxRuntimeMatrixARM64FramedSourceRET(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecl, cDecl, goChecks, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for index, instruction := range []string{"RET", "RET (R30)", "RET 8(R30)"} {
		name := fmt.Sprintf("framedReturn%d", index)
		fmt.Fprintf(&source, `TEXT ·%s(SB),4,$32-16
MOVD a+0(FP),R0
ADD $11,R0
MOVD R0,ret+8(FP)
%s
`, name, instruction)
		sigs[name] = arm64LocalRegisterBranchSig(name)
		fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&goChecks, `
for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
	if got := %s(a); got != a+11 {
		println(got)
		panic("framed RET mismatch")
	}
}
`, name)
		fmt.Fprintf(&cChecks, `
for (unsigned i=0;i<5;i++) {
	if (%s(inputs[i])!=inputs[i]+11) {
		fprintf(stderr,"framed RET mismatch\n");
		return 1;
	}
}
`, name)
	}
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
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "framed_source_ret", triple, ir, main, runner)
}
