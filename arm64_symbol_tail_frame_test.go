package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64SymbolTailRequiresGoFrameEpilogue(t *testing.T) {
	for _, frame := range []int{8, 32, 240} {
		for _, instruction := range []string{"B anchor(SB)", "JMP anchor(SB)"} {
			t.Run(fmt.Sprintf("frame%d/%s", frame, instruction), func(t *testing.T) {
				source := fmt.Sprintf("TEXT symbolTail(SB),4,$%d-0\n%s\n", frame, instruction)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
					"symbolTail": {Name: "symbolTail", Ret: Void},
					"anchor":     {Name: "anchor", Ret: Void},
				}})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("B/JMP do not pop the implicit Go frame: %v", err)
				}
			})
		}
	}
	for _, instruction := range []string{"B anchor(SB)", "JMP anchor(SB)"} {
		t.Run("nonleaf_zero/"+instruction, func(t *testing.T) {
			source := "TEXT symbolTail(SB),4,$0-0\nCALL anchor(SB)\nMOVD (RSP),R30\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"symbolTail": {Name: "symbolTail", Ret: Void}, "anchor": {Name: "anchor", Ret: Void},
			}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("symbol CALL creates a 16-byte Go frame even at TEXT $0: %v", err)
			}
		})
	}
}

func TestARM64FramedLeafReturnRequiresCallerLink(t *testing.T) {
	for _, instruction := range []string{"RET", "RET R30", "RET anchor(SB)"} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT leafReturn(SB),4,$32-0\nMOVD $123,R30\n" + instruction + "\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"leafReturn": {Name: "leafReturn", Ret: Void}, "anchor": {Name: "anchor", Ret: Void},
			}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Go leaf RET pops SP but does not reload caller LR: %v", err)
			}
		})
	}
}

func TestARM64RawBranchLinkDoesNotCreateGoFrame(t *testing.T) {
	for _, fixture := range []struct {
		body      string
		indirects int
	}{
		{"WORD $0x94000002\nRET\nhelper:\nB (R30)", 2},
		{"ADR helper,R0\nWORD $0xd63f0000\nRET\nhelper:\nB (R30)", 3},
	} {
		source := "TEXT rawLeaf(SB),4,$0-0\n" + fixture.body + "\n"
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
			"rawLeaf": {Name: "rawLeaf", Ret: Void},
		}})
		if err != nil {
			t.Fatal(err)
		}
		// Both helper return and subsequent RET target the real local link.
		// With no caller-link restoration, this is an in-function loop, not
		// an automatically restored outer return. Do not execute that loop.
		if strings.Count(ir, "indirectbr") != fixture.indirects {
			t.Fatalf("raw AWORD BL/BLR must not invent an auto-epilogue caller return:\n%s", ir)
		}
	}
}

func TestARM64NonleafReturnRequiresSavedCallerLink(t *testing.T) {
	for _, instruction := range []string{"RET", "RET anchor(SB)"} {
		for _, store := range []string{"MOVD R0,(RSP)", "MOVB R0,7(RSP)", "MOVW R0,4(RSP)"} {
			t.Run(instruction+"/"+store, func(t *testing.T) {
				source := "TEXT nonleafReturn(SB),4,$32-0\nCALL anchor(SB)\nMOVD $123,R0\n" + store + "\n" + instruction + "\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
					"nonleafReturn": {Name: "nonleafReturn", Ret: Void}, "anchor": {Name: "anchor", Ret: Void},
				}})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("nonleaf Go RET reloads LR from the overwritten implicit frame cell: %v", err)
				}
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64SymbolTailGoFrameOracle(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	var source, decl, checks strings.Builder
	index := 0
	add := func(frame int, body string, want int) {
		name := fmt.Sprintf("goFrameTarget%d", index)
		measure := fmt.Sprintf("goFrameMeasure%d", index)
		index++
		fmt.Fprintf(&source, `TEXT ·%s(SB),516,$0-8
MOVD RSP,R19
MOVD R30,R23
MOVD R29,R24
MOVD $0,R25
BL ·%s(SB)
SUB R19,RSP,R0
ADD R25,R0
MOVD R19,RSP
MOVD R24,R29
MOVD R23,R30
MOVD R0,ret+0(FP)
RET
TEXT ·%s(SB),4,$%d-0
%s
`, measure, name, name, frame, body)
		fmt.Fprintf(&decl, "func %s() int64\n", measure)
		fmt.Fprintf(&decl, "func %s()\n", name)
		fmt.Fprintf(&checks, "if got := %s(); got != %d { println(%q,got); panic(\"Go frame delta mismatch\") }\n", measure, want, name)
	}
	for _, frame := range []struct{ declared, allocated int }{{0, 0}, {8, 32}, {32, 48}, {240, 256}} {
		for _, op := range []string{"B", "JMP", "RET"} {
			want := -frame.allocated
			if op == "RET" {
				want = 0
			}
			add(frame.declared, op+" ·goFrameAnchor(SB)", want)
		}
	}
	for _, op := range []string{"B", "JMP", "RET"} {
		want := -16
		if op == "RET" {
			want = 0
		}
		add(0, "CALL ·goFrameAnchor(SB)\nMOVD (RSP),R30\n"+op+" ·goFrameAnchor(SB)", want)
	}
	// These calls are encoded as AWORD, not Go's ABL. The native assembler
	// therefore leaves TEXT $0 frameless. Save and restore the real caller LR.
	add(0, "MOVD R30,R22\nWORD $0x94000003\nMOVD R22,R30\nRET\nhelper:\nB (R30)", 0)
	add(0, "MOVD R30,R22\nADR helper,R0\nWORD $0xd63f0000\nMOVD R22,R30\nRET\nhelper:\nB (R30)", 0)
	// Redirect a source RET to a safe witness label, then return through the
	// original native link. Leaf RET uses current LR; nonleaf RET reloads the
	// saved LR cell. Both pop their Go frame before reaching the witness.
	add(32, "MOVD R30,R22\nADR redirected,R30\nRET\nredirected:\nMOVD R22,R30\nMOVD $123,R25\nB ·goFrameAnchor(SB)", 123)
	add(32, "CALL ·goFrameAnchor(SB)\nMOVD (RSP),R22\nADR redirected,R0\nMOVD R0,(RSP)\nRET\nredirected:\nMOVD R22,R30\nMOVD $123,R25\nB ·goFrameAnchor(SB)", 123)
	source.WriteString("TEXT ·goFrameAnchor(SB),4,$0-0\nRET\n")
	decl.WriteString("func goFrameAnchor()\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	dir := t.TempDir()
	asm := filepath.Join(dir, "frame.s")
	if err := os.WriteFile(asm, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-S", "-o", filepath.Join(dir, "frame.o"), asm)
	cmd.Env = append(os.Environ(), "GOARCH=arm64")
	listing, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go frame object listing: %v\n%s", err, listing)
	}
	t.Logf("Go frame object listing:\n%s", listing)
	runARM64LocalRegisterGoOracle(t, source.String(), "package main\n"+decl.String()+"func main(){\n"+checks.String()+"}\n", len(runner) != 0)
	t.Logf("Native Go measured %d B/JMP/RET, raw BL/BLR and leaf/nonleaf LR witnesses; trampoline restores the actual caller SP/LR/FP", index)
}

func TestCrossLinuxRuntimeMatrixARM64SymbolTailReturnContracts(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecl, cDecl, goChecks, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	add := func(frame int, body string) {
		name := fmt.Sprintf("symbolReturn%d", index)
		index++
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$%d-16\n%s\n", name, frame, body)
		sigs[name] = arm64LocalRegisterBranchSig(name)
		fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&goChecks, `
for _, a := range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
	if got := %s(a); got != a+11 {
		println(got)
		panic("symbol return contract mismatch")
	}
}
`, name)
		fmt.Fprintf(&cChecks, `
for (unsigned i=0;i<5;i++) {
	if (%s(inputs[i])!=inputs[i]+11) {
		fprintf(stderr,"symbol return contract mismatch\n");
		return 1;
	}
}
`, name)
	}
	for _, frame := range []int{0, 8, 32, 240} {
		add(frame, "RET ·symbolValueAnchor(SB)")
		add(frame, "CALL ·symbolVoidAnchor(SB)\nRET ·symbolValueAnchor(SB)")
	}
	for _, op := range []string{"B", "JMP"} {
		add(0, "MOVD R30,R22\nMOVD $123,R30\nMOVD R22,R30\n"+op+" ·symbolValueAnchor(SB)")
	}
	for _, op := range []string{"RET", "RET ·symbolValueAnchor(SB)"} {
		body := "MOVD R30,8(RSP)\nMOVD $123,R30\nMOVD 8(RSP),R30\n"
		if op == "RET" {
			body += "MOVD a+0(FP),R0\nADD $11,R0\nMOVD R0,ret+8(FP)\n"
		}
		add(32, body+op)
		body = "MOVD (RSP),R22\nMOVD R22,8(RSP)\nCALL ·symbolVoidAnchor(SB)\nMOVD $123,R0\nMOVD R0,(RSP)\nMOVD 8(RSP),R22\nMOVD R22,(RSP)\n"
		if op == "RET" {
			body += "MOVD a+0(FP),R0\nADD $11,R0\nMOVD R0,ret+8(FP)\n"
		}
		add(32, body+op)
	}
	for _, call := range []string{"B callsite\nhelper:\nWORD $0x91002400\nB (R30)\ncallsite:\nWORD $0x97fffffe", "ADR helper,R3\nWORD $0xd63f0060"} {
		helper := "\nhelper:\nADD $9,R0\nB (R30)"
		if strings.HasPrefix(call, "B callsite") {
			helper = ""
		}
		add(0, "MOVD a+0(FP),R0\nMOVD R30,R22\n"+call+"\nADD $2,R0\nMOVD R22,R30\nMOVD R0,ret+8(FP)\nRET"+helper)
	}
	source.WriteString(`TEXT ·symbolValueAnchor(SB),4,$0-16
MOVD a+0(FP),R0
ADD $11,R0
MOVD R0,ret+8(FP)
RET
TEXT ·symbolVoidAnchor(SB),4,$0-0
RET
`)
	goDecl.WriteString("func symbolValueAnchor(uint64) uint64\nfunc symbolVoidAnchor()\n")
	sigs["symbolValueAnchor"] = arm64LocalRegisterBranchSig("symbolValueAnchor")
	sigs["symbolVoidAnchor"] = FuncSig{Name: "symbolVoidAnchor", Ret: Void}
	requireARM64GoAssemblerResult(t, source.String(), true)
	runARM64LocalRegisterGoOracle(t, source.String(), "package main\n"+goDecl.String()+"func main(){\n"+goChecks.String()+"}\n", len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs,
			ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, target, "symbol-return.ll", "symbol-return.o", ir)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + "int main(void){ uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};\n" + cChecks.String() + "return 0;}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "symbol_return_contracts", triple, ir, main, runner)
	t.Logf("%d symbol/caller-link return fixtures x 5 inputs passed native Go and LLVM22, plus four-target objects", index)
}
