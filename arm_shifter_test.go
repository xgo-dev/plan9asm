package plan9asm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARMShifterZeroCanonicalizationMatchesGoObject(t *testing.T) {
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return // Go1.20 API lane; the pinned Go1.27 object is the source oracle.
	}
	const source = "TEXT zero(SB),4,$0\n MOVW R0>>0,R3\n MOVW R0->0,R3\n MOVW R0@>0,R3\n MOVW R2,R0>>0(R1)\n MOVW R2,R0->0(R1)\n MOVW R2,R0@>0(R1)\n RET\n"
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "zero.s"), filepath.Join(dir, "zero.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	assemble := exec.Command("go", "tool", "asm", "-o", object, asm)
	assemble.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm")
	if output, err := assemble.CombinedOutput(); err != nil {
		t.Fatalf("Go object: %v\n%s", err, output)
	}
	dump := exec.Command("go", "tool", "objdump", object)
	output, err := dump.CombinedOutput()
	if err != nil {
		t.Fatalf("Go objdump: %v\n%s", err, output)
	}
	for _, encoding := range []string{"e1a03000", "e7812000"} {
		if strings.Count(string(output), encoding) != 3 {
			t.Fatalf("Go zero-shift canonical encoding %s missing:\n%s", encoding, output)
		}
	}
}

func TestARMRawVFPProofDoesNotInventEarlyNZCVTransfer(t *testing.T) {
	for _, body := range []string{"WORD $0xeeb40b40\n MOVW.EQ $1,R0", "WORD $0x1eb40b40\n WORD $0xeef1fa10\n MOVW CPSR,R0"} {
		source := "TEXT flags(SB),$0\n MOVW $0,R0\n CMP R0,R0\n " + body + "\n RET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"flags": {Name: "flags", Ret: I32}}})
		if err == nil || errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "closed unconditional") {
			t.Fatalf("unmodeled pending FPSCR effect is an ordinary hard gap, not entry-state N/A: %v", err)
		}
	}
}

func TestARMShifterCompleteGoFormats(t *testing.T) {
	cases := armShifterRuntimeCases()
	source := armShifterRuntimeSource(cases)
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
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: armShifterOracleSignature()})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "shifter.ll", "shifter.o", ir)
	}
}

func TestARMShifterRejectsOutsideGoGrammar(t *testing.T) {
	for _, instruction := range []string{"TST R0<<32,R1", "ORR.S R0>>99,R1", "MUL.S $1,R1", "MULLU.S R0,R1,R2", "MULA.S R0,R1,R2", "MVN R0,R1,R2", "MVN.S $1,R2", "ORR.S (R0),R1", "ORR R0,R1<<1,R2", "TST.S R0,R1", "AND.P R0,R1", "ADD value+4(FP),R0"} {
		source := "TEXT bad(SB),$0\n CMP R0,R0\n " + instruction + "\n RET\n"
		requireARMGoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
			t.Fatalf("accepted outside Go shifter/multiply grammar: %s", instruction)
		}
	}
}

func TestARMShifterNeedsCarryOnlyWhenSourceConsumesIt(t *testing.T) {
	for _, body := range []string{"ADC $1,R0", "TST R0,R0\n MOVW.CS $1,R1", "MUL.S R0,R1\n MOVW.VS $1,R2", "CMP R0,R0\n DIV R0,R1\n MOVW.EQ $1,R2"} {
		source := "TEXT flags(SB),$0\n MOVW $1,R0\n MOVW $1,R1\n " + body + "\n RET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"flags": {Name: "flags", Ret: Void}}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("source consumes undefined carry/overflow, not a zero flag slot: %s: %v", body, err)
		}
	}
	for _, body := range []string{"TST R0<<1,R0\n MOVW.CS $1,R1", "MUL.S R0,R1\n MOVW.EQ $1,R2"} {
		source := "TEXT flags(SB),$0\n MOVW $1,R0\n MOVW $1,R1\n " + body + "\n RET\n"
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"flags": {Name: "flags", Ret: Void}}}); err != nil {
			t.Fatalf("source defines exactly the consumed flags: %s: %v", body, err)
		}
	}
}

func TestARMStatusReachabilityDoesNotInventOrRequireDeadFlags(t *testing.T) {
	for _, body := range []string{
		"B live\ndead:\n MOVW CPSR,R2\n MOVW.EQ $1,R2\nlive:\n MOVW $7,R0\n RET",
		"MOVW $0,R0\n CMP R0,R0\n B live\ndead:\n BL unknown<>(SB)\n MOVW CPSR,R2\nlive:\n MOVW CPSR,R0\n RET",
	} {
		source := "TEXT flags(SB),$0\n " + body + "\nTEXT unknown<>(SB),$0\n RET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"flags": {Name: "flags", Ret: I32}, "unknown<>": {Name: "unknown<>", Ret: Void}}}
		if _, err := Translate(file, options); err != nil {
			t.Fatalf("unreachable flags uses must not impose entry requirements: %v", err)
		}
		module, err := TranslateModule(file, options)
		if err != nil {
			t.Fatal(err)
		}
		module.Dispose()
	}
	source := "TEXT flags(SB),$0\n B live\ndead:\n MOVW $0,R0\n CMP R0,R0\nlive:\n MOVW CPSR,R0\n RET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"flags": {Name: "flags", Ret: I32}}}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("dead writer cannot prove a live CPSR read: %v", err)
	}
}

func TestARMMultiplyFlagsCompleteGoFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT flags(SB),$0\n MOVW $0,R0\n CMP R0,R0\n")
	for _, instruction := range []string{"MUL.S R0,R1", "MULU.EQ.S R0,R1,R2", "MULA.S R0,R1,R2,R3", "MULL.S R0,R1,(R3,R2)", "MULLU.S R0,R1,(R3,R2)", "MULAL.S R0,R1,(R3,R2)", "MULALU.NE.S R0,R1,(R3,R2)"} {
		source.WriteString(" " + instruction + "\n")
	}
	source.WriteString(" MOVW CPSR,R0\n RET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{"flags": {Name: "flags", Ret: I32}}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "multiply-flags.ll", "multiply-flags.o", ir)
	}
}
