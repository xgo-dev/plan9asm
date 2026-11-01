package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalGPFixture(t *testing.T, body string) (Func, FuncSig, string) {
	t.Helper()
	_, _, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64",
		"MOVQ a+0(FP),AX\nMOVQ AX,0(SP)\n"+body+"\nMOVQ AX,ret+8(FP)\nRET")
	source = strings.Replace(source, "$0-16", "$64-16", 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig, source
}

func TestGoAMD64FixedLocalTypedGPWidths(t *testing.T) {
	var original strings.Builder
	count := 0
	// Independent family/width axes. Every memory RMW must read initialized
	// numerical bytes before writing; the syntax oracle is Go's assembler.
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, stem := range []string{"ADD", "SUB", "AND", "OR", "XOR", "ADC", "SBB"} {
			for _, destination := range []string{"AX", "0(SP)"} {
				body := "CMPQ AX,AX\n" + stem + width + " $1," + destination
				fn, sig, source := fixedLocalGPFixture(t, body)
				original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
				count++
				t.Run(stem+width+"/"+destination, func(t *testing.T) {
					if _, err := proveX86FixedLocal(fn, sig); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
		for _, stem := range []string{"NEG", "NOT", "INC", "DEC"} {
			for _, destination := range []string{"AX", "0(SP)"} {
				body := stem + width + " " + destination
				fn, sig, source := fixedLocalGPFixture(t, body)
				original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
				count++
				t.Run(stem+width+"/"+destination, func(t *testing.T) {
					if _, err := proveX86FixedLocal(fn, sig); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
	if count != 88 {
		t.Fatalf("family/width fixture count changed: %d", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalTypedGPFlagsAndProvenance(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"carry only", "STC\nADCQ $1,AX", true},
		{"NOP preserves carry", "STC\nNOP\nADCQ $1,AX", true},
		{"NOP does not define carry", "NOP\nADCQ $1,AX", false},
		{"NOP does not define registers", "NOP\nADDQ CX,AX", false},
		{"carry branch", "STC\nJCS done\ndone:", true},
		{"carry is not zero", "STC\nJEQ done\ndone:", false},
		{"carry is not set zero", "STC\nSETEQ CL", false},
		{"carry is not conditional zero", "STC\nMOVQ AX,CX\nCMOVQEQ CX,AX", false},
		{"undefined carry", "ADCQ $1,AX", false},
		{"compare defines AH flags", "CMPQ AX,AX\nLAHF", true},
		{"test does not define AF", "TESTQ AX,AX\nLAHF", false},
		{"ADX does not define zero", "STC\nADCXQ AX,AX\nJEQ done\ndone:", false},
		{"multiply defines carry", "IMULQ $3,AX\nJCS done\ndone:", true},
		{"multiply kills old zero", "CMPQ AX,AX\nIMULQ $3,AX\nJEQ done\ndone:", false},
		{"test memory", "TESTQ $1,0(SP)\nJEQ done\ndone:", true},
		{"compare memory", "CMPQ 0(SP),$1\nJEQ done\ndone:", true},
		{"self xor initializes", "XORQ CX,CX\nADDQ CX,AX", true},
		{"dword zero extension", "XORL CX,CX\nADDQ CX,AX", true},
		{"word not zero extension", "XORW CX,CX\nADDQ CX,AX", false},
		{"uninitialized register", "ADDQ CX,AX", false},
		{"uninitialized memory", "SUBQ $1,8(SP)", false},
		{"uninitialized self memory", "XORQ AX,8(SP)", false},
		{"crossing frame", "ADDQ $1,60(SP)", false},
		{"numeric not a pointer", "ADDQ $1,(AX)", false},
		{"dynamic memory bit index", "BTQ AX,0(SP)", false},
		{"spilled pointer is not numeric", "MOVQ SP,CX\nMOVQ CX,8(SP)\nADDQ $1,8(SP)", false},
		{"private not numerical", "MOVQ SP,CX\nXORQ CX,AX", false},
		{"partial private overwrite", "MOVQ SP,CX\nXORW CX,CX", false},
		{"stack overwrite", "XORQ SP,SP", false},
		{"unknown suffix", "ADDQ.Z $1,AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalGPFixture(t, row.body)
			_, err := proveX86FixedLocal(fn, sig)
			if (err == nil) != row.valid {
				t.Fatalf("valid=%v: %v", row.valid, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedGPActualObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var assembly, declarations strings.Builder
	for index, body := range []string{
		"STC\nNOP\nADCQ $1,AX",
		"ADDQ $1,AX\nSUBW $1,0(SP)\nMOVQ 0(SP),AX",
		"STC\nADCQ $1,AX\nSBBL $1,0(SP)\nMOVQ 0(SP),AX",
		"NOTQ AX\nNEGB 0(SP)\nINCW 0(SP)\nDECL 0(SP)\nMOVQ 0(SP),AX",
		"TESTQ $1,0(SP)\nCMOVQEQ 0(SP),AX\nSETCS CL",
		"MOVQ AX,CX\nIMULQ $3,CX\nADDQ CX,AX",
		"CMPQ AX,AX\nLAHF\nSAHF\nSHLQ $1,0(SP)\nMOVQ 0(SP),AX",
		"MOVQ AX,CX\nLEAQ 7(AX)(CX*2),AX\nNOPL 8(SP)",
		"MOVQ $3,CX\nagain:\nADDQ CX,AX\nSUBQ $1,CX\nJNE again",
		"MOVQ $3,8(SP)\nagain:\nADDQ $1,AX\nSUBQ $1,8(SP)\nJNE again",
		"CMPQ AX,$1\nJEQ left\nMOVQ $2,CX\nJMP join\nleft:\nMOVQ $3,CX\njoin:\nADDQ CX,AX",
	} {
		_, _, source := fixedLocalGPFixture(t, body)
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		fmt.Fprintf(&declarations, "func Value%d(a uint64) uint64\n", index)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), target.name, target.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "typed-gp.ll", "typed-gp.o", ir)
				})
		})
	}
}

func TestGoAMD64FrameSourceLocalBranches(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"forward", "JMP done\ndone:\nRET", true},
		{"backward", "again:\nSUBQ $1,AX\nJNE done\nJMP again\ndone:\nRET", true},
		{"missing", "JMP absent\nRET", false},
		{"past end", "JMP done\nRET\ndone:", false},
		{"external", "JMP ·Other(SB)\nRET", false},
		{"indirect", "JMP AX\nRET", false},
		{"relative", "JMP 2(PC)\nRET", false},
		{"call", "CALL ·Other(SB)\nRET", false},
		{"tail return", "RET ·Other(SB)", false},
		{"raw", "BYTE $0xc3\nRET", false},
		{"alignment", "PCALIGN $16\nRET", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$16-0\n"+row.body+"\n")
			if err != nil || len(file.Funcs) != 1 {
				t.Fatalf("parse original source: %v", err)
			}
			err = goAMD64FrameSourceInstructions(file.Funcs[0])
			if (err == nil) != row.valid {
				t.Fatalf("valid=%v: %v", row.valid, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedGPLoopAndJoin(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"numeric counter", "MOVQ $3,CX\nagain:\nADDQ CX,AX\nSUBQ $1,CX\nJNE again", true},
		{"private counter", "MOVQ $3,8(SP)\nagain:\nADDQ $1,AX\nSUBQ $1,8(SP)\nJNE again", true},
		{"numeric constants join", "CMPQ AX,$1\nJEQ left\nMOVQ $2,CX\nJMP join\nleft:\nMOVQ $3,CX\njoin:\nADDQ CX,AX", true},
		{"missing first iteration", "again:\nADDQ CX,AX\nMOVQ $3,CX\nJNE again", false},
		{"flags lost on backedge", "CMPQ AX,AX\nagain:\nSETNE CL\nIMULQ $3,AX\nJCS again", false},
		{"drifting private address", "MOVQ SP,CX\nagain:\nADDQ $8,CX\nCMPQ AX,AX\nJNE again", false},
		{"numeric becomes pointer", "MOVQ AX,CX\nagain:\nADDQ CX,AX\nMOVQ SP,CX\nCMPQ AX,AX\nJNE again", false},
		{"missing byte on one path", "CMPQ AX,$1\nJEQ done\nMOVQ AX,8(SP)\ndone:\nMOVQ 8(SP),AX", false},
		{"no reachable return", "again:\nJMP again", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalGPFixture(t, row.body)
			_, err := proveX86FixedLocal(fn, sig)
			if (err == nil) != row.valid {
				t.Fatalf("valid=%v: %v", row.valid, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedGPAddressIsNotAccess(t *testing.T) {
	for _, row := range []struct {
		body string
		want bool
	}{
		{"LEAQ 7(AX)(CX*2),AX", true},
		{"LEAL 7(AX),CX", true},
		{"NOPL 8(SP)", true},
		{"NOPW (AX)", true},
		{"LEAQ 8(SP),AX", true},     // Address-only grammar does not grant private backing or NUM.
		{"LEAQ slot(SP),AX", false}, // A source owner must resolve the descriptive AUTO role.
		{"LEAQ δοκιμή(SP),AX", false},
		{"LEAQ UNKNOWN(RSP),AX", false},
		{"LEAQ UNKNOWN(AX),AX", false},
		{"LEAQ.Z (AX),CX", false},
		{"MOVQ (AX),CX", false},
		{"CMPQ (AX),CX", false},
		{"ADDQ (AX),CX", false},
		{"INCQ (AX)", false},
		{"BTQ CX,(AX)", false},
		{"UNKNOWN (AX)", false},
	} {
		t.Run(row.body, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+row.body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range file.Funcs[0].Instrs {
				if ins.Raw != row.body {
					continue
				}
				if got := fixedLocalGPAddressOnly(ins, 0); got != row.want {
					t.Fatalf("address-only = %v, want %v", got, row.want)
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedGPCFGBudgetIsAtomic(t *testing.T) {
	fn, sig, _ := fixedLocalGPFixture(t, "MOVQ $3,CX\nagain:\nADDQ CX,AX\nSUBQ $1,CX\nJNE again")
	for _, budget := range []x86FixedLocalBudget{
		{steps: 4, bytes: 64 << 20}, // Includes the initial private store.
		{steps: 1 << 18, bytes: fn.FrameSize - 1},
	} {
		proof := &x86FixedLocalProof{frame: fn.FrameSize}
		if err := replayX86FixedLocal(&fn, sig, proof, 0, &budget, nil, nil); err == nil {
			t.Fatal("exhausted analysis budget was accepted")
		}
		for _, ins := range fn.Instrs {
			if len(ins.x86FixedLocalMemory) != 0 {
				t.Fatal("incomplete analysis published an access")
			}
		}
	}
}
