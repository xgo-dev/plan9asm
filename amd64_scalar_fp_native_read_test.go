package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86LoweredScalarResultExactNativeRead(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86LegacyMoveNativeOracle {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				var source, declaration strings.Builder
				for lane := 0; lane < 4; lane++ {
					name := fmt.Sprintf("view%d", lane)
					fmt.Fprintf(&declaration, "func %s(p *[16]byte) uint32\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s (AX),X1\nPEXTRD $%d,X1,CX\nMOVL CX,ret+%d(FP)\nRET\n",
						name, word+4, move, row.name, lane, word)
				}
				goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declaration.String(), target.arch, target.triple, api)
						if err != nil {
							t.Fatal("exact emitted read did not supply its returned numerical bytes:", err)
						}
						if strings.Count(ir, "asm sideeffect \""+row.native+" ($1), $0\"") != 4 {
							t.Fatal("result proof was not paired with every original native read")
						}
						compileLLVMToObject(t, llc, target.triple, "native-result.ll", "native-result.o", ir)
					})
				}
			})
		}
	}
}

func TestX86LoweredScalarResultDoesNotGrantStandaloneMemoryProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86LegacyMoveNativeOracle {
			body := fmt.Sprintf("%s p+0(FP),AX\n%s (AX),X1\nPEXTRD $0,X1,CX\nMOVL CX,ret0+%d(FP)\nRET", move, row.name, word)
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *[16]byte) uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s/%s declaration-only query acquired native backing: %v", arch, row.name, err)
				}
			}
		}
	}
}

func TestX86LoweredScalarResultNativePointerPropagation(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, move, add, lea := 8, "MOVQ", "ADDQ", "LEAQ"
		if target.arch == "386" {
			word, move, add, lea = 4, "MOVL", "ADDL", "LEAL"
		}
		for name, body := range map[string]string{
			"copy":   move + " AX,DX\nMOVOU (DX),X1\n",
			"offset": add + " $16,AX\nMOVOU (AX),X1\n",
			"index":  "MOVL $2,CX\nMOVOU 8(AX)(CX*4),X1\n",
			"lea":    "MOVL $2,CX\n" + lea + " 8(AX)(CX*4),DX\nMOVOU (DX),X1\n",
			"both paths": "MOVL $1,CX\nCMPL CX,$0\nJE other\n" + move + " AX,DX\nJMP end\nother:\n" +
				lea + " 16(AX),DX\nend:\nMOVOU (DX),X1\n",
		} {
			t.Run(target.triple+"/"+name, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s p+0(FP),AX\n%sPEXTRD $2,X1,CX\nMOVL CX,ret+%d(FP)\nRET\n",
					word+4, move, body, word)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[32]byte) uint32\n", target.arch, target.triple, api)
					if err != nil {
						t.Fatal(api, err)
					}
					compileLLVMToObject(t, llc, target.triple, "native-pointer.ll", "native-pointer.o", ir)
				}
			})
		}
	}
}

func TestX86LoweredScalarResultNativeReadBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		load := move + " p+0(FP),AX\n"
		finish := fmt.Sprintf("PEXTRD $0,X1,CX\nMOVL CX,ret+%d(FP)\nRET\n", word)
		for name, body := range map[string]string{
			"unknown base":       "MOVOU (DI),X1\n",
			"numeric base":       "MOVL $42,AX\nMOVOU (AX),X1\n",
			"lost identity":      load + "MOVL $42,AX\nMOVOU (AX),X1\n",
			"unknown index":      load + "MOVOU (AX)(DI*1),X1\n",
			"pointer index":      load + "MOVOU (AX)(AX*1),X1\n",
			"native store":       load + "MOVOU (AX),X1\nMOVOU X1,(AX)\n",
			"unknown store data": load + "MOVOU (AX),X1\nMOVOU X0,(AX)\n",
			"unknown store base": load + "MOVOU (AX),X1\nMOVOU X1,(DI)\n",
			"unknown lane":       load + "MOVOU (AX),X0\n",
			"missing path":       load + "MOVL $1,CX\nCMPL CX,$0\nJE done\nMOVOU (AX),X1\ndone:\n",
			"incoming write":     load + "MOVOU (AX),X1\nMOVL $42,p+0(FP)\n",
			"unbound static":     "MOVOU ·external(SB),X1\n",
			"unbound segment":    "MOVOU (FS),X1\n",
			"mixed pointer join": load + "MOVL $1,CX\nCMPL CX,$0\nJE other\n" + move +
				" AX,DX\nJMP end\nother:\nMOVL $42,DX\nend:\nMOVOU (DX),X1\n",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n", word+4) + body + finish
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[16]byte) uint32\n", arch, triple, api)
					if name == "native store" {
						// Both inputs are now modeled by the complete paired store
						// consumer. Keep this exact former negative as an object
						// control, with unknown data/address negatives beside it.
						if err != nil || ir == "" {
							t.Fatal("complete paired native store lost its inputs", api, err)
						}
						llc := findLLVM22Tool("llc")
						if llc == "" {
							t.Fatal("LLVM22 llc required")
						}
						for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
							compileLLVMToObject(t, llc, triple, "paired-store.ll", "paired-store.o", text)
						}
						continue
					}
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s borrowed native/result authority: %v", api, err)
					}
				}
			})
		}
	}
}

func TestX86LoweredScalarResultRawOriginCannotBorrowConditionalRead(t *testing.T) {
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[16]byte) uint32",
		"MOVQ p+0(FP),AX\nMOVOU (AX),X1\nPEXTRD $0,X1,CX\nMOVL CX,ret0+8(FP)\nRET")
	for _, change := range []string{"decoded", "address size", "unknown address size", "raw TEXT", "source stack", "fixed local"} {
		t.Run(change, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			switch change {
			case "decoded":
				fn.Instrs[2].x86Encoded = true
			case "address size":
				fn.Instrs[2].x86AddressBits = 32
			case "unknown address size":
				fn.Instrs[2].x86UnboundAddressOverride = true
			case "raw TEXT":
				fn.X86RawText = []byte{0xc3}
			case "source stack":
				fn.x86SourceStack = new(x86SourceStackProof)
			case "fixed local":
				fn.x86FixedLocal = new(x86FixedLocalProof)
			}
			ctx := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: "amd64"}
			if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved raw entry acquired ordinary conditional effect: %v", err)
			}
		})
	}
}
