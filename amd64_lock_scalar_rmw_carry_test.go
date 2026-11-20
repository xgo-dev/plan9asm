package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86LockScalarRMWUnknownIncomingCarryNeedsContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		widths := "BWL"
		if arch == "amd64" {
			widths += "Q"
		}
		for _, stem := range []string{"ADC", "SBB"} {
			for _, width := range widths {
				register := "CX"
				if width == 'B' {
					register = "CL"
				}
				body := "LOCK\n\t" + stem + string(width) + " " + register + ",(SI)"
				t.Run(arch+"/"+stem+string(width), func(t *testing.T) {
					source := x86NamedLockOracleSource(arch, body)
					machine := x86LockScalarOriginalInstruction(t, arch, source)
					t.Logf("actual Go accepts original instruction=%x; incoming CF remains undefined by the source", machine)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86OrderingHintTranslateAPI(t, api, source,
								"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
							// The unchanged source initializes its GP operands but
							// supplies no CF producer. The public error phase/text
							// is not part of this missing-input contract.
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("native carry-dependent memory effect borrowed an undefined entry flag: %v", err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86LockScalarRMWCarryCFGAndStackSources(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		suffix, counter := "Q", "JCXZQ"
		if arch == "386" {
			suffix, counter = "L", "JCXZL"
		}
		for _, control := range []struct {
			name, body string
			known      bool
		}{
			{"CLC", "CLC", true},
			{"STC CMC", "STC\nCMC", true},
			{"initialized CMP", "CMPL AX,$0", true},
			{"undefined CMC", "CMC", false},
			{"undefined compare", "CMPL BP,$0", false},
			{"explicit stack seed", "PUSH" + suffix + " DX\nPOPF" + suffix, true},
			{"unknown stack seed", "PUSH" + suffix + " BP\nPOPF" + suffix, false},
			{"unseeded join", counter + " join\nCLC\njoin:", false},
			{"seeded join", "STC\n" + counter + " join\nCLC\njoin:", true},
			{"call clobber", "STC\nCALL ·other(SB)", false},
			{"undefined divide flags", "STC\nDIVL CX", false},
			{"loop retains seed", "STC\nloop:\nNOP\nLOOP loop", true},
		} {
			t.Run(arch+"/"+control.name, func(t *testing.T) {
				source := x86NamedLockOracleSource(arch,
					control.body+"\nLOCK\nADCL CX,(SI)")
				x86LockScalarOriginalInstruction(t, arch, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before, temporary := output.String(), ctx.tmp
				carryErr := ctx.verifyNamedLockCarry()
				if output.String() != before || ctx.tmp != temporary {
					t.Fatal("carry-only proof changed emitted code")
				}
				if control.known {
					if carryErr != nil {
						t.Fatal("defined source carry was lost", carryErr)
					}
				} else if !errors.Is(carryErr, ErrProbeNeedsContext) {
					t.Fatal("independent carry proof accepted an undefined source", carryErr)
				}
				// The public proof may reject an earlier undefined stack value
				// before reaching LOCK. Its phase is not the carry-only contract.
				triple := testTargetTriple("linux", arch)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source,
							"package ordering\nfunc locked(p *[16]byte)\nfunc other()\n", arch, triple)
						if control.known {
							if err != nil || !strings.Contains(ir, "lock; adcl") {
								t.Fatal("independent defined carry was not retained", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("unclosed carry acquired a numerical value", err)
						}
					})
				}
			})
		}
	}
}

func TestX86LockScalarRMWCarryBudgetAndInputsRemainUnchanged(t *testing.T) {
	file, err := Parse(ArchAMD64, x86NamedLockOracleSource("amd64", "CLC\nLOCK\nADCL CX,(SI)"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
	before, temporary := output.String(), ctx.tmp
	source := fmt.Sprintf("%#v", file)
	for count := 0; count != 2; count++ {
		if err := ctx.verifyNamedLockCarry(); err != nil || before != output.String() || temporary != ctx.tmp || source != fmt.Sprintf("%#v", file) {
			t.Fatal("CF proof modified IR, temporary state or input source", err)
		}
	}
	ctx.blocks = make([]amd64Block, 4097)
	ctx.blocks[0].instrs = []Instr{{Op: "LOCK"}, {Op: "ADCL", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpMem, Mem: MemRef{Base: SI}}}}}
	if err := ctx.verifyNamedLockCarry(); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "bounded") {
		t.Fatal("oversized CF domain did not fail closed", err)
	}
	ctx.blocks = nil
	// Synthetic empty/mismatched cells are consumer tripwires, not Go source
	// acceptance evidence: stock Go rejects a bare POPF as an unbalanced pop.
	if state := ctx.lockCarryTransfer(Instr{Op: "POPFQ"}, x86LockCarryState{carry: true}); state.carry {
		t.Fatal("synthetic empty stack supplied carry")
	}
	state := x86LockCarryState{carry: true, stack: []x86LockCarryCell{{bits: 16, valueKnown: true, carryKnown: true}}}
	if state = ctx.lockCarryTransfer(Instr{Op: "POPFQ"}, state); state.carry {
		t.Fatal("synthetic mismatched-width stack cell supplied carry")
	}
}
