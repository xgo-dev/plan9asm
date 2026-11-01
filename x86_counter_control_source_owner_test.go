package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86CounterControlCanonicalAndExactFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86CounterControlOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, row.op+" done")
				var before [16]uint8
				for index := range before {
					before[index] = 0xff
				}
				want := before
				if row.decrement {
					want[1] = 0
					if arch == "386" {
						want[1] = 0xf0
					}
				}
				if got := x86RegisterCanonicalBytesAfter(ins, before, arch); got != want {
					t.Error("counter control retained a stale canonical value or killed an unrelated alias", got, want)
				}
				if arch != "amd64" {
					return // The existing exact caller-length domain is amd64-only.
				}
				facts := x86CallerCountedNumbers{regs: map[Reg]x86CallerCountedNumber{
					CX: {value: 2, known: true, version: 7}, BX: {value: 9, known: true, version: 8}},
					flags: x86CallerCountedFlags{pc: 3, op: "CMPQ", known: true}, sequence: 10}
				flags, unrelated := facts.flags, facts.regs[BX]
				facts.step(4, 0, ins, x86SourceStackState{}, nil)
				_, count := facts.regs[CX]
				if count == row.decrement || facts.flags != flags || facts.regs[BX] != unrelated {
					t.Error("counter control retained its old exact count/version or changed unrelated facts", facts)
				}
			})
		}
	}
}

func TestX86CounterControlCallerNumericalInputs(t *testing.T) {
	for _, row := range x86CounterControlOracle {
		for _, input := range []struct {
			name    string
			mask    uint8
			pointer bool
		}{
			{"missing", 0, false}, {"word", 3, false}, {"dword", 15, false},
			{"complete", 255, false}, {"opaque", 255, true},
		} {
			t.Run(row.op+"/"+input.name, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, row.op+" done")
				state := x86SourceStackState{known: map[Reg]uint8{CX: input.mask, BX: 255},
					callers: map[Reg]x86CallerPointerValue{}, numericFlags: true}
				if input.pointer {
					state.callers[CX] = x86CallerPointerValue{argument: 0}
				}
				want := !input.pointer && (input.mask == 255 || input.mask == 15 && row.halfCounter)
				_, valid := x86CallerScalarStep(&ins, &state, &x86GoCallerRegionProof{})
				if valid != want {
					t.Fatal("registered caller count consumed an absent/opaque/partial numerical input", valid, want)
				}
				if valid && row.decrement && state.known[CX] != 255 {
					t.Fatal("counter write lost its complete numerical result")
				}
			})
		}
	}
}

func x86CounterCallerAPI(t *testing.T, pkg GoPackage, file *File, source, api string) (string, error) {
	t.Helper()
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "module" {
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
		}
		if err != nil {
			return "", err
		}
		return module.String(), nil
	}
	translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		FileName: "kernel_amd64.s", GOARCH: "amd64", TargetTriple: options.TargetTriple, ResolveSym: resolve,
	})
	if translated != nil && !translated.Module.IsNil() {
		defer translated.Module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return translated.Module.String(), nil
}

func TestX86CounterControlRegisteredCallerSource(t *testing.T) {
	declaration := strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint64")
	for _, row := range x86CounterControlOracle {
		for _, input := range []string{"complete", "counter", "pointer-counter", "low-word", "low-dword", "zero-flag"} {
			t.Run(row.op+"/"+input, func(t *testing.T) {
				producer := "MOVQ (CX),CX\n"
				switch input {
				case "counter":
					producer = "MOVQ R11,CX\n"
				case "pointer-counter":
					producer = ""
				case "low-word":
					producer = "MOVW (CX),CX\n"
				case "low-dword":
					producer = "MOVL (CX),CX\n"
				}
				flags := "MOVL $0,AX\nCMPL AX,$0\n"
				if input == "zero-flag" {
					flags = "MOVL $0,AX\n"
				}
				body := producer + flags + row.op + " counter_done\nMOVQ $2,BX\nJMP counter_out\n" +
					"counter_done:\nMOVQ $3,BX\ncounter_out:\nMOVQ BX,(DX)"
				source := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", body, 1)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				pkg, file := x86CallerCoreFixture(t, declaration, source)
				want := input == "complete" || input == "low-dword" || input == "zero-flag" && !row.zeroFlag
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86CounterCallerAPI(t, pkg, file, source, api)
						if want {
							if err != nil || ir == "" {
								t.Fatal("initialized actual caller lost its counter inputs", err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("actual caller source invented count or ZF input", err)
						}
					})
				}
			})
		}
	}
}

func TestX86CounterControlRegisteredScalarSource(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		suffix, typ := "Q", "uint64"
		if arch == "386" {
			suffix, typ = "L", "uint32"
		}
		for _, row := range x86CounterControlOracle {
			for _, input := range []string{"complete", "counter", "low-word", "low-dword", "zero-flag", "physical-low-word", "physical-low-dword"} {
				t.Run(arch+"/"+row.op+"/"+input, func(t *testing.T) {
					producer := "@MOV @WORD(SP),CX\n"
					if input == "counter" {
						producer = ""
					} else if input == "low-word" {
						producer = "@MOV @WORD(SP),AX\nMOVW AX,CX\n"
					} else if input == "low-dword" {
						producer = "@MOV @WORD(SP),AX\nMOVL AX,CX\n"
					} else if input == "physical-low-word" {
						producer = "MOVW @WORD(SP),CX\n"
					} else if input == "physical-low-dword" {
						producer = "MOVL @WORD(SP),CX\n"
					}
					flags := "@MOV $0,AX\nCMP" + suffix + " AX,$0\n"
					if input == "zero-flag" {
						flags = "@MOV $0,AX\n"
					}
					body := producer + flags + row.op + " count_done\n@MOV $2,BX\nJMP count_out\n" +
						"count_done:\n@MOV $3,BX\ncount_out:\n@MOV BX,@RESULT(SP)\nBYTE $0xc3"
					source, _, _ := x86SourceStackNumericalFixture(arch, body)
					goAssemblerOracleOutput(t, arch, source, "", true)
					want := input == "complete" || input == "low-dword" || input == "zero-flag" && !row.zeroFlag ||
						input == "low-word" && arch == "386" && row.halfCounter || input == "physical-low-dword" && arch == "386"
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(x "+typ+") "+typ, arch, testTargetTriple("linux", arch), api)
							if want {
								if err != nil || ir == "" {
									t.Fatal("initialized scalar source lost its actual physical parameter", err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("scalar source invented count or ZF input", err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86CounterControlDoesNotBorrowBranchHints(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86CounterControlOracle {
			for _, hint := range []int{0, 1} {
				body := fmt.Sprintf("%s $%d,done", row.op, hint)
				source := "TEXT ·Value(SB),4,$0-0\n" + body + "\ndone:\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				ins := x86PureGPUnknownInstruction(t, body)
				before := append([]Operand(nil), ins.Args...)
				if args := x86DirectTailBranchArgs(ins); !reflect.DeepEqual(args, before) {
					t.Fatal("counter target borrowed a FLAGS-branch hint projection")
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, testTargetTriple("linux", arch), api)
					if err == nil || errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("malformed original counter operands were accepted or hidden as Context", err)
					}
				}
			}
		}
	}
}
