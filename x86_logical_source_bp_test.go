package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86PrivateStackPreservesOnlyUnwrittenGPIdentities(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range strings.Fields("PUSHW POPW PUSHL POPL PUSHQ POPQ PUSHFW POPFW PUSHFL POPFL PUSHFQ POPFQ") {
			t.Run(arch+"/"+op, func(t *testing.T) {
				args := " BX"
				if strings.Contains(op, "F") {
					args = ""
				}
				ins := x86ScalarLaneInstruction(t, op+args)
				before := [16]bool{0: true, 1: true, 2: true, 3: true, 5: arch == "386", 6: true, 7: true}
				want := before
				invalid := arch == "386" && strings.HasSuffix(op, "Q") || arch == "amd64" && strings.HasSuffix(op, "L")
				if invalid {
					want = [16]bool{}
				} else if strings.HasPrefix(op, "POP") && !strings.Contains(op, "F") {
					want[3] = false // Any partial/full POP revokes BX's old identity.
				}
				if got := x86ResultCallerAddressesAfter(ins, before, nil, arch); !reflect.DeepEqual(got, want) {
					t.Fatal("typed stack GP footprint either invented or revoked an unrelated identity", got, want)
				}
			})
		}
	}
}

func TestX86OrdinaryMemoryModeAwareFrameRegisters(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, base := range []Reg{AX, BP, SP} {
			for _, index := range []Reg{"", AX, BP, SP} {
				t.Run(arch+"/"+string(base)+"/"+string(index), func(t *testing.T) {
					memory := MemRef{Base: base, Index: index}
					if index != "" {
						memory.Scale = 1
					}
					want := base != SP && index != SP && (arch == "386" || base != BP && index != BP)
					if got := x86OrdinaryNativeMemoryOperand(Operand{Kind: OpMem, Mem: memory}, arch); got != want {
						t.Fatal("ordinary native address classification differs from the selected GP mode", got, want)
					}
				})
			}
		}
	}
}

func TestX86DirectTailModeAwareBPRegisterRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, width, typ := "Q", 8, "uint64"
		if target.arch == "386" {
			word, width, typ = "L", 4, "uint32"
		}
		for _, row := range []struct {
			name, setup, body string
			complete          bool
		}{
			{"numerical", "MOVWORD n+0(FP),BP", "ADDWORD $7,BP\nMOVWORD BP,ret+RESULT(FP)", true},
			{"helper-write", "NOP", "MOVWORD n+0(FP),BP\nMOVWORD BP,ret+RESULT(FP)", true},
			{"logical-result-address", "MOVWORD n+0(FP),SI\nLEAWORD ret+RESULT(FP),BP", "MOVWORD SI,(BP)", true},
			{"private-value-stack", "LEAWORD ret+RESULT(FP),BP", "PUSHWORD n+0(FP)\nMOVWORD $7,(BP)\nPOPWORD AX", true},
			{"unknown-entry", "NOP", "MOVWORD BP,ret+RESULT(FP)", false},
			{"partial-word", "MOVW $7,BP", "MOVWORD BP,ret+RESULT(FP)", false},
			{"unknown-overwrite", "MOVWORD n+0(FP),BP", "MOVWORD CX,BP\nMOVWORD BP,ret+RESULT(FP)", false},
			{"unbound-memory", "MOVWORD n+0(FP),BP", "MOVWORD (BP),AX\nMOVWORD AX,ret+RESULT(FP)", false},
			{"physical-SP", "MOVWORD n+0(FP),SP", "MOVWORD SP,ret+RESULT(FP)", false},
			{"physical-SP-memory", "NOP", "MOVWORD (SP),AX\nMOVWORD AX,ret+RESULT(FP)", false},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf(`TEXT ·Value(SB),NOSPLIT,$0-%d
%s
JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
%s
RET
`,
						2*width, row.setup, row.body)
					source = strings.NewReplacer("WORD", word, "RESULT", fmt.Sprint(width)).Replace(source)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(n "+typ+") "+typ, target.arch, target.triple, api)
					wantPass := target.arch == "386" && row.complete
					if wantPass {
						if err != nil || ir == "" {
							t.Fatal("ordinary mode32 BP lost its source-defined logical role", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("BP classification granted an unbound register/frame/memory role", err)
					}
				})
			}
		}
	}
}

func x86Mode32BPNativeLoadSource(word string, offset int, suffix, widen, setup string) string {
	// Like the other standalone object fixtures, use Go's numeric NOSPLIT
	// flag: the independent `go tool asm` oracle has no header include path.
	return fmt.Sprintf(`TEXT ·Value(SB),4,$0-%d
%s
MOV%s (DX),BP
%s BP,AX
MOVL AX,X0
PEXTRD $0,X0,AX
MOVL AX,ret+%d(FP)
RET
`, offset+4, strings.ReplaceAll(setup, "WORD", word), suffix, widen, offset)
}

func TestX86Mode32BPPairedNativeLoadDefinedBytes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, offset := "Q", 8
		if target.arch == "386" {
			word, offset = "L", 4
		}
		for _, width := range []struct{ suffix, widen string }{
			{"B", "MOVBLZX"}, {"W", "MOVWLZX"}, {"L", "MOVL"},
		} {
			for _, row := range []struct {
				name, setup string
				complete    bool
			}{
				{"incoming-pointer", "MOVWORD p+0(FP),DX", true},
				{"unknown-pointer", "NOP", false},
				{"partial-pointer", "MOVW p+0(FP),DX", false},
				{"numeric-pointer", "MOVL $7,DX", false},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+width.suffix+"/"+row.name+"/"+api, func(t *testing.T) {
						source := x86Mode32BPNativeLoadSource(word, offset, width.suffix, width.widen, row.setup)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte) uint32", target.arch, target.triple, api)
						if target.arch == "386" && row.complete {
							if err != nil || ir == "" || !strings.Contains(ir, "load volatile i") {
								t.Fatal("paired native load lost its ordinary mode32 destination or original fault", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("paired BP load acquired unknown pointer bytes or a physical frame destination", err)
						}
					})
				}
			}
		}
	}
}

func TestX86LogicalSourcePrivateStackWholeHelperCFG(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, width, typ := "Q", 8, "uint64"
		if target.arch == "386" {
			word, width, typ = "L", 4, "uint32"
		}
		for _, row := range []struct {
			name, body string
			complete   bool
		}{
			{"balanced", "PUSHWORD n+0(FP)\nPOPWORD AX\nMOVWORD AX,ret+RESULT(FP)", true},
			{"unknown-input", "PUSHWORD CX\nPOPWORD AX\nMOVWORD AX,ret+RESULT(FP)", false},
			{"unbalanced", "PUSHWORD n+0(FP)\nMOVWORD $7,ret+RESULT(FP)", false},
			{"underflow", "POPWORD AX\nMOVWORD AX,ret+RESULT(FP)", false},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf(`TEXT ·Value(SB),NOSPLIT,$0-%d
JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
%s
RET
`, 2*width, row.body)
					source = strings.NewReplacer("WORD", word, "RESULT", fmt.Sprint(width)).Replace(source)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(n "+typ+") "+typ, target.arch, target.triple, api)
					if row.complete {
						if err != nil || ir == "" {
							t.Fatal("private stack features were not discovered in the complete helper CFG", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("private helper stack bypassed its input/depth proof", err)
					}
				})
			}
		}
	}
}

func x86LogicalSourceBPContinuation(t *testing.T, arch, role string) (string, Options) {
	t.Helper()
	source, options := x86ContinuationResultFixture(t, arch, true)
	if register := map[string]string{"numerical": "BX", "code-table": "SI", "output-pointer": "DI"}[role]; register != "" {
		return strings.ReplaceAll(source, register, "BP"), options
	}
	word := "Q"
	if arch == "386" {
		word = "L"
	}
	body := " MOV" + word + " (SI),BP\n JMP BP"
	switch role {
	case "code-target":
	case "partial-target":
		body = " MOVW (SI),BP\n JMP BP"
	case "unknown-target":
		body = " MOV" + word + " $0,BP\n JMP BP"
	case "overwritten-target":
		body = " MOV" + word + " (SI),BP\n MOVB $0,BP\n JMP BP"
	default:
		t.Fatal("unknown BP continuation fixture role", role)
	}
	return strings.Replace(source, " JMP (SI)", body, 1), options
}

func TestX86ContinuationModeAwareBPRegisterRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			name     string
			complete bool
		}{
			{"numerical", true},
			{"code-table", true},
			{"output-pointer", true},
			{"code-target", true},
			{"partial-target", false},
			{"unknown-target", false},
			{"overwritten-target", false},
		} {
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source, options := x86LogicalSourceBPContinuation(t, target.arch, row.name)
					options.TargetTriple = target.triple
					ir, err := x86ContinuationResultAPI(t, source, options, api)
					if target.arch == "386" && row.complete {
						if err != nil || ir == "" {
							t.Fatal("mode32 BP lost its independently closed continuation role", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("logical continuation admitted the AMD64 physical BP frame", err)
					}
				})
			}
		}
	}
}

func TestX86Mode32BPLogicalSourceOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for mode32 logical BP objects")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue // This owner explicitly compiles the two mode32 targets.
		}
		for _, role := range []string{
			"direct-tail", "private-stack", "private-result-stack",
			"native-load-B", "native-load-W", "native-load-L",
			"numerical", "code-table", "output-pointer", "code-target",
		} {
			t.Run(target.triple+"/"+role, func(t *testing.T) {
				source := strings.ReplaceAll(x86DirectTail386ASM, "SI", "BP")
				declarations := x86DirectTail386Go
				ordinary := role == "direct-tail" || strings.HasPrefix(role, "private-") || strings.HasPrefix(role, "native-load-")
				var options Options
				switch {
				case role == "private-stack":
					source = strings.Replace(source, " MOVL BP,AX", " PUSHL BP\n POPL AX", 1)
				case role == "private-result-stack":
					declarations = "func Value(n uint32) uint32"
					source = `TEXT ·Value(SB),4,$0-8
LEAL ret+4(FP),BP
JMP body<>(SB)
TEXT body<>(SB),4,$0-0
PUSHL n+0(FP)
MOVL $7,(BP)
POPL AX
RET
`
				case strings.HasPrefix(role, "native-load-"):
					suffix := strings.TrimPrefix(role, "native-load-")
					widen := map[string]string{"B": "MOVBLZX", "W": "MOVWLZX", "L": "MOVL"}[suffix]
					source = x86Mode32BPNativeLoadSource("L", 4, suffix, widen, "MOVWORD p+0(FP),DX")
					declarations = "func Value(p *byte) uint32"
				case !ordinary:
					source, options = x86LogicalSourceBPContinuation(t, "386", role)
					options.TargetTriple = target.triple
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				apis := []string{"text", "module", "owned-module"}
				if ordinary {
					apis[2] = "Go"
				}
				for _, api := range apis {
					t.Run(api, func(t *testing.T) {
						var ir string
						var err error
						if ordinary {
							ir, err = x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
						} else {
							ir, err = x86ContinuationResultAPI(t, source, options, api)
						}
						if err != nil {
							t.Fatal(err)
						}
						for _, optimized := range []bool{false, true} {
							input := ir
							if optimized {
								input = x86UndefinedTrapOptimizedIR(t, input)
							}
							for _, level := range []string{"-O0", "-O2"} {
								t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
									x86PackedStringCompileObject(t, llc, target.triple, input, level)
								})
							}
						}
					})
				}
			})
		}
	}
}
