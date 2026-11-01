package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ResultNamedLockCompleteSourceGrammar(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows, want := x86NamedLockOracleForms(arch), 67
		if arch == "386" {
			want = 49
		}
		if len(rows) != want {
			t.Fatal("complete independent LOCK family changed", arch, len(rows))
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				source := x86NamedLockOracleSource(arch, "CMPL AX,AX\nLOCK\n"+row.text)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				fn := file.Funcs[0]
				before := x86DirectTailSnapshot(file)
				bound := x86ResultSourceLockPrefixes(fn, arch)
				if len(bound) != 1 {
					t.Fatal("same-block legal complete RMW lost its prefix association", row.text)
				}
				for ordinal, prefix := range bound {
					if prefix.Op != "LOCK" || !reflect.DeepEqual(fn.Instrs[ordinal], prefix) {
						t.Fatal("prefix did not retain its complete original source ordinal")
					}
					state := x86ResultState{}
					if x86ResultTransfer(prefix, &state, nil, 0, arch) {
						t.Fatal("standalone LOCK acquired a generic inert numerical effect")
					}
					if accepted, known := x86LoweredCompareExchangeResultStep(prefix, &state, nil, arch); accepted || known {
						t.Fatal("an isolated typed opcode query borrowed source adjacency")
					}
				}
				if !reflect.DeepEqual(before, file) {
					t.Fatal("source binding modified the original instruction tuple")
				}
			})
		}
	}
}

func TestX86ResultCompareExchangePrefixAndAuthorityBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, width, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, width, triple = "L", 4, "i386-unknown-linux-gnu"
		}
		for _, row := range []struct{ name, from, to string }{
			{"missing-result", fmt.Sprintf("SETEQ ret+%d(FP)\n", width*5), ""},
			{"missing-CX", fmt.Sprintf("MOV%s c+%d(FP),CX\n", word, width*4), ""},
			{"unknown-address", "MOV" + word + " p+0(FP),SI", "MOV" + word + " $0,SI"},
			{"numerical-address", "MOV" + word + " p+0(FP),SI", fmt.Sprintf("MOV%s a+%d(FP),SI", word, width)},
			{"unknown-index", "CMPXCHGL CX,(SI)", "CMPXCHGL CX,(SI)(DI*4)"},
			{"unbound-SB", "CMPXCHGL CX,(SI)", "CMPXCHGL CX,missing(SB)"},
			{"unbound-FP", "CMPXCHGL CX,(SI)", "CMPXCHGL CX,p+0(FP)"},
			{"physical-SP", "CMPXCHGL CX,(SI)", "CMPXCHGL CX,(SP)"},
			{"physical-BP", "CMPXCHGL CX,(SI)", "CMPXCHGL CX,(BP)"},
			{"prefix-operands", "LOCK\n", "LOCK AX\n"},
			{"double-prefix", "LOCK\n", "LOCK\nLOCK\n"},
			{"detached-prefix", "LOCK\nCMPXCHGL CX,(SI)", "LOCK\nNOP\nCMPXCHGL CX,(SI)"},
			{"trailing-prefix", "LOCK\nCMPXCHGL CX,(SI)", "CMPXCHGL CX,(SI)\nLOCK"},
			{"label-between", "LOCK\nCMPXCHGL CX,(SI)", "LOCK\nmiddle:\nCMPXCHGL CX,(SI)"},
			{"jump-into-body", "LOCK\nCMPXCHGL CX,(SI)", "JMP 2(PC)\nLOCK\nCMPXCHGL CX,(SI)"},
			{"jump-target-body", "LOCK\nCMPXCHGL CX,(SI)", "CMPL AX,AX\nJEQ 2(PC)\nLOCK\nCMPXCHGL CX,(SI)"},
			{"locked-register", "CMPXCHGL CX,(SI)", "CMPXCHGL CX,BX"},
			{"non-RMW-prefix-target", "CMPXCHGL CX,(SI)", "MOVL (SI),CX"},
			{"REP-is-not-LOCK", "LOCK\n", "REP\n"},
			{"REPN-is-not-LOCK", "LOCK\n", "REPN\n"},
			{"undefined-vector-result", "SETEQ ret+", "AESENC X1,X0\nMOV" + word + " X0,AX\nCMPL AX,$0\nSETEQ ret+"},
			{"unknown-effect", "SETEQ ret+", "FSIN\nSETEQ ret+"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					source, declaration := x86ResultCompareExchangeFixture(arch, "CMPXCHGL", true, false)
					if !strings.Contains(source, row.from) {
						t.Fatal("negative did not match the complete source", row.name)
					}
					source = strings.Replace(source, row.from, row.to, 1)
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err == nil || ir != "" {
						t.Fatal("unproved prefix/result/native role was published", row.name, err)
					}
				})
			}
		}
		for _, vector := range []string{"X0", "X1"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/unused-AES-input-"+vector+"/"+api, func(t *testing.T) {
					source, declaration := x86ResultCompareExchangeFixture(arch, "CMPXCHGL", true, false)
					source = strings.Replace(source, "SETEQ ret+", "AESENC "+vector+",X0\nSETEQ ret+", 1)
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil || ir == "" {
						t.Fatal("an unused numerical AES output changed the independent CAS predicate", err)
					}
				})
			}
		}
		for _, pair := range []string{"CMPXCHG8B", "CMPXCHG16B"} {
			if arch == "386" && pair == "CMPXCHG16B" {
				continue // The complete Go grammar rejects this mode, not a missing effect.
			}
			for _, implicit := range []string{"AX", "DX", "BX", "CX"} {
				t.Run(arch+"/"+pair+"/missing-"+implicit, func(t *testing.T) {
					source, declaration := x86ResultCompareExchangeFixture(arch, pair, true, false)
					lines := strings.Split(source, "\n")
					for index, line := range lines {
						if strings.HasSuffix(line, ","+implicit) && strings.Contains(line, "(FP)") {
							lines[index] = ""
						}
					}
					if ir, err := x86ScalarFPBitViewAPI(t, strings.Join(lines, "\n"), declaration, arch, triple, "text"); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("missing implicit pair input acquired bytes", implicit, err)
					}
				})
			}
			t.Run(arch+"/"+pair+"/uninitialized-CF", func(t *testing.T) {
				source, declaration := x86ResultCompareExchangeFixture(arch, pair, true, false)
				source = strings.Replace(source, "SETEQ ret+", "SETCS ret+", 1)
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, "text"); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("pair CAS invented non-ZF status bytes", err)
				}
			})
		}
	}
}

func TestX86ResultCompareExchangeAlternateRMWUsesIndependentEffect(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		source, declaration := x86ResultCompareExchangeFixture(arch, "CMPXCHGL", true, false)
		source = strings.Replace(source, "CMPXCHGL CX,(SI)", "XADDL CX,(SI)", 1)
		requireX86GoAssemblerResult(t, arch, source, true)
		instruction := x86ScalarLaneInstruction(t, "XADDL CX,(SI)")
		state := x86ResultState{}
		if accepted, known := x86LoweredCompareExchangeResultStep(instruction, &state, nil, arch); accepted || known {
			t.Fatal("XADD acquired the unrelated CAS effect")
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil || ir == "" {
					t.Fatal("the independently modeled complete XADD source was rejected", err)
				}
			})
		}
	}
}

func TestX86ResultNamedLockSourceBlockBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, body := range []string{
			"LOCK", "LOCK AX\nCMPXCHGL CX,(SI)",
			"LOCK\nLOCK\nCMPXCHGL CX,(SI)",
			"LOCK\nNOP\nCMPXCHGL CX,(SI)",
			"LOCK\nbody:\nCMPXCHGL CX,(SI)",
			"JMP 2(PC)\nLOCK\nCMPXCHGL CX,(SI)",
			"CMPL AX,AX\nJEQ 2(PC)\nLOCK\nCMPXCHGL CX,(SI)",
		} {
			t.Run(arch+"/"+body, func(t *testing.T) {
				file, err := Parse(ArchAMD64, x86NamedLockOracleSource(arch, body))
				if err != nil {
					t.Fatal("boundary must reach the original source/CFG observer", err)
				}
				prefixes := x86ResultSourceLockPrefixes(file.Funcs[0], arch)
				for ordinal, ins := range file.Funcs[0].Instrs {
					if ins.Op == "LOCK" {
						if _, bound := prefixes[ordinal]; bound {
							t.Fatal("the first split, malformed or independently entered prefix acquired a body", prefixes)
						}
						break
					}
				}
			})
		}
	}
}

func TestX86ResultCompareExchangeConditionalBytesAndFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			op    string
			bytes int64
			pair  bool
		}{
			{"CMPXCHGB", 1, false}, {"CMPXCHGW", 2, false},
			{"CMPXCHGL", 4, false}, {"CMPXCHGQ", 8, false},
			{"CMPXCHG8B", 4, true}, {"CMPXCHG16B", 8, true},
		} {
			if arch == "386" && row.bytes == 8 {
				continue // These complete Go forms are unavailable in this mode.
			}
			for _, register := range []bool{false, true} {
				if register && row.pair {
					continue // Pair register encodings are #UD, not numerical CAS.
				}
				t.Run(fmt.Sprintf("%s/%s/register=%t", arch, row.op, register), func(t *testing.T) {
					source, _ := x86ResultCompareExchangeFixture(arch, row.op, false, register)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					var ins Instr
					for _, candidate := range file.Funcs[0].Instrs {
						if string(candidate.Op) == row.op {
							ins = candidate
						}
					}
					mask := uint8((uint16(1) << uint(row.bytes)) - 1)
					initial := x86ResultState{fp: make([]bool, 16), auto: make([]bool, 16)}
					initial.pointerGP[6] = true // Only the actual opaque SI identity.
					for _, index := range []int{0, 1, 2, 3} {
						initial.gp[index] = mask
					}
					for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
						state := initial.clone()
						state.flags = flags
						want := state.clone()
						want.flags = x86ByteFlagsAll
						if row.pair {
							want.flags = flags | x86ByteFlagZF
						}
						if accepted, known := x86LoweredCompareExchangeResultStep(ins, &state, nil, arch); !accepted || !known || !reflect.DeepEqual(state, want) {
							t.Fatal("conditional accumulator/high-half, non-ZF or disjoint authority changed", flags, state, want)
						}
					}
					inputs := []int{0, 1}
					if register || row.pair {
						inputs = append(inputs, 3)
					}
					if row.pair {
						inputs = append(inputs, 2)
					}
					for _, input := range inputs {
						for missing := int64(0); missing < row.bytes; missing++ {
							state := initial.clone()
							state.gp[input] &^= 1 << uint(missing)
							before := state.clone()
							if accepted, known := x86LoweredCompareExchangeResultStep(ins, &state, nil, arch); accepted || !known || !reflect.DeepEqual(state, before) {
								t.Fatal("unknown/partial actual input gained conditional result bytes", input, missing)
							}
						}
					}
				})
			}
		}
	}
}

func x86ResultCompareExchangeFixture(arch, op string, locked, register bool) (string, string) {
	word, width, typ := "Q", 8, "uint64"
	if arch == "386" {
		word, width, typ = "L", 4, "uint32"
	}
	body := op + " CX,(SI)"
	if strings.HasSuffix(op, "B") && op != "CMPXCHG8B" && op != "CMPXCHG16B" {
		body = op + " CL,(SI)"
	}
	if op == "CMPXCHG8B" || op == "CMPXCHG16B" {
		body = op + " (SI)"
	}
	if register {
		body = strings.ReplaceAll(body, "(SI)", "BX")
	}
	if locked {
		body = "LOCK\n" + body
	}
	source := fmt.Sprintf("TEXT ·cas(SB),4,$0-%d\nMOV%s p+0(FP),SI\n"+
		"MOV%s a+%d(FP),AX\nMOV%s d+%d(FP),DX\nMOV%s b+%d(FP),BX\nMOV%s c+%d(FP),CX\n"+
		"MOV%s AX,X0\nMOV%s X0,AX\n%s\nSETEQ ret+%d(FP)\nRET\n",
		width*5+1, word, word, width, word, width*2, word, width*3, word, width*4, word, word, body, width*5)
	declaration := "func cas(p *byte, a,d,b,c " + typ + ") uint8"
	return source, declaration
}

func TestX86ResultCompareExchangeCompleteSourceFamily(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
	} {
		ops := []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHG8B"}
		if target.arch == "amd64" {
			ops = append(ops, "CMPXCHGQ", "CMPXCHG16B")
		}
		for _, op := range ops {
			for _, shape := range []string{"plain-memory", "LOCK-memory", "register"} {
				if shape == "register" && (op == "CMPXCHG8B" || op == "CMPXCHG16B") {
					continue // Both Go pair register rows encode #UD, not a numerical CAS.
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/"+shape+"/"+api, func(t *testing.T) {
						source, declaration := x86ResultCompareExchangeFixture(target.arch, op, shape == "LOCK-memory", shape == "register")
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						if shape != "register" && (!strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, "=*m") || !strings.Contains(ir, "~{memory}")) {
							t.Fatal("paired native read/write/fault/ordering effect was removed")
						}
						if shape == "LOCK-memory" && !strings.Contains(ir, "asm sideeffect \"lock; cmpxchg") {
							t.Fatal("source-bound LOCK was removed from the original native operation")
						}
					})
				}
			}
		}
	}
}

func TestX86ResultCompareExchangeOrdinaryABI0Source(t *testing.T) {
	const source = `TEXT ·Cas(SB),4,$0-13
MOVL ptr+0(FP),BX
MOVL old+4(FP),AX
MOVL new+8(FP),CX
LOCK
CMPXCHGL CX,0(BX)
SETEQ ret+12(FP)
RET
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			_, err := x86ScalarFPBitViewAPI(t, source,
				"func Cas(ptr *int32, old, new int32) bool", "386", "i386-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
