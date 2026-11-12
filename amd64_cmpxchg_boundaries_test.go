package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86CMPXCHGDirectHelpersCannotBypassOrderedGrammar(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			op       Op
			identity Op
			bits     int
			pair     bool
			args     []Operand
			context  bool
		}{
			{"CMPXCHG8B", "CMPXCHG8B", 64, true, []Operand{{Kind: OpReg, Reg: BX}}, true},
			{"CMPXCHGL", "MOVL", 32, false, []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: BX}}, false},
			{"CMPXCHGL", "CMPXCHGL", 16, false, []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: BX}}, false},
			{"UNKNOWN", "UNKNOWN", 32, false, []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: BX}}, false},
		} {
			t.Run(fmt.Sprintf("%s/%s/%s/width=%d", arch, row.op, row.identity, row.bits), func(t *testing.T) {
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before, temporary := output.String(), ctx.tmp
				ins := Instr{Op: row.identity, Args: row.args}
				var known, terminated bool
				var err error
				if row.pair {
					known, terminated, err = ctx.lowerPairCompareExchange(string(row.op), row.bits, ins)
				} else {
					known, terminated, err = ctx.lowerScalarCompareExchange(string(row.op), row.bits, ins)
				}
				if !known || terminated || err == nil || errors.Is(err, ErrProbeNeedsContext) != row.context ||
					before != output.String() || temporary != ctx.tmp {
					t.Fatalf("direct helper bypassed complete grammar or emitted partial IR: %t/%t/%v", known, terminated, err)
				}
			})
		}
	}
}

func TestX86CMPXCHGFPRequiresCompleteNativeExtentAndIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := testTargetTriple("linux", arch)
		for _, row := range []struct {
			body, declaration string
			valid             bool
		}{
			{"CMPXCHGB CL,value+0(FP)", "func locked(value uint8)", true},
			{"CMPXCHGW CX,value+0(FP)", "func locked(value uint8)", false},
			{"CMPXCHGL CX,value+0(FP)", "func locked(value uint16)", false},
			{"CMPXCHG8B value+0(FP)", "func locked(value uint32)", false},
			{"CMPXCHGL CX,value+2(FP)", "func locked(value uint32)", false},
			{"CMPXCHGL CX,value+8(FP)", "func locked(value uint32)", false},
		} {
			t.Run(arch+"/"+row.body+"/"+row.declaration, func(t *testing.T) {
				source := "TEXT ·locked(SB),4,$0-16\nMOVL $1,AX\nMOVL $2,BX\nMOVL $3,CX\nMOVL $4,DX\n" + row.body + "\nRET\n"
				actual := x86OrderingHintGoBytes(t, arch, source)
				t.Logf("actual Go accepts the source spelling: %x; this does not prove its typed FP extent", actual)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86OrderingHintTranslateAPI(t, api, source,
						"package ordering\n"+row.declaration+"\n", arch, triple)
					if row.valid {
						if err != nil || !strings.Contains(ir, "cmpxchgb") {
							t.Fatalf("complete pre-existing one-byte FP extent was rejected in %s: %v", api, err)
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), triple, "fp-control.ll", "fp-control.o", ir)
						continue
					}
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("incomplete FP native extent acquired an atomic write in %s: %v", api, err)
					}
				}
			})
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("amd64/16B/shadow/"+api, func(t *testing.T) {
			source := "TEXT ·locked(SB),4,$0-16\nMOVL $1,AX\nMOVL $2,BX\nMOVL $3,CX\nMOVL $4,DX\nCMPXCHG16B value+0(FP)\nRET\n"
			actual := x86OrderingHintGoBytes(t, "amd64", source)
			t.Logf("actual original FP16 opcode: %x; no native alignment identity supplied by a logical shadow", actual)
			ir, err := x86OrderingHintTranslateAPI(t, api, source,
				"package ordering\nfunc locked(value [2]uint64)\n", "amd64", "x86_64-unknown-linux-gnu")
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("virtual FP shadow fabricated CMPXCHG16B native address/alignment: %v", err)
			}
		})
	}
}

func TestX86CMPXCHGFPBackendRequiresExplicitNativeTarget(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		otherMode := "i386-unknown-linux-gnu"
		if arch == "386" {
			otherMode = "x86_64-unknown-linux-gnu"
		}
		// Use the complete byte extent from the positive owner. A missing
		// implicit register or FP byte must not substitute for backend rejection.
		source := "TEXT ·locked(SB),4,$0-16\nMOVL $1,AX\nMOVL $2,BX\nMOVL $3,CX\nMOVL $4,DX\nCMPXCHGB CL,value+0(FP)\nRET\n"
		x86OrderingHintGoBytes(t, arch, source)
		for _, triple := range []string{"", otherMode, "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+triple+"/"+api, func(t *testing.T) {
					ir, err := x86OrderingHintTranslateAPI(t, api, source,
						"package ordering\nfunc locked(value uint8)\n", arch, triple)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "inline assembly") {
						t.Fatal("complete native FP CAS escaped an absent or foreign backend", ir != "", err)
					}
				})
			}
		}
	}
}
