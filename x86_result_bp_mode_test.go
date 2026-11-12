package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultMode32BPDefinedBytesAndCompleteCFG(t *testing.T) {
	for _, row := range []struct {
		name, body string
		pass       bool
	}{
		{"full-input", "MOVL n+0(FP),BP", true},
		{"constant", "MOVL $7,BP", true},
		{"arithmetic", "MOVL n+0(FP),BP\nADDL $9,BP", true},
		{"self-XOR", "XORL BP,BP", true},
		{"byte-exchange", "MOVL n+0(FP),BP\nMOVL $9,DI\nXCHGB BP,DI", true},
		{"word-exchange", "MOVL n+0(FP),BP\nMOVL $9,DI\nXCHGW BP,DI", true},
		{"dword-exchange", "MOVL n+0(FP),BP\nMOVL $9,DI\nXCHGL BP,DI", true},
		{"byte-SETcc", "CMPL n+0(FP),$0\nSETEQ BP\nMOVBLZX BP,BP", true},
		{"numerical-LEA", "MOVL n+0(FP),BP\nLEAL 3(BP)(BP*2),BP", true},
		{"word-preserves-defined-high", "MOVL n+0(FP),BP\nMOVW $7,BP", true},
		{"both-branches", "CMPL n+0(FP),$0\nJE other\nMOVL $7,BP\nJMP joined\nother:\nMOVL $9,BP\njoined:", true},
		{"unknown-entry", "NOP", false},
		{"partial-word", "MOVW $7,BP", false},
		{"partial-byte", "MOVB $7,BP", false},
		{"unknown-overwrite", "MOVL n+0(FP),BP\nMOVL CX,BP", false},
		{"one-branch", "CMPL n+0(FP),$0\nJE joined\nMOVL $7,BP\njoined:", false},
		{"unknown-LEA-input", "LEAL 3(BP),BP", false},
		{"returning-CALL", "MOVL n+0(FP),BP\nCALL ·other(SB)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := row.body + "\nMOVL BP,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+4(FP)\nRET"
			_, file, sig, _ := x86ResultInitializationFixture(t, "386", "func Value(n uint32) uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				err := check(file.Funcs[0], sig, "386")
				if row.pass && err != nil || !row.pass && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("mode32 BP defined-byte proof differs", row.pass, err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					source := "TEXT ·view(SB),4,$0-8\n" + body + "\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(n uint32) uint32\nfunc other()\n", "386", "i386-unknown-linux-gnu", api)
					if row.pass && (err != nil || ir == "") || !row.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("mode32 BP source/result publication differs", row.pass, err)
					}
				})
			}
		})
	}
}

func TestX86ResultMode32BPOpaquePointerPredicateAndCAS(t *testing.T) {
	for _, row := range []struct {
		name, body string
		pass       bool
	}{
		{"pointer-TEST", "MOVL p+0(FP),BP\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", true},
		{"copied-pointer-TEST", "MOVL p+0(FP),SI\nMOVL SI,BP\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", true},
		{"unknown-BP", "TESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", false},
		{"partial-pointer", "MOVW p+0(FP),BP\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", false},
		{"pointer-not-numeric", "MOVL p+0(FP),BP\nMOVL BP,AX", false},
		{"partial-pointer-overwrite", "MOVL p+0(FP),BP\nMOVW $7,BP\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", false},
		{"unknown-FLAGS", "MOVL p+0(FP),BP\nSETEQ AX\nMOVBLZX AX,AX", false},
		{"both-pointer-branches", "MOVL p+0(FP),SI\nTESTL $1,SI\nJE other\nMOVL SI,BP\nJMP joined\nother:\nMOVL p+0(FP),BP\njoined:\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", true},
		{"missing-pointer-branch", "MOVL p+0(FP),SI\nTESTL $1,SI\nJE joined\nMOVL SI,BP\njoined:\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", false},
		{"numeric-pointer-join", "MOVL p+0(FP),SI\nTESTL $1,SI\nJE other\nMOVL SI,BP\nJMP joined\nother:\nMOVL $7,BP\njoined:\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", false},
		{"returning-pointer-CALL", "MOVL p+0(FP),BP\nCALL ·other(SB)\nTESTL $7,BP\nSETEQ AX\nMOVBLZX AX,AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := row.body + "\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+4(FP)\nRET"
			_, file, sig, _ := x86ResultInitializationFixture(t, "386", "func Value(p *byte) uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				err := check(file.Funcs[0], sig, "386")
				if row.pass && err != nil || !row.pass && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("mode32 BP pointer and NUM domains conflated", row.pass, err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-8\n"+body+"\n", "func view(p *byte) uint32\nfunc other()\n", "386", "i386-unknown-linux-gnu", api)
					if row.pass && (err != nil || ir == "") || !row.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("mode32 BP predicate publication differs", row.pass, err)
					}
				})
			}
		})
	}
	for _, name := range []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHG8B"} {
		for _, row := range []struct{ name, pointer string }{
			{"incoming", "MOVL p+0(FP),BP"}, {"unknown", "NOP"}, {"numeric", "MOVL $7,BP"}, {"partial", "MOVW p+0(FP),BP"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(name+"/"+row.name+"/"+api, func(t *testing.T) {
					body := row.pointer + "\nMOVL a+4(FP),AX\nMOVL b+8(FP),DX\nMOVL c+12(FP),BX\nMOVL d+16(FP),CX\nLOCK\n"
					if name == "CMPXCHG8B" {
						body += name + " (BP)"
					} else {
						body += name + " CX,(BP)"
					}
					body += "\nSETEQ AX\nMOVBLZX AX,AX\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+20(FP)\nRET\n"
					_, file, sig, _ := x86ResultInitializationFixture(t, "386", "func Value(p *uint64,a,b,c,d uint32) uint32", body)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "386"); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("ordinary BP classification gave a standalone query native CAS authority", err)
					}
					ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-24\n"+body,
						"func view(p *uint64,a,b,c,d uint32) uint32\n", "386", "i386-unknown-linux-gnu", api)
					pass := row.name == "incoming"
					if pass && (err != nil || ir == "") || !pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("mode32 BP CAS acquired address/NUM authority", pass, err)
					}
				})
			}
		}
	}
}

func TestX86ResultModeAwareBPAndSPRemainDistinct(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, reg := range []string{"SP", "BP"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+reg+"/"+api, func(t *testing.T) {
					word, move, triple := 4, "MOVL", "i386-unknown-linux-gnu"
					if arch == "amd64" {
						word, move, triple = 8, "MOVQ", "x86_64-unknown-linux-gnu"
					}
					body := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s n+0(FP),%s\nMOVL %s,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+%d(FP)\nRET\n", word+4, move, reg, reg, word)
					ir, err := x86ScalarFPBitViewAPI(t, body, fmt.Sprintf("func view(n uint%d) uint32\n", word*8), arch, triple, api)
					pass := arch == "386" && reg == "BP"
					if pass && (err != nil || ir == "") || !pass && (err == nil || ir != "") {
						t.Fatal("ordinary mode32 BP changed a stack/frame contract", pass, err)
					}
					if pass && !strings.Contains(ir, "%reg_BP") {
						t.Fatal("mode32 BP source lost its independent value slot")
					}
				})
			}
		}
	}
}
