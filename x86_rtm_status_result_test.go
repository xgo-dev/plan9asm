package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86RTMStatusQueryGoRowAndState(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{"var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}",
		"{AXTEST, ynone, Px, opBytes{0x0f, 01, 0xd6}}"} {
		if !strings.Contains(string(table), row) {
			t.Fatal("original Go RTM status-query row changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		source := "TEXT query(SB),4,$0-0\nXTEST\nRET\n"
		if got := assembleX87ControlBytes(t, arch, source); !bytes.Equal(got, []byte{0x0f, 0x01, 0xd6, 0xc3}) {
			t.Fatalf("Go XTEST identity changed: %x", got)
		}
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", arch, raw), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "XTEST")
				if raw {
					ins.x86SourceRaw = &x86SourceRawInstruction{op: "XTEST"}
				}
				state := x86ResultState{direction: x86ResultDirectionBackward,
					valueStack: &x86ResultValueStack{bytes: []uint8{1, 2}, id: true}}
				state.gp[0], state.xmm[1], state.masks[2] = 0x81, 0x1234, true
				state.callerAddressGP[7], state.pointerGP[7] = true, true
				want := state.clone()
				want.flags = x86ByteFlagsAll
				if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
					t.Error("XTEST must define six status flags without borrowing or modifying any other state")
				}
				if !x86ResultValueStackContinuation(ins, &state, arch) ||
					x86ResultDirectionAfter(ins, state.direction) != state.direction ||
					x86ResultCallerAddressesAfter(ins, state.callerAddressGP, nil, arch) != state.callerAddressGP {
					t.Error("status query destroyed private storage, DF or unrelated caller identity")
				}
			})
		}
	}
}

func TestX86RTMGrammarRejectsConstructedIdentityAndNonIntegerAbort(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, spelling := range []string{"XABORT $0.0", "XTEST"} {
			t.Run(arch+"/"+spelling, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, spelling)
				if ins.Op == "XABORT" {
					requireX86GoAssemblerResult(t, arch, "TEXT bad(SB),4,$0-0\n"+spelling+"\nRET\n", false)
				} else {
					ins.Op = "XEND" // A dispatcher may not reinterpret a different original opcode.
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before, temporary := output.String(), ctx.tmp
				op := Op(strings.Fields(spelling)[0])
				known, terminated, err := ctx.lowerRTM(0, 0, op, ins, nil)
				if !known || terminated || err == nil || output.String() != before || ctx.tmp != temporary {
					t.Fatal("malformed RTM source emitted an instruction", known, terminated, err)
				}
			})
		}
	}
}

func TestX86RTMStatusQueryRawCompositionKeepsBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		x86RegisterQueryRawCompositionRoles(t, arch, "XTEST", []byte{0x0f, 0x01, 0xd6}, "MOVL $1,AX\n")
	}
}

func TestX86RTMAbortCompleteIntegerImmediateDomain(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var source strings.Builder
	source.WriteString("TEXT ·Abort(SB),4,$0-0\n")
	var bytesWant []byte
	for immediate := 0; immediate < 256; immediate++ {
		fmt.Fprintf(&source, "XABORT $%d\n", immediate)
		bytesWant = append(bytesWant, 0xc6, 0xf8, byte(immediate))
	}
	source.WriteString("RET\n")
	bytesWant = append(bytesWant, 0xc3)
	for _, arch := range []string{"386", "amd64"} {
		if got := assembleX87ControlBytes(t, arch, source.String()); !bytes.Equal(got, bytesWant) {
			t.Fatalf("%s original Go abort immediate bytes differ", arch)
		}
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Abort()", target.arch, target.triple, api)
				if err != nil || strings.Count(ir, "call void @llvm.x86.xabort(") != 256 {
					t.Fatal("complete integer-domain source did not reach actual aborts", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86RTMStatusQueryThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, value, size := "L", "uint32", 4
		if target.arch == "amd64" {
			word, value, size = "Q", "uint64", 8
		}
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				body := "XTEST\n"
				if raw {
					body = x86RawDisplacementDirectives([]byte{0x0f, 0x01, 0xd6})
				}
				source := fmt.Sprintf("TEXT ·Query(SB),4,$0-%d\nPUSH%s seed+0(FP)\nPOPF%s\n%sPUSHF%s\nPOP%s AX\nMOV%s AX,ret+%d(FP)\nRET\n",
					2*size, word, word, body, word, word, word, size)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Query(seed "+value+") "+value, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Error("original complete status query rejected", api, err)
						continue
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			})
		}
	}
}
