package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86EnqueueCompletePhysicalRegisterAddressFamily(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(table), "{AENQCMD") {
		t.Fatal("Go acquired an enqueue spelling; bind its full encoder rows before changing the oracle")
	}
	registers := []Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for _, mode := range []int{32, 64} {
		count := 8
		if mode == 64 {
			count = 16
		}
		addressSizes := []int{mode}
		if mode == 64 {
			addressSizes = append(addressSizes, 32)
		}
		for _, addressBits := range addressSizes {
			for _, prefix := range []byte{0xf2, 0xf3} {
				for destination := 0; destination < count; destination++ {
					for base := 0; base < count; base++ {
						code := []byte{prefix}
						if addressBits != mode {
							code = append(code, 0x67)
						}
						if mode == 64 {
							// W is ignored. Independently cover every R/B register bit.
							code = append(code, 0x48|byte(destination/8)<<2|byte(base/8))
						}
						code = append(code, 0x0f, 0x38, 0xf8, 0x40|byte(destination%8)<<3|byte(base%8))
						if base%8 == 4 {
							code = append(code, 0x24) // Required SIB: no index, SP/R12 base.
						}
						code = append(code, 0x80) // Signed disp8 avoids the RIP/no-base encoding.
						ins, length, known, err := decodedX86EnqueueInstruction(code, mode)
						want := Op("ENQCMD")
						if prefix == 0xf3 {
							want = "ENQCMDS"
						}
						if err != nil || !known || length != len(code) || ins.Op != want || ins.x86AddressBits != addressBits ||
							len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != registers[base] ||
							ins.Args[0].Mem.Off != -128 || ins.Args[0].Mem.Index != "" || ins.Args[1].Reg != registers[destination] {
							t.Fatalf("complete enqueue register/address form %x in mode %d: %#v / %v", code, mode, ins, err)
						}
					}
				}
			}
		}
	}
}

// Intel's complete family is F2/F3 0F 38 F8 /r, m512 and an address-size
// GP operand. Go has no mnemonic row: the independent Go witnesses use BYTE.
// Native continuation is not a successful device submission, PASID or CPL proof.
func x86EnqueuePointerProgram(arch string, prefix byte, before, after string) (string, string) {
	word, size := "L", 4
	if arch == "amd64" {
		word, size = "Q", 8
	}
	source := fmt.Sprintf("TEXT ·Enqueue(SB),4,$0-%d\nMOV%s command+0(FP),AX\nMOV%s device+%d(FP),DI\n%s%s%sMOVL $0,AX\nSETEQ AX\nMOVL AX,ret+%d(FP)\nRET\n",
		2*size+4, word, word, size, before,
		x86RawDisplacementDirectives([]byte{prefix, 0x0f, 0x38, 0xf8, 0x38}), after, 2*size)
	return source, "func Enqueue(command, device *[64]byte) uint32"
}

func TestX86EnqueueInitializedPointersThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, prefix := range []byte{0xf2, 0xf3} {
			t.Run(fmt.Sprintf("%s/%x", target.triple, prefix), func(t *testing.T) {
				source, declaration := x86EnqueuePointerProgram(target.arch, prefix, "", "")
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete original raw enqueue pointer/status program", api, err)
					}
					op := "enqcmd"
					if prefix == 0xf3 {
						op += "s"
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if !strings.Contains(text, "asm sideeffect \""+op+" $1, $2; sete $0\"") ||
							!strings.Contains(text, "elementtype([64 x i8])") || strings.Contains(text, "llvm.memcpy") {
							t.Fatal("enqueue lost actual whole command, retry or fault behavior", api)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86EnqueueInputAndFrameBoundariesThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, size := "L", 4
		if target.arch == "amd64" {
			word, size = "Q", 8
		}
		for _, prefix := range []byte{0xf2, 0xf3} {
			for _, invalid := range []struct{ name, before, after string }{
				{"numeric-source", "MOVL $0,AX\n", ""},
				{"numeric-device", "MOVL $0,DI\n", ""},
				{"uninitialized-source", "MOV" + word + " BX,AX\n", ""},
				{"uninitialized-device", "MOV" + word + " BX,DI\n", ""},
				{"physical-frame", "LEA" + word + " 0(SP),AX\n", ""},
				{"no-future-read-authority", "", "MOVL (DI),BX\n"},
			} {
				t.Run(fmt.Sprintf("%s/%x/%s", target.triple, prefix, invalid.name), func(t *testing.T) {
					source, declaration := x86EnqueuePointerProgram(target.arch, prefix, invalid.before, invalid.after)
					if invalid.name == "no-future-read-authority" {
						// A later actual native read has its own continuation. An
						// uninitialized third pointer must never inherit device facts.
						source = strings.Replace(source, "MOVL (DI),BX", "MOVL (BX),CX", 1)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("enqueue acquired missing source/device/frame knowledge", api, err)
						}
					}
				})
			}
			// Void cannot evade the same two input-address obligations.
			source, _ := x86EnqueuePointerProgram(target.arch, prefix, "MOVL $0,AX\n", "")
			source = strings.Replace(source, fmt.Sprintf("$0-%d", 2*size+4), fmt.Sprintf("$0-%d", 2*size), 1)
			source = strings.Replace(source, fmt.Sprintf("MOVL AX,ret+%d(FP)\n", 2*size), "", 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Enqueue(command, device *[64]byte)", target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("dead enqueue evaded its source inputs", api, err)
				}
			}
		}
	}
}

func TestX86EnqueueGrammarRejectsBeforePartialEmission(t *testing.T) {
	for _, op := range []Op{"ENQCMD", "ENQCMDS"} {
		for _, invalid := range []string{"dispatch", "foreign-mode", "address-size", "constructed-destination", "unresolved-offset"} {
			t.Run(string(op)+"/"+invalid, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, string(op)+" (AX),DI")
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = "amd64"
				switch invalid {
				case "dispatch":
					ins.Op = "NOP"
				case "foreign-mode":
					ctx.goarch = "arm64"
				case "address-size":
					ins.x86AddressBits = 16
				case "constructed-destination":
					ins.Args[1].ImmRaw = "$unknown"
				case "unresolved-offset":
					ins.Args[0].Mem.OffRaw = "unknown"
				}
				before, temporary := output.String(), ctx.tmp
				known, terminated, err := ctx.lowerEnqueue(op, ins)
				if !known || terminated || err == nil || before != output.String() || temporary != ctx.tmp {
					t.Fatal("invalid enqueue emitted partial IR", known, terminated, err)
				}
			})
		}
	}
}
