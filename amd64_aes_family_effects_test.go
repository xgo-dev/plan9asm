package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent source inventory: six SSE names and their six AVX names. AES
// round rows are destructive only in their legacy spelling; no Go AES row
// has a K operand, broadcast or zeroing suffix.
var x86AESOracleNames = []string{"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST", "VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST", "VAESIMC", "VAESKEYGENASSIST"}

func x86AESOracleRow(name, source, bank string) (string, int) {
	if strings.Contains(name, "KEYGEN") {
		return name + " $27," + source + "," + bank + "2", 2
	}
	if strings.HasSuffix(name, "IMC") {
		return name + " " + source + "," + bank + "2", 2
	}
	if strings.HasPrefix(name, "V") {
		return name + " " + source + "," + bank + "1," + bank + "2", 2
	}
	return name + " " + source + "," + bank + "1", 1
}

func TestX86AESFamilyInitialTypedAndPrivateResults(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86AESOracleNames {
			row, destination := x86AESOracleRow(name, "X0", "X")
			t.Run(arch+"/"+name, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
				ins := x86YMMReadSource(t, row)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatalf("complete AES typed byte/flags effect absent: known=%t err=%v", known, err)
				}
				for _, transfer := range []struct {
					name string
					fn   func(Instr, *x86ResultState, []bool, int64, string) bool
				}{{"public", x86ResultTransfer}, {"private", x86ScalarFPResultTransfer}} {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.xmm[0], state.xmm[1] = 0xffff, 0xffff
					if !transfer.fn(ins, &state, nil, 0, arch) || state.xmm[destination] != 0xffff || state.flags != x86ByteFlagsAll {
						t.Fatal(transfer.name, "lost complete AES input/result or preserved flags", state)
					}
				}
			})
		}
	}
}

func TestX86AESFamilyInitialCallerSourceEffects(t *testing.T) {
	for _, name := range x86AESOracleNames {
		row, destination := x86AESOracleRow(name, "X0", "X")
		t.Run(name, func(t *testing.T) {
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\n" + row + fmt.Sprintf("\nVMOVSS X%d,(DX)", destination)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal("actual Go accepted whole-family caller has no registered AES source effect", err)
			}
		})
	}
}

func TestX86AESFamilyResultEveryNativeMemoryByte(t *testing.T) {
	for _, name := range x86AESOracleNames {
		row, destination := x86AESOracleRow(name, "a+0(FP)", "X")
		ins := x86YMMReadSource(t, row)
		for missing := -1; missing < 16; missing++ {
			t.Run(fmt.Sprintf("%s/missing%d", name, missing), func(t *testing.T) {
				state := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll}
				state.xmm[1] = 0xffff
				owned := make([]bool, 16)
				for i := range owned {
					owned[i], state.fp[i] = true, i != missing
				}
				before := state.clone()
				got := x86ScalarFPResultTransfer(ins, &state, owned, 16, "amd64")
				if got != (missing == -1) || got && state.xmm[destination] != 0xffff || !got && !reflect.DeepEqual(state, before) {
					t.Fatal("native m128 envelope/unknown byte must not be shrunk to numerical subwords", got, state)
				}
			})
		}
	}
}

func TestX86AESFamilyWholeSourceResultsCannotLaunderUndefinedInputs(t *testing.T) {
	for _, name := range x86AESOracleNames {
		row, destination := x86AESOracleRow(name, "X0", "X")
		for _, target := range x86RawReturnTargets {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(name+"/"+target.triple+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·F(SB),4,$0-4\n%s\nMOVL X%d,AX\nMOVL AX,ret+0(FP)\nRET\n", row, destination)
					_, err := x86ScalarFPBitViewAPI(t, source, "func F() uint32\n", target.arch, target.triple, api)
					if err == nil {
						t.Fatal("undefined AES byte escaped through GP result-store fallback")
					}
				})
			}
		}
	}
}
