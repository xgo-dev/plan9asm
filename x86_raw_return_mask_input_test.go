package plan9asm

import (
	"fmt"
	"math"
	"testing"
)

// This observer checks only the existing return-PC memory-disjointness role.
// It supplies neither mask initialization nor permission to access a native
// pointer. The initialized literal programs exercise the independent consumer.
func x86RawReturnMaskInputFixture(t *testing.T, arch, instruction string, sig FuncSig) (*File, Options) {
	t.Helper()
	source := "TEXT Bound(SB),4,$0-32\n" + instruction + "\nBYTE $0xc3\n"
	file, err := Parse(ArchAMD64, source)
	if err == nil {
		// Exercise the exact memory consumer, not an earlier normalization
		// rejection for the deliberately unbound native-pointer controls.
		file.Funcs[0], err = decodeX86RawDirectives(file.Funcs[0], arch)
	}
	if err != nil {
		t.Fatal("original mask input and canonical raw RET lost their source", err)
	}
	sig.Name = "Bound"
	return file, Options{Goarch: arch, Sigs: map[string]FuncSig{"Bound": sig}}
}

func x86RawReturnMaskNumericParameters() FuncSig {
	return FuncSig{Args: []LLVMType{I64, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: I64, Index: 0, Field: -1},
		{Offset: 8, Type: I64, Index: 1, Field: -1},
	}}}
}

func TestX86RawReturnMaskParameterReadsUseExactCompleteNumericBytes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86MaskMoveFPOracle[:4] {
			for offset := 0; offset <= 16-row.bits/8; offset++ {
				t.Run(fmt.Sprintf("%s/%s/+%d", target.triple, row.op, offset), func(t *testing.T) {
					instruction := fmt.Sprintf("%s mask+%d(FP),K1", row.op, offset)
					file, options := x86RawReturnMaskInputFixture(t, target.arch, instruction, x86RawReturnMaskNumericParameters())
					if !x86RawReturnMemoryBound(file.Funcs[0], file, options, true) {
						t.Fatal("an exact existing typed numeric parameter read lost the bounded raw-return role")
					}
				})
			}
		}
	}
}

func TestX86RawReturnMaskParameterReadsRequireEveryOriginalByte(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86MaskMoveFPOracle[:4] {
			for missing := -1; missing < row.bits/8; missing++ {
				t.Run(fmt.Sprintf("%s/%s/missing%d", target.triple, row.op, missing), func(t *testing.T) {
					sig := FuncSig{Ret: Void}
					for offset := 0; offset < row.bits/8; offset++ {
						sig.Args = append(sig.Args, I8)
						if offset != missing {
							sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(offset), Type: I8, Index: offset, Field: -1})
						}
					}
					file, options := x86RawReturnMaskInputFixture(t, target.arch, row.op+" mask+0(FP),K1", sig)
					if got := x86RawReturnMemoryBound(file.Funcs[0], file, options, true); got != (missing == -1) {
						t.Fatal("padding or a missing parameter byte acquired return-PC separation", got)
					}
				})
			}
		}
	}
}

func TestX86RawReturnMaskParameterReadsDoNotGrantOtherStorageRoles(t *testing.T) {
	controls := []string{
		"pointer", "bool", "missing signature", "wrong signature", "unbound index", "overlap", "negative slot", "overflow slot",
		"before frame", "past frame", "numeric result", "mask store", "wrong destination", "native pointer", "raw origin",
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range x86MaskMoveFPOracle[:4] {
			for _, control := range controls {
				t.Run(target.triple+"/"+row.op+"/"+control, func(t *testing.T) {
					sig := x86RawReturnMaskNumericParameters()
					instruction := row.op + " mask+0(FP),K1"
					switch control {
					case "pointer", "bool":
						typ := Ptr
						if control == "bool" {
							typ = I1
						}
						sig.Args[0], sig.Frame.Params[0].Type = typ, typ
					case "missing signature":
						sig.Args = nil
					case "wrong signature":
						sig.Args[0] = I32
					case "unbound index":
						sig.Frame.Params[0].Index = 2
					case "overlap":
						sig.Frame.Params[1].Offset = 4
					case "negative slot":
						sig.Frame.Params[1].Offset = -1
					case "overflow slot":
						sig.Frame.Params[1].Offset = math.MaxInt64 - 1
					case "past frame":
						instruction = row.op + " mask+16(FP),K1"
					case "numeric result":
						sig = FuncSig{Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Type: I64, Index: 0, Field: -1}}}}
					case "mask store":
						instruction = row.op + " K1,mask+0(FP)"
					case "wrong destination":
						instruction = row.op + " mask+0(FP),AX"
					case "native pointer":
						instruction = row.op + " (AX),K1"
					}
					file, options := x86RawReturnMaskInputFixture(t, target.arch, instruction, sig)
					if control == "before frame" {
						file.Funcs[0].Instrs[1].Args[0].FPOffset = -1
					}
					if control == "raw origin" {
						file.Funcs[0].Instrs[1].x86Encoded = true
					}
					if x86RawReturnMemoryBound(file.Funcs[0], file, options, true) {
						t.Fatal("a bounded mask parameter read granted another storage or source role")
					}
				})
			}
		}
	}
}
