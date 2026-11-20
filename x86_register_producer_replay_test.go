package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86RegisterReplayConsumers(t *testing.T, arch, source string) (func(Func) error, func(Func) error) {
	t.Helper()
	pkg := mustGoPackage(t, "registerreplay", "package registerreplay\nfunc Value() uint32")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	signatures, err := goSigsForAsmFile(pkg, mustParseX86RawReturn(t, source), resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal("actual zero-argument numeric result declaration prerequisite", err)
	}
	sig, found := signatures["Value"]
	if !found || len(sig.Frame.Params) != 0 || sig.Ret != I32 {
		t.Fatal("register-only fixture acquired caller inputs or a different result role")
	}
	strict := func(function Func) error {
		if x86StaticIntegerResultSourceCandidate(function, sig, arch) || function.x86SourceStack != nil ||
			function.x86FixedLocal != nil || len(function.X86RawText) != 0 {
			t.Fatal("register-only fixture accidentally selected another static/native/frame owner")
		}
		return checkX86ScalarFPResultInitialization(function, sig, arch)
	}
	lowered := func(function Func) error {
		consumer := amd64Ctx{fpScalarSource: function, sig: sig, fpSourceSig: sig,
			goarch: arch, targetTriple: x86AddressMemoryTargets(arch)[0]}
		return consumer.checkLoweredScalarFPResultInitialization()
	}
	return strict, lowered
}

func x86RegisterFloatReplaySource(row x86RawLegacyFloatCompareOracle, selector byte, producer string, raw bool) string {
	initialization := "PXOR X0,X0\nPXOR X1,X1\n"
	if producer == "immediate" {
		initialization = "MOVL $0x3f800000,AX\nMOVL AX,X0\nMOVL $0x40000000,CX\nMOVL CX,X1\n"
	}
	operation := fmt.Sprintf("%s X1,X0,$%d\n", row.op, int8(selector))
	if raw {
		operation = x86RawDisplacementDirectives(row.code(false, selector))
	}
	return "TEXT ·Value(SB),4,$0-4\n" + initialization + operation + "MOVL X0,ret+0(FP)\nRET\n"
}

// Unlike the native-pointer matrix, every input here comes from PXOR or an
// actual immediate GP→X transfer. Assert that the strict numeric observer
// succeeds, so a passing test cannot merely exercise the old fallback gate.
func TestX86RawLegacyFloatingCompareRegisterOnlyFastReplayAllSelectors(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		first := x86RegisterFloatReplaySource(x86RawLegacyFloatCompareOracles[0], 0, "xor", false)
		strict, check := x86RegisterReplayConsumers(t, arch, first)
		for _, row := range x86RawLegacyFloatCompareOracles {
			for _, producer := range []string{"xor", "immediate"} {
				for selector := 0; selector < 256; selector++ {
					t.Run(fmt.Sprintf("%s/%s/%s/selector=%03d", arch, row.op, producer, selector), func(t *testing.T) {
						source := x86RegisterFloatReplaySource(row, byte(selector), producer, true)
						original, ordinal := x86LegacyFloatReplayOriginal(t, arch, source)
						if err := check(original); err != nil {
							t.Fatal("fully initialized original register producer rejected before any mutation", err)
						}
						named := mustParseX86RawReturn(t, x86RegisterFloatReplaySource(row, byte(selector), producer, false)).Funcs[0]
						if strict(named) != nil || check(named) != nil || named.x86RawReplay != nil {
							t.Fatal("genuine named register-only source lost its unchanged strict input domain")
						}
						changed := original
						changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
						changed.Instrs[ordinal].x86SourceRaw = nil
						if err := strict(changed); err != nil {
							t.Fatal("fixture did not reach the strict-success shortcut under review", err)
						}
						if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("strict numeric success bypassed immutable original compare replay", err)
						}
					})
				}
			}
		}
	}
}

func TestX86RawLegacyFloatingCompareRegisterOnlyGoObjectsAndInputBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		first := x86RegisterFloatReplaySource(x86RawLegacyFloatCompareOracles[0], 0, "xor", false)
		_, check := x86RegisterReplayConsumers(t, arch, first)
		var object strings.Builder
		ordinal := 0
		for _, row := range x86RawLegacyFloatCompareOracles {
			for _, producer := range []string{"xor", "immediate"} {
				for _, raw := range []bool{false, true} {
					source := x86RegisterFloatReplaySource(row, 255, producer, raw)
					fmt.Fprintf(&object, "%s", strings.Replace(source, "·Value", fmt.Sprint("·Register", ordinal), 1))
					ordinal++
					t.Run(fmt.Sprintf("%s/%s/%s/raw=%t", arch, row.op, producer, raw), func(t *testing.T) {
						producerLine := "PXOR X0,X0\n"
						if producer == "immediate" {
							producerLine = "MOVL $0x3f800000,AX\n"
						}
						missing := strings.Replace(source, producerLine, "", 1)
						function := mustParseX86RawReturn(t, missing).Funcs[0]
						if raw {
							function, _ = x86LegacyFloatReplayOriginal(t, arch, missing)
						}
						if err := check(function); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("replay or a strict-success shortcut manufactured missing GP/vector input bytes", err)
						}
					})
				}
			}
		}
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], object.String())
	}
}

func TestX86ScalarShiftArchitecturalChoiceRegisterOnlyFastReplay(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		first := "TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nMOVL AX,ret+0(FP)\nRET\n"
		strict, check := x86RegisterReplayConsumers(t, arch, first)
		for _, operation := range []struct {
			name string
			code []byte
		}{
			{"SHLL $1,AX", []byte{0xd1, 0xe0}}, {"SHRL $1,AX", []byte{0xd1, 0xe8}},
			{"SARL $1,AX", []byte{0xd1, 0xf8}}, {"ROLL $1,AX", []byte{0xd1, 0xc0}},
			{"RORL $1,AX", []byte{0xd1, 0xc8}}, {"RCLL $1,AX", []byte{0xd1, 0xd0}},
			{"RCRL $1,AX", []byte{0xd1, 0xd8}},
		} {
			t.Run(arch+"/"+operation.name, func(t *testing.T) {
				prefix := "TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nSTC\n"
				suffix := "MOVL AX,ret+0(FP)\nRET\n"
				named := mustParseX86RawReturn(t, prefix+operation.name+"\n"+suffix).Funcs[0]
				if strict(named) != nil || check(named) != nil {
					t.Fatal("initialized strict named scalar producer control rejected")
				}
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, prefix+x86RawDisplacementDirectives(operation.code)+suffix), arch)
				if err != nil {
					t.Fatal("original scalar opcode decoding prerequisite", err)
				}
				original, ordinal := file.Funcs[0], -1
				for index, ins := range original.Instrs {
					if x86RawLegacyScalarShiftSource(ins, arch) {
						ordinal = index
					}
				}
				if ordinal < 0 || original.x86RawReplay == nil || check(original) != nil {
					t.Fatal("initialized original scalar producer lost its complete replay")
				}
				changed := original
				changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
				changed.Instrs[ordinal].x86SourceRaw = nil
				if err := strict(changed); err != nil {
					t.Fatal("scalar fixture did not reach strict numeric success", err)
				}
				if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("strict scalar result bypassed immutable original producer replay", err)
				}
			})
		}
	}
}
