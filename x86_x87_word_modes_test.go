package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86X87HardwareWordRead(t *testing.T, ir string, expected int) {
	t.Helper()
	count := 0
	for _, line := range strings.Split(ir, "\n") {
		if !strings.Contains(line, `asm sideeffect "fnstcw $0"`) {
			continue
		}
		if !strings.Contains(line, `"=*m,~{dirflag},~{fpsr},~{flags}"`) || !strings.Contains(line, "elementtype(i16)") {
			t.Fatal("actual control capture lost its complete i16 write constraint", line)
		}
		count++
	}
	if count != expected {
		t.Fatal("actual hardware control reads differ from full source inventory", count, expected)
	}
}

func x86X87SoftwareControlRoundTrip(t *testing.T, ir string) {
	t.Helper()
	if strings.Contains(ir, "fnstcw") || strings.Contains(ir, "fldcw") {
		t.Fatal("explicit Software mode borrowed an actual hardware word operation")
	}
	for index, input := range []uint16{0, 0xffff, 0x5a5a} {
		name := fmt.Sprintf("ControlInput%d", index)
		probe := fmt.Sprintf("\ndefine i16 @%s() {\n %%r = call i16 @Value(i16 %d)\n ret i16 %%r\n}\n", name, input)
		x86ScalarFPNamedConstantResult(t, ir+probe, name, []uint64{uint64(input)})
	}
}

func x86X87HardwareCaptureBody(kind string, result int) string {
	prefix := ""
	if strings.HasPrefix(kind, "load-") {
		prefix = "FLDCW input+0(FP)\n"
	}
	if strings.HasSuffix(kind, "param") {
		return prefix + "FSTCW input+0(FP)\nMOVW input+0(FP),AX\n" + fmt.Sprintf("MOVW AX,ret+%d(FP)\nRET\n", result)
	}
	return prefix + fmt.Sprintf("FSTCW ret+%d(FP)\nRET\n", result)
}

func TestX86X87HardwareControlCaptureNeedsNoSyntheticDefaultThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		result := 8
		if target.arch == "386" {
			result = 4
		}
		for _, kind := range []string{"entry-result", "entry-param", "load-result", "load-param"} {
			const declaration = "func Value(input uint16) uint16"
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, x86X87HardwareCaptureBody(kind, result))
			for _, mode := range []X87Mode{X87Auto, X87Hardware} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/mode%d/%s", target.triple, kind, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, mode)
						if err != nil || ir == "" {
							t.Fatal("actual hardware word capture lost its existing storage role", err)
						}
						x86X87HardwareWordRead(t, ir, 1)
						if strings.HasPrefix(kind, "load-") && !strings.Contains(ir, `asm sideeffect "fldcw $0"`) {
							t.Fatal("known typed input was not applied through the actual control-word emitter")
						}
						// Ambient hardware control is not a fixed 0x037f value.
					})
				}
			}
		}
	}
}

func TestX86X87TypedCallInitRestoresWordsNotValuesThreeAPIs(t *testing.T) {
	for _, row := range []struct {
		name, prefix string
		good         bool
	}{
		{"independent-void-call-init", "CALL ·notify(SB)\nFINIT\n", true},
		{"call-does-not-initialize-status", "CALL ·notify(SB)\n", false},
		{"init-does-not-initialize-F0", "CALL ·notify(SB)\nFINIT\nFTST\n", false},
		{"unknown-call-stays-unclosed", "CALL ·unknown(SB)\nFINIT\n", false},
	} {
		source := "TEXT ·probe(SB),4,$0-5\n" + row.prefix +
			"FSTSW AX\nTESTW AX,AX\nSETEQ ret+4(FP)\nRET\nTEXT ·notify(SB),4,$0-0\nRET\n"
		for _, target := range x86RawReturnTargets {
			if target.arch != "386" {
				continue // This existing typed CALL contract is mode32 only.
			}
			for _, mode := range []X87Mode{X87Auto, X87Software} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/mode%d/%s", target.triple, row.name, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, x86ABI0BoolVoidCallDeclarations,
							target.arch, target.triple, api, mode)
						if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
							t.Fatal("FINIT changed CALL authority or invented x87 values", row.good, len(ir), err)
						}
					})
				}
			}
		}
	}
}

func TestX86X87ControlLoadsNeedOnlyTheirDefinedBoundWord(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		result, move := 8, "MOVQ"
		if target.arch == "386" {
			result, move = 4, "MOVL"
		}
		for _, row := range []struct {
			name, declaration, body string
			good                    bool
		}{
			{"known-AUTO", "func Value(input uint16) uint16", "MOVW input+0(FP),AX\nMOVW AX,control-2(SP)\nFLDCW control-2(SP)\n", true},
			{"unknown-AUTO", "func Value(input uint16) uint16", "FLDCW control-2(SP)\n", false},
			{"partial-AUTO", "func Value(input uint16) uint16", "MOVB $1,control-2(SP)\nFLDCW control-2(SP)\n", false},
			{"pointer-is-not-word-backing", "func Value(input *byte) uint16", move + " input+0(FP),BX\nFLDCW (BX)\n", false},
		} {
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, row.declaration,
				row.body+fmt.Sprintf("FSTCW ret+%d(FP)\nRET\n", result))
			// The logical AUTO role requires an original positive bounded TEXT,
			// not a zero-frame access or a guessed physical stack allocation.
			source = strings.Replace(source, ",4,$0-", ",4,$4-", 1)
			for _, mode := range []X87Mode{X87Auto, X87Hardware, X87Software} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/mode%d/%s", target.triple, row.name, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, row.declaration, target.arch, target.triple, api, mode)
						if !row.good {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("control load invented source bytes or native backing", len(ir), err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("complete known AUTO word was treated as unknown environment state", err)
						}
						if mode == X87Software {
							x86X87SoftwareControlRoundTrip(t, ir)
						} else {
							x86X87HardwareWordRead(t, ir, 1)
						}
					})
				}
			}
		}
	}
}
