package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ImmediateTestInstruction(t *testing.T, text string) Instr {
	t.Helper()
	file, err := Parse(ArchARM64, "TEXT scratch(SB),4,$0-0\n"+text+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestARM64GPImmediateGoOperandClasses(t *testing.T) {
	for _, tc := range []struct {
		text    string
		valid   bool
		scratch bool
	}{
		{"ADD $4096,R27,R1", true, false},
		{"ADD $0x123456,R27,R1", true, false},
		{"ADDS $0x123456,R27,R1", false, false},
		{"ADD $0x1234,R27,R1", false, false},
		{"ADD $0x1234,R27", true, true},
		{"EON $0x1234,R27", true, true},
		{"AND $1,R0,ZR", true, true},
		{"ANDS $1,R0,ZR", true, false},
		{"BICS $1,R0,ZR", true, false},
		{"AND $1,R0,RSP", true, false},
		{"AND $0x1234,R0,RSP", false, false},
		{"AND $1,RSP", false, false},
		{"ADD $1,R0,ZR", false, false},
		{"ADDS $1,R0,ZR", false, false},
		{"CMP $4096,R27", true, false},
		{"CMP $0x1234,R27", false, false},
		{"CMP $0x1234,RSP", true, true},
		{"CMP $0x123456,RSP", false, false},
		{"CMP $0,ZR", false, false},
		{"CMN $-1,ZR", false, false},
		{"CMPW $0,ZR", true, true},
		{"CMNW $-1,ZR", true, true},
		{"TST $1,ZR", true, false},
		{"TST $0x1234,ZR", true, true},
		{"ADDW $0x123456789abcdef,R0,R1", true, true},
		{"ANDW $0x123456789abcdef,R0,R1", true, true},
		{"ADDS $1,R0,RSP", false, false},
		{"ADD $1,ZR,R0", false, false},
		{"CMP $1,R0,R1", false, false},
		{"ADD $1.5,R0,R1", false, false},
		{"ADD $missing,R0,R1", false, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, "TEXT classes(SB),4,$0-0\n"+tc.text+"\nRET\n", tc.valid)
			ins := arm64ImmediateTestInstruction(t, tc.text)
			before := ins
			form, handled, err := parseARM64GPImmediateForm(ins.Op, ins)
			if !handled && !tc.valid {
				_, handled, err = parseARM64GPDataForm(ins.Op, ins)
			}
			if !handled || (err == nil) != tc.valid || tc.valid && form.scratch != tc.scratch {
				t.Fatalf("class/REGTMP mismatch: handled=%v form=%+v error=%v", handled, form, err)
			}
			if !reflect.DeepEqual(ins, before) {
				t.Fatal("validation mutated the original instruction")
			}
			if handled && err != nil && ins.Args[0].Kind == OpImm {
				var output strings.Builder
				context := &arm64Ctx{b: &output}
				if handled, _, err := context.lowerARM64GPImmediate(ins.Op, ins); !handled || err == nil || output.Len() != 0 {
					t.Fatal("invalid immediate emitted IR before validation")
				}
			}
		})
	}
	ins := arm64ImmediateTestInstruction(t, "ADD $1,R0,R1")
	if _, handled, err := parseARM64GPImmediateForm("SUB", ins); !handled || err == nil {
		t.Fatal("conflicting dispatch identity supplied a Go encoder proof")
	}
}

func TestARM64GPImmediateScratchIndependentProvenance(t *testing.T) {
	for _, suffix := range []string{"", "W"} {
		for _, op := range []string{"ADD", "ADDS", "SUB", "SUBS", "CMP", "CMN", "AND", "ANDS", "BIC", "BICS", "ORR", "ORN", "EOR", "EON", "TST"} {
			text := op + suffix + " $0x1234,R0"
			if op != "CMP" && op != "CMN" && op != "TST" {
				text += ",R1"
			}
			ins := arm64ImmediateTestInstruction(t, text)
			control := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R0": arm64ControlFromMap(map[string]bool{"label:actual_code": true}), "R27": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})},
				memory: make(map[string]arm64ControlValue),
			}
			control.transfer(ins, ins.Op, false, nil)
			if arm64ControlCount(arm64ControlLabels(control.regs["R27"])) != 0 {
				t.Fatalf("%s scratch inherited source/old-R27 code provenance", text)
			}
			if strings.HasSuffix(text, ",R1") && arm64ControlCount(arm64ControlLabels(control.regs["R1"])) == 0 {
				t.Fatalf("%s actual result lost its code-derived source", text)
			}
			address := arm64PrivateFrameAddress{offset: 16, exact: true}
			readOnly := arm64PrivateFrameAddresses{"R27": address}
			raw := &arm64RawPrivateFrameState{regs: readOnly.clone(), spills: make(map[int64]arm64PrivateFrameAddress)}
			if !readOnly.transfer(ins, 64) || !raw.transfer(ins, ins, 64) {
				t.Fatalf("%s dead scratch address was still consumed", text)
			}
			if _, present := readOnly["R27"]; present {
				t.Fatalf("%s stale read-only frame provenance", text)
			}
			if _, present := raw.regs["R27"]; present {
				t.Fatalf("%s stale raw frame provenance", text)
			}
			numeric := newARM64PrivateDataState()
			numeric.regs["R27"] = arm64PrivateDataValue{frame: true, interval: arm64PoolInterval{8, 8}}
			numeric.comparison = arm64PrivateDataCompare{valid: true, leftReg: "R27"}
			if _, valid := numeric.transfer(ins, 0, 64); !valid {
				t.Fatalf("%s failed numeric scratch transfer", text)
			}
			value := numeric.value("R27")
			if value.frame || value.interval != (arm64PoolInterval{0x1234, 0x1234}) {
				t.Fatalf("%s scratch was not an independent exact constant: %+v", text, value)
			}
			if numeric.comparison.valid && numeric.comparison.leftReg == "R27" {
				t.Fatalf("%s retained a stale bound comparison", text)
			}
		}
	}
	for _, text := range []string{"ADD $1,R27,R1", "ADD $0x123456,R27,R1", "AND $255,R27,R1"} {
		ins := arm64ImmediateTestInstruction(t, text)
		state := &arm64ControlState{regs: map[Reg]arm64ControlValue{"R27": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})}, memory: make(map[string]arm64ControlValue)}
		state.transfer(ins, ins.Op, false, nil)
		if arm64ControlCount(arm64ControlLabels(state.regs["R27"])) == 0 || arm64ControlCount(arm64ControlLabels(state.regs["R1"])) == 0 {
			t.Fatalf("non-TMP encoding killed a genuine source witness: %s", text)
		}
	}
}

func TestARM64GPImmediateScratchWholeCallerContext(t *testing.T) {
	pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch()\n")
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	for _, suffix := range []string{"", "W"} {
		for _, base := range []string{"ADD", "ADDS", "SUB", "SUBS", "CMP", "CMN", "AND", "ANDS", "BIC", "BICS", "ORR", "ORN", "EOR", "EON", "TST"} {
			text := base + suffix + " $0x1234,R0"
			if base != "CMP" && base != "CMN" && base != "TST" {
				text += ",R1"
			}
			source := "TEXT ·Scratch(SB),4,$0-0\nMOVD R30,R27\nMOVD $17,R0\n" + text + "\nMOVD R27,R30\nRET\n"
			requireARM64GoAssemblerResult(t, source, true) // Compile only: deliberately invalid continuation.
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
				opt := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: map[string]FuncSig{"Scratch": {Name: "Scratch", Ret: Void}}}
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %s stale LR accepted by Translate: %v", target, text, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					ctx.Dispose()
					t.Fatalf("%s %s stale LR accepted by Module: %v", target, text, err)
				}
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %s stale LR accepted by GoModule: %v", target, text, err)
				}
			}
		}
	}
}

func TestARM64GPImmediateEncodedOriginCannotBeForged(t *testing.T) {
	for _, word := range []uint32{0x9100041b, 0xb100041f, 0xf10007ff, 0x92401c1b} {
		original := arm64ImmediateTestInstruction(t, fmt.Sprintf("WORD $%#x", word))
		decoded, err := decodeARM64RawWordInstruction(original)
		if err != nil || !decoded.arm64Encoded {
			t.Fatalf("real WORD origin missing: %v", err)
		}
		if _, handled, err := parseARM64GPImmediateForm(decoded.Op, decoded); handled || err != nil {
			t.Fatalf("raw architectural instruction selected source pseudo expansion: %+v %v", decoded, err)
		}
		normalized, err := normalizeARM64RawPCRelative(Func{Instrs: []Instr{decoded}})
		if err != nil || len(normalized.Instrs) != 1 || !normalized.Instrs[0].arm64Encoded {
			t.Fatalf("normalization lost authenticated WORD origin: %v", err)
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		var supplied Instr
		if err := json.Unmarshal(encoded, &supplied); err != nil {
			t.Fatal(err)
		}
		if supplied.arm64Encoded {
			t.Fatal("public JSON acquired private raw origin")
		}
	}
	ins := arm64ImmediateTestInstruction(t, "ADDS $1,R0,ZR")
	ins.Raw = "WORD $0xb100041f"
	if _, handled, err := parseARM64GPImmediateForm(ins.Op, ins); !handled || err == nil {
		t.Fatal("forged source Raw text bypassed Go register classes")
	}
}

func TestARM64GPImmediateRawPCWidthUsesActualGoRows(t *testing.T) {
	for _, text := range []string{"AND $1,R0,ZR", "AND $4096,R0,ZR", "ANDW $1,R0,ZR", "ANDW $4096,R0,ZR"} {
		ins := arm64ImmediateTestInstruction(t, text)
		if width, known := arm64RawKnownSourceWidth(Func{}, ins); known {
			t.Errorf("multiword source acquired physical width %d: %s", width, text)
		}
		// The genuine raw address reaches +8. Assuming a four-byte source
		// pseudo would falsely resolve that PC to the following RET label.
		source := "TEXT uncertain(SB),4,$0-0\nWORD $0x10000040\n" + text + "\ntarget:\nRET\n"
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err == nil {
			t.Errorf("raw ADR acquired a guessed label across multiword source: %s", text)
		}
	}
	for _, text := range []string{"AND $255,R0,R1", "ANDS $255,R0,ZR", "TST $255,ZR"} {
		if width, known := arm64RawKnownSourceWidth(Func{}, arm64ImmediateTestInstruction(t, text)); !known || width != 4 {
			t.Fatalf("direct one-word Go row lost exact width: %s", text)
		}
	}
	decoded, err := decodeARM64RawWordInstruction(arm64ImmediateTestInstruction(t, "WORD $0x92401c1f"))
	if err != nil {
		t.Fatal(err)
	}
	if width, known := arm64RawKnownSourceWidth(Func{}, decoded); !known || width != 4 {
		t.Fatal("actual raw logical WORD lost its physical four-byte width")
	}
}

func TestARM64GPImmediateSourceEncoderContext(t *testing.T) {
	pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch()\n")
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	for _, base := range []string{"CMP", "CMN", "AND", "BIC", "ORR", "ORN", "EOR", "EON"} {
		text := base + " $0x00ff00ff00ff00ff,ZR"
		if base != "CMP" && base != "CMN" {
			text = base + " $0x00ff00ff00ff00ff,R0,ZR"
		}
		source := "TEXT ·Scratch(SB),4,$0-0\n" + text + "\nRET\n"
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
			opt := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: map[string]FuncSig{"Scratch": {Name: "Scratch", Ret: Void}}}
			if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s Translate version-dependent fallback %s: %v", target, text, err)
			}
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err == nil {
				module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				ctx.Dispose()
				t.Fatalf("%s Module version-dependent fallback %s: %v", target, text, err)
			}
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
			if err == nil {
				bound.Module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s GoModule version-dependent fallback %s: %v", target, text, err)
			}
		}
	}
}
