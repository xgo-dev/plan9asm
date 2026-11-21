package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestARM64AtomicCASNamedAndEncoded(t *testing.T) {
	const text = "TEXT atomics(SB),4,$0-0\n"
	var original, named, raw strings.Builder
	original.WriteString(text)
	named.WriteString(text)
	raw.WriteString(text)
	type row struct {
		effect   string
		rawOrder uint32
	}
	var forms []row
	for size, width := range []string{"B", "H", "W", "D"} {
		for _, order := range []struct {
			suffix, normal, discard string
			bits                    uint32
		}{
			{"", "monotonic monotonic", "monotonic monotonic", 0},
			{"A", "acquire acquire", "monotonic monotonic", 1 << 22},
			{"L", "release monotonic", "release monotonic", 1 << 15},
			{"AL", "acq_rel acquire", "release monotonic", 1<<22 | 1<<15},
		} {
			for _, registers := range []struct {
				args, effects string
			}{
				{"R5,(R6),R7", order.normal},
				{"ZR,(RSP),R7", order.discard},
				{"R5,(ZR),ZR", order.normal},
			} {
				supported := size >= 2 || order.suffix == "" || order.suffix == "AL"
				name := fmt.Sprintf("CAS%s%s %s\n", order.suffix, width, registers.args)
				oracle := name
				var rawOrder uint32
				if !supported {
					// Go exposes both order bits together for the narrow
					// rows. Assemble the relaxed row and select one bit
					// for the architecturally defined WORD-only forms.
					oracle = fmt.Sprintf("CAS%s %s\n", width, registers.args)
					rawOrder = order.bits
				} else {
					named.WriteString(name)
				}
				original.WriteString(oracle)
				forms = append(forms, row{fmt.Sprintf("i%d %s", 8<<size, registers.effects), rawOrder})
			}
		}
	}
	original.WriteString("RET\n")
	code := arm64ImmediateOriginalGoBytes(t, original.String(), "linux")
	end := len(forms) * 4
	if len(code) < end+4 || binary.LittleEndian.Uint32(code[end:]) != 0xd65f03c0 {
		t.Fatalf("Go CAS oracle did not emit %d instructions and RET", len(forms))
	}
	var namedEffects, rawEffects []string
	for i, form := range forms {
		word := binary.LittleEndian.Uint32(code[4*i:])
		fmt.Fprintf(&raw, "WORD $0x%08x\n", word|form.rawOrder)
		rawEffects = append(rawEffects, form.effect)
		if form.rawOrder == 0 {
			namedEffects = append(namedEffects, form.effect)
		}
	}
	named.WriteString("RET\n")
	raw.WriteString("RET\n")
	for _, fixture := range []struct {
		name, source string
		want         []string
	}{
		{"named", named.String(), namedEffects},
		{"encoded", raw.String(), rawEffects},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ll := arm64AtomicMatrixIR(t, fixture.source)
			var got []string
			for _, line := range strings.Split(ll, "\n") {
				if _, effects, found := strings.Cut(line, " = cmpxchg "); found {
					fields := strings.Fields(effects)
					if len(fields) < 8 {
						t.Fatalf("incomplete cmpxchg: %s", line)
					}
					got = append(got, fields[2]+" "+fields[6]+" "+strings.TrimSuffix(fields[7], ","))
				}
			}
			if strings.Join(got, "|") != strings.Join(fixture.want, "|") {
				t.Fatalf("CAS width or ordering differs\ngot  %v\nwant %v", got, fixture.want)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc is required")
			}
			compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "cas.ll", "cas.o", ll)
		})
	}
}

func TestARM64AtomicLoadStoreOriginalWords(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT atomics(SB),4,$0-0\n")
	for _, width := range []string{"B", "H", "W", ""} {
		fmt.Fprintf(&source, "LDAR%s (R6),R7\nSTLR%s R5,(R6)\n", width, width)
		fmt.Fprintf(&source, "LDAR%s (ZR),ZR\nSTLR%s ZR,(RSP)\n", width, width)
	}
	source.WriteString("RET\n")
	code := arm64ImmediateOriginalGoBytes(t, source.String(), "linux")
	if len(code) < 68 || binary.LittleEndian.Uint32(code[64:]) != 0xd65f03c0 {
		t.Fatal("Go ordered-load/store oracle did not emit 16 instructions and RET")
	}
	var raw strings.Builder
	raw.WriteString("TEXT atomics(SB),4,$0-0\n")
	for i := 0; i < 64; i += 4 {
		fmt.Fprintf(&raw, "WORD $0x%08x\n", binary.LittleEndian.Uint32(code[i:]))
	}
	raw.WriteString("RET\n")
	_, namedIR, _ := strings.Cut(arm64AtomicMatrixIR(t, source.String()), "target triple")
	_, rawIR, _ := strings.Cut(arm64AtomicMatrixIR(t, raw.String()), "target triple")
	if namedIR == "" || namedIR != rawIR {
		t.Fatalf("named and encoded ordered memory effects differ\nnamed:\n%s\nencoded:\n%s", namedIR, rawIR)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "ordered-memory.ll", "ordered-memory.o", "target triple"+rawIR)
}

func TestARM64AtomicReleaseStoreUpdatesStackControl(t *testing.T) {
	for _, width := range []string{"B", "H", "W", ""} {
		source := fmt.Sprintf("TEXT atomics(SB),4,$0-0\nSTLR%s R5,(ZR)\nRET\n", width)
		code := arm64ImmediateOriginalGoBytes(t, source, "linux")
		for _, assembly := range []string{source, fmt.Sprintf("TEXT atomics(SB),4,$0-0\nWORD $0x%08x\nRET\n", binary.LittleEndian.Uint32(code))} {
			file, err := Parse(ArchARM64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			ins := arm64ControlDecode(file.Funcs[0].Instrs[1])
			state := arm64ControlState{
				regs: map[Reg]arm64ControlValue{
					SP: arm64ControlFromMap(map[string]bool{"sp:0": true}),
				},
				memory: map[string]arm64ControlValue{
					"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true}),
				},
				unexposedSP: true,
			}
			state.transfer(ins, arm64ControlOp(ins), false, nil)
			if !arm64ControlHas(state.memory["sp:0"], "") {
				t.Errorf("%s: release store left a stale caller-link proof", ins.Raw)
			}
		}
	}
}

func arm64AtomicMatrixIR(t *testing.T, source string) string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"atomics": {Name: "atomics", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ll
}

func arm64AtomicCASCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT atomicCASComplete(SB),$0-0\n")
	for _, width := range []string{"B", "H", "W", "D"} {
		orders := []string{"", "AL"}
		if width == "W" || width == "D" {
			orders = []string{"", "A", "L", "AL"}
		}
		for _, order := range orders {
			opcode := "CAS" + order + width
			source.WriteString("\t" + opcode + " R5, (R6), R7\n")
			source.WriteString("\t" + opcode + " ZR, (RSP), ZR\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64AtomicCASCompleteFormats(t *testing.T) {
	source := arm64AtomicCASCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"atomicCASComplete": {Name: "atomicCASComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cmpxchg ptr", " i8 ", " i16 ", " i32 ", " i64 ",
		" monotonic monotonic", " acquire acquire", " release monotonic", " acq_rel acquire",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 complete CAS lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-cas-complete.ll", "arm64-cas-complete.o", ll)
}

func TestTranslateARM64AtomicCASRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"CASD R0, 8(R1), R2", "CASW R0, (R1)", "CASQ R0, (R1), R2", "CASAB R0,(R1),R2", "CASLH R0,(R1),R2"} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: arm64LinuxGNUTriple,
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 LSE CAS optab", instruction)
		}
	}
}
