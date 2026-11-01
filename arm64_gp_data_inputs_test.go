package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// All rows of the ADD, AND/ANDS, NEG, MVN, LSL, SXTB and BFI
// families, including their registered W/flags aliases. Rd is R9 here so
// stock Go can validate the spelling without special raw g-register words.
func arm64GPDataForms() []string {
	var forms []string
	for _, op := range []string{"ADD", "ADDS", "SUB", "SUBS", "ADDW", "ADDSW", "SUBW", "SUBSW"} {
		for _, source := range []string{"R4", "$17", "R4<<1", "R4.UXTB<<1"} {
			forms = append(forms, op+" "+source+",R5,R9", op+" "+source+",R9")
		}
	}
	for _, op := range []string{"AND", "ANDW", "EOR", "EORW", "ORR", "ORRW", "BIC", "BICW", "EON", "EONW", "ORN", "ORNW", "ANDS", "ANDSW", "BICS", "BICSW"} {
		for _, source := range []string{"R4", "$17", "R4<<1"} {
			forms = append(forms, op+" "+source+",R5,R9", op+" "+source+",R9")
		}
	}
	for _, op := range []string{"LSL", "LSLW", "LSR", "LSRW", "ASR", "ASRW", "ROR", "RORW"} {
		for _, source := range []string{"$1", "R4"} {
			forms = append(forms, op+" "+source+",R5,R9", op+" "+source+",R9")
		}
	}
	for _, op := range []string{"NEG", "NEGW", "NEGS", "NEGSW", "MVN", "MVNW"} {
		forms = append(forms, op+" R4,R9", op+" R4<<1,R9")
	}
	for _, op := range []string{"SXTB", "SXTBW", "SXTH", "SXTHW", "SXTW", "UXTB", "UXTBW", "UXTH", "UXTHW", "UXTW"} {
		forms = append(forms, op+" R4,R9")
	}
	for _, op := range []string{"BFI", "BFIW", "BFXIL", "BFXILW", "SBFIZ", "SBFIZW", "SBFX", "SBFXW", "UBFIZ", "UBFIZW", "UBFX", "UBFXW"} {
		forms = append(forms, op+" $1,R4,$7,R9")
	}
	return forms
}

func arm64GPDataReadsDestination(text string) bool {
	parts := strings.SplitN(text, " ", 2)
	count := len(strings.Split(parts[1], ","))
	op := parts[0]
	if strings.HasPrefix(op, "BFI") || strings.HasPrefix(op, "BFXIL") {
		return true
	}
	if strings.HasPrefix(op, "NEG") {
		return count == 1
	}
	if strings.HasPrefix(op, "MVN") || strings.HasPrefix(op, "SXT") || strings.HasPrefix(op, "UXT") || count == 4 {
		return false
	}
	return count == 2
}

func TestARM64GPDataTrueInputsAndFullOverwrite(t *testing.T) {
	for _, text := range arm64GPDataForms() {
		t.Run(text, func(t *testing.T) {
			source := "TEXT direction(SB),$0-0\n" + text + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			mayFrame := arm64PrivateFrameAddress{offset: -16, exact: true}
			state := &arm64RawPrivateFrameState{
				regs:   arm64PrivateFrameAddresses{"R9": mayFrame},
				spills: make(map[int64]arm64PrivateFrameAddress),
			}
			readOnly := arm64PrivateFrameAddresses{"R9": mayFrame}
			reads := arm64GPDataReadsDestination(text)
			affine := strings.HasPrefix(text, "ADD $") || strings.HasPrefix(text, "SUB $")
			if valid := state.transfer(ins, ins, 64); valid != (!reads || affine) {
				t.Fatalf("raw proof destination input=%v, transfer=%v", reads, valid)
			}
			if valid := readOnly.transfer(ins, 64); valid != (!reads || affine) {
				t.Fatalf("read-only proof destination input=%v, transfer=%v", reads, valid)
			}
			if !reads {
				if _, present := state.regs["R9"]; present {
					t.Fatal("known full overwrite retained a dead may-frame value")
				}
				if _, present := readOnly["R9"]; present {
					t.Fatal("read-only proof retained overwritten may-frame value")
				}
			}
			control := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R9": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})},
				memory: make(map[string]arm64ControlValue),
			}
			control.transfer(ins, ins.Op, false, nil)
			value := arm64ControlRead(control.regs, "R9")
			if arm64ControlCount(arm64ControlLabels(value)) != 0 != reads {
				t.Fatalf("continuation input direction mismatch: %v", value)
			}
		})
	}
}

func TestARM64GPDataFrameInputAliasesStayClosed(t *testing.T) {
	for _, text := range []string{
		"ADD R9,R5,R9", "ADD R4,R9,R9", "ADD R9<<1,R5,R9",
		"ADD R9.UXTB<<1,R5,R9", "LSL R9,R5,R9", "LSL $1,R9,R9",
		"SXTB R9,R9", "UBFX $1,R9,$7,R9", "BFI $1,R4,$7,R9",
		"BFXIL $1,R4,$7,R9", "NEG R9", "AND R4,R9",
	} {
		file, err := Parse(ArchARM64, "TEXT inputs(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64RawPrivateFrameState{
			regs:   arm64PrivateFrameAddresses{"R9": {offset: -16, exact: true}},
			spills: make(map[int64]arm64PrivateFrameAddress),
		}
		if state.transfer(file.Funcs[0].Instrs[1], file.Funcs[0].Instrs[1], 64) {
			t.Fatalf("true frame input was treated as dead Rd: %s", text)
		}
	}
}

func TestARM64GPDataSavedGOverwriteWholeSource(t *testing.T) {
	for _, text := range []string{"ADD R4,R5,R28", "LSL $1,R4,R28", "UXTB R4,R28", "UBFX $1,R4,$7,R28"} {
		body := "WORD $0xa9bf4bfc\n" + text + "\nMOVD R28,(R1)\nWORD $0xa8c14bfc\n"
		file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, body))
		if err != nil {
			t.Fatal(err)
		}
		sig := arm64RawZeroFrameSig()
		if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}}); err != nil {
			t.Fatalf("saved/restored g scratch false input: %s: %v", text, err)
		}
		for _, bad := range []string{
			strings.Replace(body, "WORD $0xa8c14bfc", "MOVD $0,R28", 1),
			strings.Replace(body, text, "MOVD RSP,R4\n"+text, 1),
		} {
			file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, bad))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}}); err == nil {
				t.Fatalf("fixed-g or actual frame input gained permission: %s", bad)
			}
		}
	}
}

func TestARM64GPDataMultiplyUsesExistingCompleteGrammar(t *testing.T) {
	for _, text := range arm64ControlMultiplyForms() {
		text = strings.ReplaceAll(text, "R30", "R9")
		file, err := Parse(ArchARM64, "TEXT multiply(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		state := &arm64RawPrivateFrameState{
			regs: arm64PrivateFrameAddresses{"R9": {}}, spills: make(map[int64]arm64PrivateFrameAddress),
		}
		readOnly := state.regs.clone()
		reads := len(ins.Args) == 2
		if state.transfer(ins, ins, 64) == reads || readOnly.transfer(ins, 64) == reads {
			t.Fatalf("multiply operand grammar differed between proofs: %s", text)
		}
	}
}

func TestARM64GPDataCopyJoinEscapeAndSavedIdentityRemainClosed(t *testing.T) {
	for _, body := range []string{
		"MOVD RSP,R9\nMOVD R9,R10\nADD R4,R5,R9\nMOVD R10,(R1)\nMOVD $0,R10",
		"MOVD RSP,R9\nCBZ R0,joined\nADD R4,R5,R9\njoined:\nMOVD R9,(R1)\nMOVD $0,R9",
		"MOVD RSP,R9\nMOVD R9,R10\nUBFX $1,R4,$7,R9\nMOVD R10,holder(SB)\nMOVD $0,R10",
		"MOVD RSP,R9\nBFI $1,R4,$7,R9\nMOVD R9,(R1)\nMOVD $0,R9",
		"WORD $0xa9bf4bfc\nADD R4,R5,R28\nMOVB R4,(RSP)\nWORD $0xa8c14bfc",
		"WORD $0xa9bf4bfc\nADD R4,R5,R28\nMOVD $0,R18\nADD $16,RSP",
	} {
		file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, body+"\nMOVD R4,(R1)\n"))
		if err != nil {
			t.Fatal(err)
		}
		sig := arm64RawZeroFrameSig()
		if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}}); err == nil {
			t.Fatalf("overwrite washed a copied/joined escape or caller identity: %s", body)
		}
	}
	for _, body := range []string{
		"MOVD RSP,R9\nADD R4,R5,R9\nMOVD R9,(R1)",
		"MOVD RSP,R9\nCBZ R0,other\nADD R4,R5,R9\nB joined\nother:\nUXTB R4,R9\njoined:\nMOVD R9,(R1)",
	} {
		file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, body+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		sig := arm64RawZeroFrameSig()
		if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}}); err != nil {
			t.Fatalf("all-path full overwrites did not close the may-frame scope: %s: %v", body, err)
		}
	}
}

func TestARM64GPDataCompleteGoFamiliesAndRows(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(bytes)
	fixtureNames := make(map[string]bool)
	for _, text := range arm64GPDataForms() {
		fixtureNames[strings.SplitN(text, " ", 2)[0]] = true
	}
	for _, family := range []struct {
		name string
		rows int
	}{
		{name: "AADD", rows: 24}, {name: "AAND", rows: 16},
		{name: "AANDS", rows: 16}, {name: "ANEG", rows: 3},
		{name: "AMVN", rows: 2}, {name: "ALSL", rows: 4},
		{name: "ASXTB", rows: 1}, {name: "ABFI", rows: 1},
	} {
		rows := regexp.MustCompile(`(?m)^\s*\{`+family.name+`, C_[A-Z0-9]+, C_[A-Z0-9]+, C_[A-Z0-9]+, C_[A-Z0-9]+,`).FindAllString(source, -1)
		if len(rows) != family.rows {
			t.Fatalf("Go %s rows changed: expected %d, got %d", family.name, family.rows, len(rows))
		}
		start := strings.Index(source, "case "+family.name+":")
		if start < 0 {
			t.Fatalf("Go %s alias registration missing", family.name)
		}
		block := source[start+len("case "+family.name+":"):]
		if end := strings.Index(block, "\n\t\tcase "); end >= 0 {
			block = block[:end]
		}
		names := []string{strings.TrimPrefix(family.name, "A")}
		for _, alias := range regexp.MustCompile(`oprangeset\(A([A-Z0-9]+), t\)`).FindAllStringSubmatch(block, -1) {
			names = append(names, alias[1])
		}
		for _, name := range names {
			if !fixtureNames[name] {
				t.Fatalf("Go %s alias has no actual-form fixture: %s", family.name, name)
			}
			delete(fixtureNames, name)
		}
	}
	if len(fixtureNames) != 0 {
		t.Fatalf("fixture opcodes lack source-table registration: %v", fixtureNames)
	}
	// The internal ANEG C_NONE row does not imply a public one-operand
	// spelling: Go's frontend puts that operand in From, not To. Preserve
	// this exact observed distinction instead of claiming a Go object passed.
	for _, op := range []string{"NEG", "NEGW", "NEGS", "NEGSW"} {
		requireARM64GoAssemblerResult(t, "TEXT internal(SB),$0-0\n"+op+" R9\nRET\n", false)
	}
}

func TestARM64GPDataShiftExtendImmediateAndInvalidAxes(t *testing.T) {
	for _, text := range []string{
		"ADD $4096,R5,R9", "ADD $0x100001,R5,R9", "ADD $0x12345678,R5,R9",
		"ADD $0x123456789abcdef,R5,R9", "ADD R4>>63,R5,R9", "ADDW R4->31,R5,R9",
		"AND $0xff00ff00,R5,R9", "AND $0x123456789abcdef,R5,R9", "MVN R4@>63,R9",
		"LSL $0,R5,R9", "LSL $63,R5,R9", "LSLW $31,R5,R9",
		"UBFX $63,R4,$1,R9", "BFIW $31,R4,$1,R9",
	} {
		requireARM64GoAssemblerResult(t, "TEXT axes(SB),$0-0\n"+text+"\nRET\n", true)
		file, err := Parse(ArchARM64, "TEXT axes(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseARM64GPDataForm(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1]); err != nil {
			t.Fatalf("actual Go operand axis rejected: %s: %v", text, err)
		}
	}
	for _, extension := range []string{"UXTB", "UXTH", "UXTW", "UXTX", "SXTB", "SXTH", "SXTW", "SXTX"} {
		for _, amount := range []int{0, 4} {
			text := fmt.Sprintf("ADD R4.%s<<%d,R5,R9", extension, amount)
			requireARM64GoAssemblerResult(t, "TEXT extension(SB),$0-0\n"+text+"\nRET\n", true)
		}
	}
	for _, text := range []string{
		"ADD.P R4,R5,R9", "ADD R4@>1,R5,R9", "ADDW R4<<32,R5,R9",
		"ADD R4.UXTW<<5,R5,R9", "ADD R4<<R5,R6,R9", "ADD F0,R5,R9",
		"AND R4.UXTW,R5,R9", "AND R4,RSP,R9", "LSL $64,R5,R9",
		"LSLW $32,R5,R9", "LSL (R4),R5,R9", "SXTB R4,(R9)",
		"UBFX $63,R4,$2,R9", "UBFX $0,R4,$0,R9",
		"UBFX $missing,R4,$1,R9", "ADD $1.5,R5,R9",
	} {
		requireARM64GoAssemblerResult(t, "TEXT invalid(SB),$0-0\n"+text+"\nRET\n", false)
		file, err := Parse(ArchARM64, "TEXT invalid(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			continue
		}
		ins := file.Funcs[0].Instrs[1]
		if _, handled, err := parseARM64GPDataForm(arm64ControlOp(ins), ins); !handled || err == nil {
			t.Fatalf("invalid operand supplied an overwrite proof: %s: %v", text, err)
		}
	}
	// Go's alias encoder accepts this W spelling, but its field crosses
	// the W bank boundary. The existing lowerer rejects it; it must not
	// become an address overwrite witness merely because asm accepts it.
	file, err := Parse(ArchARM64, "TEXT crossBank(SB),$0-0\nBFIW $31,R4,$2,R9\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	requireARM64GoAssemblerResult(t, "TEXT crossBank(SB),$0-0\nBFIW $31,R4,$2,R9\nRET\n", true)
	if _, _, err := parseARM64GPDataForm("BFIW", file.Funcs[0].Instrs[1]); err == nil {
		t.Fatal("cross-bank bitfield gained an overwrite proof")
	}
	for _, text := range []string{"REV R4,R9", "CLZ R4,R9", "MOVK $1,R9", "WORD $0xffffffff"} {
		file, err := Parse(ArchARM64, "TEXT unknown(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64RawPrivateFrameState{
			regs: arm64PrivateFrameAddresses{"R9": {}}, spills: make(map[int64]arm64PrivateFrameAddress),
		}
		if state.transfer(file.Funcs[0].Instrs[1], file.Funcs[0].Instrs[1], 64) {
			t.Fatalf("unregistered effects washed may-frame destination: %s", text)
		}
	}
}

func arm64GPDataFamilyFixture(t *testing.T) (*File, map[string]FuncSig, string) {
	t.Helper()
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, form := range arm64GPDataForms() {
		name := fmt.Sprintf("gpDataCaller%d", index)
		body := "WORD $0xa9bf4bfc\nMOVD (R0),R4\nMOVD 8(R0),R5\n"
		if arm64GPDataReadsDestination(form) {
			body += "MOVD 16(R0),g\n"
		}
		body += strings.ReplaceAll(form, "R9", "g") + "\nMOVD g,(R1)\nWORD $0xa8c14bfc\n"
		source.WriteString(strings.Replace(arm64RawZeroFrameFixture(516, false, body), "rawZero", name, 1))
		sig := arm64RawZeroFrameSig()
		sig.Name = name
		sigs[name] = sig
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	return file, sigs, source.String()
}

func TestARM64GPDataAllFormsFiveTargetObjects(t *testing.T) {
	file, sigs, _ := arm64GPDataFamilyFixture(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "gp-data.ll", "gp-data.o", ir)
	}
}
