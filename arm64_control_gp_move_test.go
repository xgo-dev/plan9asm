package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestARM64ControlGPMoveUnsignedLiteralHasNoEncoderWitness(t *testing.T) {
	// Go 1.27 accepts the inherited MOVCON rows, but omovconst leaves
	// nonzero MOVWU move-wide literals as zero WORDs. Keep the emitted
	// object as evidence; never execute its undefined instruction here.
	for _, literal := range []int64{-601, 806, 0x12340000} {
		dir := t.TempDir()
		path := filepath.Join(dir, "unsigned.s")
		source := fmt.Sprintf("TEXT unsigned(SB),516,$0-0\nMOVWU $%d,R30\nRET\n", literal)
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("go", "tool", "asm", "-S", "-o", filepath.Join(dir, "unsigned.o"), path)
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("actual Go MOVWU inherited literal row: %v\n%s", err, output)
		}
		if !regexp.MustCompile(`(?m)^\s*0x0000 00 00 00 00 c0 03 5f d6`).Match(output) {
			t.Fatalf("Go MOVWU literal encoder changed; audit before granting overwrite: %d\n%s", literal, output)
		}
	}
}

func TestARM64ControlGPMoveCompleteRegisterRows(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(bytes)
	for _, family := range []string{"AMOVB", "AMOVH", "AMOVW"} {
		row := regexp.MustCompile(`(?m)^\s*\{` + family + `, C_ZREG, C_NONE, C_NONE, C_ZREG,(?: C_NONE,)? 45,`)
		if len(row.FindAllString(source, -1)) != 1 {
			t.Fatalf("Go narrow GP move row changed: %s", family)
		}
		alias := regexp.MustCompile(`case ` + family + `:\s*\n\s*oprangeset\(` + family + `U, t\)`)
		if !alias.MatchString(source) {
			t.Fatalf("Go narrow unsigned alias changed: %s", family)
		}
	}
	for _, class := range []string{"C_RSP", "C_ZREG"} {
		row := regexp.MustCompile(`(?m)^\s*\{AMOVD, ` + class + `, C_NONE, C_NONE, ` + class + `,(?: C_NONE,)? 24,`)
		if len(row.FindAllString(source, -1)) != 1 {
			t.Fatalf("Go full GP copy row changed: %s", class)
		}
	}
	for _, op := range []string{"AMOVD", "AMOVW"} {
		for _, class := range []string{"C_MBCON", "C_MOVCON", "C_BITCON"} {
			row := regexp.MustCompile(`(?m)^\s*\{` + op + `, ` + class + `, C_NONE, C_NONE, C_(?:ZREG|RSP),(?: C_NONE,)? 32,`)
			if len(row.FindAllString(source, -1)) != 1 {
				t.Fatalf("Go single-instruction literal move row changed: %s/%s", op, class)
			}
		}
	}
}

func TestARM64ControlGPMoveReadsSourceNotOldDestination(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, source := range []string{"R4", "ZR", "$0"} {
			text := op + " " + source + ",R30"
			requireARM64GoAssemblerResult(t, "TEXT move(SB),$0-0\n"+text+"\nRET\n", true)
			file, err := Parse(ArchARM64, "TEXT move(SB),$0-0\n"+text+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R30": arm64ControlFromMap(map[string]bool{"label:caller": true})},
				memory: make(map[string]arm64ControlValue),
			}
			ins := file.Funcs[0].Instrs[1]
			state.transfer(ins, ins.Op, false, nil)
			if value := arm64ControlRead(state.regs, "R30"); arm64ControlCount(value) != 1 || !arm64ControlHas(value, "") {
				t.Errorf("write-only destination kept old caller code: %s: %v", text, value)
			}
		}
	}
	for _, op := range []string{"MOVW", "MOVD"} {
		for _, value := range []int64{-601, 806, 0x12340000, 0x12345678} {
			text := fmt.Sprintf("%s $%d,R30", op, value)
			requireARM64GoAssemblerResult(t, "TEXT move(SB),$0-0\n"+text+"\nRET\n", true)
			file, err := Parse(ArchARM64, "TEXT move(SB),$0-0\n"+text+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			state := &arm64ControlState{regs: map[Reg]arm64ControlValue{"R30": arm64ControlFromMap(map[string]bool{"label:caller": true})}, memory: make(map[string]arm64ControlValue)}
			ins := file.Funcs[0].Instrs[1]
			state.transfer(ins, ins.Op, false, nil)
			if labels := arm64ControlLabels(arm64ControlRead(state.regs, "R30")); arm64ControlCount(labels) != 0 {
				t.Errorf("literal overwrote LR but retained its code bits: %s: %v", text, labels)
			}
		}
	}
}

func TestARM64ControlGPMoveLiteralToVectorScratch(t *testing.T) {
	body := `MOVW $-601,R30
VDUP R30,V22.S4
FMOVQ F22,(R1)
`
	source := arm64RawZeroFrameFixture(516, false, body)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := arm64RawZeroFrameSig()
	if !arm64CallFrameUnexposedTyped(file.Funcs[0], sig, nil, nil) {
		t.Fatal("constant vector scratch was mistaken for escaping caller code")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "constant-vector.ll", "constant-vector.o", ir)
	}
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		text := op + " R30,R4"
		file, err := Parse(ArchARM64, "TEXT taint(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{regs: map[Reg]arm64ControlValue{"R30": arm64ControlFromMap(map[string]bool{"label:caller": true})}, memory: make(map[string]arm64ControlValue)}
		ins := file.Funcs[0].Instrs[1]
		state.transfer(ins, ins.Op, false, nil)
		value := arm64ControlRead(state.regs, "R4")
		if !arm64ControlHas(value, "label:caller") || op != "MOVD" && !arm64ControlHas(value, "code-derived:") {
			t.Errorf("actual narrow/copy source washed caller code: %s: %v", text, value)
		}
	}
	for _, text := range []string{"MOVK $1,R30", "MOVKW $65536,R30", "MOVW.X $1,R30"} {
		file, err := Parse(ArchARM64, "TEXT closed(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{regs: map[Reg]arm64ControlValue{"R30": arm64ControlFromMap(map[string]bool{"label:caller": true})}, memory: make(map[string]arm64ControlValue)}
		ins := file.Funcs[0].Instrs[1]
		state.transfer(ins, arm64ControlOp(ins), false, nil)
		if !arm64ControlHas(arm64ControlRead(state.regs, "R30"), "label:caller") {
			t.Errorf("RMW/unknown move got full overwrite witness: %s", text)
		}
	}
	for _, text := range []string{"MOVW $unknown,R30", "MOVWU $-601,R30", "MOVWU $806,R30", "MOVWU $305419896,R30", "MOVB $1,R30", "FMOVD $0,R30"} {
		file, err := Parse(ArchARM64, "TEXT unknown(SB),$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{regs: make(map[Reg]arm64ControlValue), memory: make(map[string]arm64ControlValue)}
		if state.transferGPRegisterMove(file.Funcs[0].Instrs[1]) {
			t.Errorf("unknown/invalid move got overwrite witness: %s", text)
		}
	}
	// Fixed ABI identities cannot be restored by overwriting their bits.
	for _, fixed := range []string{"g", "R29"} {
		source := strings.Replace(arm64RawZeroFrameFixture(516, false, "MOVD $0,"+fixed+"\nMOVD R4,(R1)\n"), "WORD $0xa8c17bfd", "WORD $0xa8c107fe", 1)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposedTyped(file.Funcs[0], sig, nil, nil) {
			t.Fatalf("constant replacement restored fixed entry identity: %s", fixed)
		}
	}
}
