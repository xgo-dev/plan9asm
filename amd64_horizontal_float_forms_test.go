package plan9asm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86HorizontalFloatEveryGoOpcodeAttribute(t *testing.T) {
	if len(amd64HorizontalFloatingSpecs) != 8 {
		t.Fatal("incomplete horizontal floating family")
	}
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return // older source builds still execute grammar, object and bit tests
	}
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"HADDPS", "HADDPD", "HSUBPS", "HSUBPD", "VHADDPS", "VHADDPD", "VHSUBPS", "VHSUBPD"} {
		bits, prefix, opcode := 32, "vexF2", "0x7C"
		if strings.HasSuffix(op, "PD") {
			bits, prefix = 64, "vex66"
		}
		if strings.Contains(op, "SUB") {
			opcode = "0x7D"
		}
		spec := amd64HorizontalFloatingSpecs[Op(op)]
		if spec.laneBits != bits || spec.subtract != strings.Contains(op, "SUB") || spec.vector != strings.HasPrefix(op, "V") {
			t.Fatalf("%s independent opcode attributes differ: %+v", op, spec)
		}
		if !spec.vector {
			if !strings.Contains(string(legacy), "{A"+op+", yxm,") {
				t.Fatalf("Go legacy yxm changed: %s", op)
			}
			continue
		}
		start := strings.Index(string(avx), "{as: A"+op+",")
		if start < 0 {
			t.Fatalf("Go omits %s", op)
		}
		row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if !strings.Contains(row, "ytab: _yvaddsubpd,") || strings.Contains(row, "evex") || strings.Contains(row, "Bcst") || strings.Contains(row, "Sae") {
			t.Fatalf("Go VEX-only grammar changed: %s", row)
		}
		for _, width := range []string{"vex128", "vex256"} {
			if !strings.Contains(row, "avxEscape | "+width+" | "+prefix+" | vex0F | vexW0, "+opcode) {
				t.Fatalf("%s complete encoding attributes changed: %s", op, row)
			}
		}
	}
}

func TestX86HorizontalFloatDispatchIdentityBeforeEmission(t *testing.T) {
	for _, row := range x86HorizontalFloatFormats() {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		op := file.Funcs[0].Instrs[1].Op
		for _, identity := range []Op{"", op, Op(strings.ToLower(string(op))), "UNKNOWN", "VHADDPS.Z"} {
			ins := file.Funcs[0].Instrs[1]
			ins.Op = identity
			original := ins
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerHorizontalFloating(op, ins)
			conflict := identity == "UNKNOWN" || identity == "VHADDPS.Z"
			if !known || term || (err != nil) != conflict || conflict && output.String() != before || !reflect.DeepEqual(ins, original) {
				t.Fatalf("%s/%s source identity: %t/%t/%v", op, identity, known, term, err)
			}
		}
	}
}

func TestX86HorizontalFloatMalformedFormsBeforeEmission(t *testing.T) {
	for _, row := range []string{
		"HADDPS X0,Y1", "HSUBPD X0,X16", "HADDPD.SAE X0,X1", "HSUBPS $data(SB),X1",
		"VHADDPS X0,X1", "VHADDPD X0,Y1,Y2", "VHSUBPS Z0,Z1,Z2", "VHSUBPD X0,X1,X16",
		"VHADDPS X0,X1,K1,X2", "VHADDPD.Z X0,X1,X2", "VHSUBPS.BCST (AX),X1,X2",
		"VHSUBPD.RN_SAE Y0,Y1,Y2", "VHADDPS. X0,X1,X2", "VHADDPD (AX)(SP*2),X1,X2",
		"VHSUBPS 2147483648(AX),X1,X2",
	} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			ins := file.Funcs[0].Instrs[1]
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerHorizontalFloating(ins.Op, ins)
			if !known || term || err == nil || output.String() != before {
				t.Fatalf("invalid form emitted IR: %t/%t/%v", known, term, err)
			}
		})
	}
}

func TestX86HorizontalFloatGoFormatsFiveLLVMTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		for index, row := range x86HorizontalFloatFormats() {
			name := fmt.Sprintf("horizontal%d", index)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		triples := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			file, signatures := x86UnboundVoidFormatSources(t, source.String(), arch, triple)
			ir := x86ScalarFormatObjectUnit(t, file, signatures, arch, triple, 0)
			compileLLVMToObject(t, llc, triple, "horizontal-formats.ll", "horizontal-formats.o", ir)
		}
	}
}

func TestX86HorizontalFloatLegacyMode32ClassesMatchGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		// NOSPLIT is a CPP macro, not an assembler constant without its header.
		goAssemblerOracleOutput(t, arch,
			"TEXT horizontal_floating_complete_forms(SB),NOSPLIT,$0-0\nHADDPS X0,X1\nRET\n", "", false)
	}
	// Keep the former complete-form fixture's rejected source, rather than
	// treating mode32 X15 as a translator-supported ordinary register.
	for _, opcode := range []string{"HADDPS", "HADDPD", "HSUBPS", "HSUBPD"} {
		for _, instruction := range []string{opcode + " X15,X1", opcode + " 8(BX),X15"} {
			t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
				source := "TEXT f(SB),4,$0-0\n" + instruction + "\nRET\n"
				goAssemblerOracleOutput(t, "386", source, "", false)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{
					Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}},
				}); err == nil {
					t.Fatal("translator accepted the original Go-rejected legacy X15 form")
				}
			})
		}
	}
}

func TestX86HorizontalFloat386VEXHighRegistersKeepPhysicalContext(t *testing.T) {
	// Execute each compatibility Go assembler rather than trusting the current
	// optab-only oracle. Actual objects are syntax evidence, not mode32 runtime.
	const source = "TEXT f(SB),4,$0-0\nVHADDPS X8,X9,X10\nVHSUBPD Y8,Y9,Y10\nRET\n"
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "high.s"), filepath.Join(dir, "high.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "oracle", "-o", object, asm)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), true, "386"); failure != nil {
		t.Fatalf("actual named high-register fixture: %v\n%s", failure, output)
	}
	if !bytes.Contains(output, []byte("c4 41 33 7c d0 c4 41 35 7d d0 c3")) {
		t.Fatalf("actual Go mode32 source bytes changed:\n%s", output)
	}
	for _, row := range []struct{ code, op, bank string }{{"c441337cd0", "VHADDPS", "X"}, {"c441357dd0", "VHSUBPD", "Y"}} {
		code, err := hex.DecodeString(row.code)
		if err != nil {
			t.Fatal(err)
		}
		ins, length, recognized, err := decodedX86VEXHorizontalFloatInstruction(code, 64)
		if !recognized || err != nil || length != len(code) || string(ins.Op) != row.op ||
			ins.Args[0].Reg != Reg(row.bank+"8") || ins.Args[1].Reg != Reg(row.bank+"9") || ins.Args[2].Reg != Reg(row.bank+"10") {
			t.Fatalf("source bytes lost physical register identities: %+v/%d/%t/%v", ins, length, recognized, err)
		}
		if _, _, known, err := decodedX86VEXHorizontalFloatInstruction(code, 32); !known || err == nil {
			t.Fatal("mode32 decoder invented high physical SIMD registers")
		}
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("named Go object laundered as physical mode32 success: %v", err)
	}
	goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\nHADDPS X8,X9\nRET\n", "", false)
}

func TestX86HorizontalFloatCompleteTypedFPSpanBeforeEmission(t *testing.T) {
	for _, row := range x86HorizontalFloatFormats() {
		if !strings.Contains(row, "(BX)") {
			continue
		}
		width := 16
		if strings.Contains(row, "Y") {
			width = 32
		}
		row = strings.Replace(row, "(BX)", "a+0(FP)", 1)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-32\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, missing := range []int{-1, 0, width/8 - 1} {
			sig := FuncSig{Name: "f", Ret: Void}
			for index := 0; index < width/8; index++ {
				if index == missing {
					continue
				}
				sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(index * 8), Type: I64, Index: len(sig.Args), Field: -1})
				sig.Args = append(sig.Args, I64)
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			ins := file.Funcs[0].Instrs[1]
			before := output.String()
			known, term, err := ctx.lowerHorizontalFloating(ins.Op, ins)
			needsContext := missing >= 0 || !strings.HasPrefix(row, "V")
			if !known || term || (err != nil) != needsContext || needsContext && output.String() != before {
				t.Fatalf("%s missing typed slot %d: %t/%t/%v", row, missing, known, term, err)
			}
		}
	}
}

func TestX86HorizontalFloatPairsUseSingleStrictVectorOperation(t *testing.T) {
	for _, row := range x86HorizontalFloatFormats() {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ir := x86ScalarFormatObjectUnit(t, file, map[string]FuncSig{"f": {Ret: Void}}, "amd64", "x86_64-unknown-linux-gnu", 0)
		// One original native reduction owns its joint exception, pair NaN
		// priority and ambient MXCSR semantics. No scalar reconstruction or
		// pure arithmetic carrier can replace it, including a dead output.
		// The common prelude still declares unrelated constrained intrinsics.
		// Inspect this original instruction's body, not global declarations.
		_, body, found := strings.Cut(ir, "define void @InstructionFormat0(")
		body, _, ended := strings.Cut(body, "\n}")
		opcode := `asm sideeffect "` + strings.ToLower(strings.Fields(row)[0]) + ` `
		if got := strings.Count(body, opcode); !found || !ended || got != 1 ||
			strings.Count(body, "asm sideeffect") != 1 || !strings.Contains(body, "~{fpsr}") ||
			!strings.Contains(body, "~{memory}") || strings.Contains(body, "@llvm.experimental.constrained") {
			t.Fatalf("%s lost its one native strict horizontal operation (%d):\n%s", row, got, ir)
		}
	}
}
