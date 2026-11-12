package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestARM64RawFloatDecodersHaveSharedEffectsAndLowering(t *testing.T) {
	registry, err := parser.ParseFile(token.NewFileSet(), "arm64_raw_float_families.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]bool)
	ast.Inspect(registry, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		decoder, ok := call.Args[0].(*ast.Ident)
		if !ok || !strings.HasPrefix(decoder.Name, "decodeARM64Raw") {
			return true
		}
		if registered[decoder.Name] {
			t.Fatalf("duplicate floating family %s", decoder.Name)
		}
		registered[decoder.Name] = true
		return true
	})
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range files {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		floating := name == "arm64_lower_word_cvtf.go" || name == "arm64_lower_word_fcvtz.go" || name == "arm64_lower_word_fixed_int_to_float.go"
		for _, prefix := range []string{"arm64_lower_word_float_", "arm64_lower_word_scalar_", "arm64_lower_word_half_", "arm64_lower_word_bfloat_"} {
			floating = floating || strings.HasPrefix(name, prefix)
		}
		if !floating {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && strings.HasPrefix(fn.Name.Name, "decodeARM64Raw") && !registered[fn.Name.Name] {
				t.Errorf("%s has no shared effects/lowering family", fn.Name.Name)
			}
		}
	}
}

func TestARM64RawFloatGPEffectsAllRegisterBanksAndDirections(t *testing.T) {
	var lines []string
	var wants []arm64RawContinuationEffects
	for register := 0; register < 32; register++ {
		x, w := fmt.Sprintf("x%d", register), fmt.Sprintf("w%d", register)
		bit := uint32(1) << uint(register)
		if register == 31 {
			x, w, bit = "xzr", "wzr", 0
		}
		for _, test := range []struct {
			format string
			gp     string
			writes bool
		}{
			{"fmov %s, h31", w, true}, {"fmov h31, %s", w, false},
			{"fmov %s, s31", w, true}, {"fmov s31, %s", w, false},
			{"fmov %s, d31", x, true}, {"fmov d31, %s", x, false},
			{"fmov %s, v31.d[1]", x, true}, {"fmov v31.d[1], %s", x, false},
			{"fcvtzs %s, h31", w, true}, {"fcvtnu %s, d31", x, true},
			{"scvtf h31, %s", w, false}, {"ucvtf d31, %s", x, false},
			{"scvtf s31, %s, #32", w, false}, {"ucvtf d31, %s, #64", x, false},
		} {
			lines = append(lines, fmt.Sprintf(test.format, test.gp))
			effects := arm64RawContinuationEffects{gpReads: bit}
			if test.writes {
				effects = arm64RawContinuationEffects{gpWrites: bit}
			}
			wants = append(wants, effects)
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+fullfp16") {
		_, effects, known := decodeARM64RawFloatFamily(word)
		if !known || effects != wants[i] {
			t.Errorf("%s: effects=%+v, known=%v; want %+v", lines[i], effects, known, wants[i])
		}
	}
}

func TestARM64RawFloatControlEffectsDistinguishGPAndVectorBanks(t *testing.T) {
	tests := []struct {
		assembly string
		writes   uint32
	}{
		{"bfdot v30.4s, v31.8h, v29.8h", 0},
		{"bfmmla v30.4s, v31.8h, v29.8h", 0},
		{"fmlal v30.4s, v31.4h, v29.4h", 0},
		{"scvtf v30.4s, v31.4s", 0},
		{"fmla v30.4s, v31.4s, v29.4s", 0},
		{"fmadd h30, h31, h29, h28", 0},
		{"fmul v30.4s, v31.4s, v29.s[3]", 0},
		{"fsqrt h30, h31", 0},
		{"fcvtzs d30, d31", 0},
		{"fadd d30, d31, d29", 0},
		{"fcmp d30, d31", 0},
		{"fcsel d30, d31, d29, eq", 0},
		{"fmov h30, #1.0", 0},
		{"scvtf d30, x30", 0},
		{"scvtf d30, x30, #3", 0},
		{"fmov x30, d31", 1 << 30},
		{"fmov d30, x30", 0},
		{"bfcvtn v30.4h, v31.4s", 0},
		{"frinta v30.4s, v31.4s", 0},
		{"fcvtn v30.4h, v31.4s", 0},
		{"fcvtl v30.4s, v31.4h", 0},
		{"fmaxv s30, v31.4s", 0},
		{"faddp v30.4s, v31.4s, v29.4s", 0},
		{"fminnmp v30.4s, v31.4s, v29.4s", 0},
		{"fadd v30.4s, v31.4s, v29.4s", 0},
		{"frecpe v30.4s, v31.4s", 0},
		{"fsqrt v30.4s, v31.4s", 0},
		{"fabs v30.8h, v31.8h", 0},
		{"fcmeq v30.4s, v31.4s, v29.4s", 0},
		{"fmov v30.4s, #1.0", 0},
		{"fcvtzs x30, d31", 1 << 30},
		{"fcvtzs v30.4s, v31.4s", 0},
	}
	lines := make([]string, len(tests))
	for i, test := range tests {
		lines[i] = test.assembly
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+bf16,+fullfp16,+fp16fml") {
		test := tests[i]
		t.Run(test.assembly, func(t *testing.T) {
			if writes, known := arm64RawPoolGPWrites(word); !known || writes != test.writes {
				t.Errorf("GP writes=%#x, known=%v; want %#x", writes, known, test.writes)
			}
			caller := arm64ControlFromMap(map[string]bool{"return:outer": true})
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R30": caller},
				memory: map[string]arm64ControlValue{"sp:0": caller},
			}
			state.transfer(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}, OpWORD, false, nil)
			if unknown := arm64ControlHas(state.regs["R30"], ""); unknown != (test.writes&(1<<30) != 0) {
				t.Errorf("caller LR unknown=%v; GP writes=%#x", unknown, test.writes)
			}
			if arm64ControlHas(state.memory["sp:0"], "") {
				t.Error("a register-only floating instruction cannot write a saved continuation")
			}
		})
	}
}

func TestARM64RawFloatGPResultsCannotInventCallerReturn(t *testing.T) {
	lines := []string{"fmov x30, d31", "fcvtzs x30, d31", "fcvtnu w30, h31"}
	for i, word := range assembleARM64LLVMWords(t, lines, "+fullfp16") {
		source := fmt.Sprintf("TEXT control(SB),4,$0-0\nWORD $%#08x\nRET\n", word)
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
			"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
		} {
			_, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"control": {Name: "control", Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s / %s: changed caller LR must remain Context, got %v", lines[i], triple, err)
			}
		}
	}
}
