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

func TestARM64RawSVEGPResultEffectsAllRegisters(t *testing.T) {
	var lines []string
	var wants []uint32
	for register := 0; register < 32; register++ {
		name := fmt.Sprintf("x%d", register)
		mask := uint32(1) << uint(register)
		if register == 31 {
			name, mask = "xzr", 0
		}
		for _, format := range []string{
			"cntp %s, p7, p15.d", "cntp %s, pn15.d, vlx4",
			"incp %s, p15.d", "uqdecp %s, p15.d",
			"lasta %s, p7, z31.d", "lastb %s, p7, z31.d",
		} {
			lines = append(lines, fmt.Sprintf(format, name))
			wants = append(wants, mask)
		}
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		if writes, known := arm64RawPoolGPWrites(word); !known || writes != wants[index] {
			t.Errorf("%s: writes=%#x, known=%v; want %#x", lines[index], writes, known, wants[index])
		}
	}
}

func TestARM64RawSVEGPResultDoesNotInventCallerReturn(t *testing.T) {
	lines := []string{"cntp x30, p7, p15.d", "incp x30, p15.d", "lasta x30, p7, z31.d"}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		source := fmt.Sprintf("TEXT control(SB),$0-0\nWORD $%#08x\nRET\n", word)
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
				t.Errorf("%s / %s: discarded real caller LR must retain Context, got %v", lines[index], triple, err)
			}
		}
	}
}

func TestARM64RawSVEInstrDecodersHaveSharedFamily(t *testing.T) {
	registry, err := parser.ParseFile(token.NewFileSet(), "arm64_raw_sve_families.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]bool)
	ast.Inspect(registry, func(node ast.Node) bool {
		field, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := field.Key.(*ast.Ident)
		if !ok || key.Name != "decode" {
			return true
		}
		decoder, ok := field.Value.(*ast.Ident)
		if !ok || registered[decoder.Name] {
			t.Fatal("raw SVE decoder must have one explicit family")
		}
		registered[decoder.Name] = true
		return true
	})
	// These are nested grammar helpers, not alternative lowering routes.
	delegated := map[string]string{
		"decodeARM64RawSVEPNLoad":      "decodeARM64RawSVEUnsignedLoad",
		"decodeARM64RawSVELoadAddress": "decodeARM64RawSVEUnsignedLoad",
	}
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "arm64_") || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		source, err := parser.ParseFile(token.NewFileSet(), file.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range source.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "decodeARM64RawSVE") || fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
				continue
			}
			result, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
			if !ok || result.Name != "Instr" || registered[fn.Name.Name] {
				continue
			}
			if parent := delegated[fn.Name.Name]; parent != "" && registered[parent] {
				continue
			}
			t.Errorf("%s has no shared lowerer/control-effect family", fn.Name.Name)
		}
	}
}

// Destination effects and memory effects are independent. In particular a
// predicate/vector numbered 30 must not clobber X30, and a load must not erase
// a saved continuation merely because its address is unknown.
func TestARM64RawSVETypedControlEffects(t *testing.T) {
	tests := []struct {
		assembly string
		writes   uint32
		stores   bool
	}{
		{"rev p15.d, p14.d", 0, false},
		{"zip1 p15.b, p14.b, p13.b", 0, false},
		{"punpkhi p15.h, p14.b", 0, false},
		{"match p7.b, p7/z, z30.b, z31.b", 0, false},
		{"brka p15.b, p7/z, p14.b", 0, false},
		{"ptest p7, p15.b", 0, false},
		{"whilelo p7.d, x30, x29", 0, false},
		{"index z30.d, x30, x29", 0, false},
		{"adr z30.d, [z31.d, z29.d, lsl #3]", 0, false},
		{"sdot z30.s, z31.b, z29.b", 0, false},
		{"mul z30.d, p7/m, z30.d, z31.d", 0, false},
		{"tbl z30.d, {z31.d}, z29.d", 0, false},
		{"umullb z30.d, z31.s, z29.s", 0, false},
		{"umlalb z30.d, z31.s, z29.s", 0, false},
		{"fmaxnmv d30, p7, z31.d", 0, false},
		{"saddwb z30.d, z31.d, z29.s", 0, false},
		{"umax z30.d, p7/m, z30.d, z31.d", 0, false},
		{"lasta d30, p7, z31.d", 0, false},
		{"lasta x30, p7, z31.d", 1 << 30, false},
		{"lastb xzr, p7, z31.d", 0, false},
		{"cntp x30, p7, p15.d", 1 << 30, false},
		{"cntp xzr, pn15.d, vlx4", 0, false},
		{"incp x30, p15.d", 1 << 30, false},
		{"uqdecp xzr, p15.d", 0, false},
		{"ld1b {z30.d}, p7/z, [x29]", 0, false},
		{"ld1sb {z30.d}, p7/z, [x29]", 0, false},
		{"ld1rw {z30.s}, p7/z, [x29]", 0, false},
		{"ld2d {z30.d, z31.d}, p7/z, [x29]", 0, false},
		{"st1b {z30.d}, p7, [x29]", 0, true},
		{"st2d {z30.d, z31.d}, p7, [x29]", 0, true},
	}
	lines := make([]string, len(tests))
	for index, test := range tests {
		lines[index] = test.assembly
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		test := tests[index]
		t.Run(test.assembly, func(t *testing.T) {
			if writes, known := arm64RawPoolGPWrites(word); !known || writes != test.writes {
				t.Errorf("GP writes = %#x, known=%v; want %#x", writes, known, test.writes)
			}
			continuation := arm64ControlFromMap(map[string]bool{"return:outer": true})
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R30": continuation},
				memory: map[string]arm64ControlValue{"sp:0": continuation},
			}
			state.transfer(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}, OpWORD, false, nil)
			if got := arm64ControlHas(state.regs["R30"], ""); got != (test.writes&(1<<30) != 0) {
				t.Errorf("X30 became unknown=%v, writes=%#x", got, test.writes)
			}
			if got := arm64ControlHas(state.memory["sp:0"], ""); got != test.stores {
				t.Errorf("saved continuation became unknown=%v, memory store=%v", got, test.stores)
			}
		})
	}
}

func TestARM64RawUnknownControlEffectsRemainConservative(t *testing.T) {
	for _, word := range []uint32{0xffffffff, 0x05304010, 0x25208a00, 0xd63f0000} {
		continuation := arm64ControlFromMap(map[string]bool{"return:outer": true})
		state := &arm64ControlState{
			regs:   map[Reg]arm64ControlValue{"R30": continuation},
			memory: map[string]arm64ControlValue{"sp:0": continuation},
		}
		state.transfer(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}, OpWORD, false, nil)
		if !arm64ControlHas(state.regs["R30"], "") || !arm64ControlHas(state.memory["sp:0"], "") {
			t.Errorf("unmodeled/call word %#08x silently preserved continuation", word)
		}
	}
}
