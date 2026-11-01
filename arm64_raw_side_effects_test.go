package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestARM64RawStateFamiliesHavePreciseGPAndSavedMemoryEffects(t *testing.T) {
	for _, test := range []struct {
		name   string
		word   uint32
		writes uint32
		stores bool
	}{
		{"ic_ivau", 0xd50b753e, 0, false},
		{"rndr_x30", 0xd53b241e, 1 << 30, false},
		{"rndrrs_xzr", 0xd53b243f, 0, false},
		{"casp_expected_x2_x3", 0x48227f3e, 1<<2 | 1<<3, true},
		{"smstart", 0xd503477f, 0, false},
		{"zero_za", 0xc00800ff, 0, false},
		{"fmopa", 0x80800020, 0, false},
		{"sme_tile_read", 0xc0820000, 0, false},
		{"sme_tile_write", 0xc080e000, 0, false},
		{"sme_memory_load", 0xe01f0020, 0, false},
		{"sme_memory_store", 0xe03f0000, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if writes, known := arm64RawPoolGPWrites(test.word); !known || writes != test.writes {
				t.Errorf("GP writes=%#x, known=%v; want %#x", writes, known, test.writes)
			}
			caller := arm64ControlFromMap(map[string]bool{"return:outer": true})
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R30": caller, "R2": caller, "R3": caller},
				memory: map[string]arm64ControlValue{"sp:0": caller},
			}
			state.transfer(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(test.word)}}}, OpWORD, false, nil)
			for _, register := range []struct {
				name Reg
				bit  uint32
			}{{"R30", 1 << 30}, {"R2", 1 << 2}, {"R3", 1 << 3}} {
				if arm64ControlHas(state.regs[register.name], "") != (test.writes&register.bit != 0) {
					t.Errorf("%s provenance did not follow its exact GP output", register.name)
				}
			}
			if arm64ControlHas(state.memory["sp:0"], "") != test.stores {
				t.Errorf("saved continuation clobber must match a real memory store, want %v", test.stores)
			}
		})
	}
}

func TestARM64RawStateGPBankAndSPEffectsCompleteIndependentAxes(t *testing.T) {
	for register := 0; register < 32; register++ {
		bit := uint32(1) << uint(register)
		if register == 31 {
			bit = 0
		}
		for _, base := range []uint32{0xd53b2400, 0xd53b2420} {
			word := base | uint32(register)
			_, effects, ok := decodeARM64RawStateFamily(word)
			want := arm64RawContinuationEffects{gpWrites: bit}
			if !ok || effects != want {
				t.Errorf("RNDR word %#08x: %+v, %v; want %+v", word, effects, ok, want)
			}
		}
		word := uint32(0xd50b7520) | uint32(register)
		_, effects, ok := decodeARM64RawStateFamily(word)
		want := arm64RawContinuationEffects{gpReads: bit}
		if !ok || effects != want {
			t.Errorf("IC IVAU word %#08x: %+v, %v; want %+v", word, effects, ok, want)
		}
	}
	for _, bits := range []int{32, 64} {
		for _, order := range []struct{ acquire, release bool }{
			{}, {acquire: true}, {release: true}, {acquire: true, release: true},
		} {
			for expected := 0; expected < 32; expected += 2 {
				for newValue := 0; newValue < 32; newValue += 2 {
					for base := 0; base < 32; base++ {
						word := arm64EncodeRawCASP(bits, order.acquire, order.release, expected, newValue, base)
						_, effects, ok := decodeARM64RawStateFamily(word)
						writes := uint32(3) << uint(expected) & 0x7fffffff
						newReads := uint32(3) << uint(newValue) & 0x7fffffff
						baseRead := uint32(1) << uint(base) & 0x7fffffff
						want := arm64RawContinuationEffects{
							gpReads: writes | newReads | baseRead, gpWrites: writes,
							readsSP: base == 31, stores: true,
						}
						if !ok || effects != want {
							t.Fatalf("CASP word %#08x: %+v, %v; want %+v", word, effects, ok, want)
						}
					}
				}
			}
		}
	}
	// SME tile addresses use SP as a base, but XZR as a register offset.
	// Vary each independent bank/width/direction axis without a huge product.
	for register := 0; register < 32; register++ {
		for size := uint32(0); size < 4; size++ {
			for row := uint32(0); row < 4; row++ {
				for _, store := range []bool{false, true} {
					for _, spBase := range []bool{false, true} {
						base, offset := uint32(register), uint32(31)
						if spBase {
							base, offset = 31, uint32(register)
						}
						word := uint32(0xe0000000) | size<<22 | offset<<16 | row<<13 | base<<5
						if store {
							word |= 1 << 21
						}
						_, effects, ok := decodeARM64RawStateFamily(word)
						want := arm64RawContinuationEffects{
							gpReads: (1 << (row + 12)) | ((1 << base) & 0x7fffffff) | ((1 << offset) & 0x7fffffff),
							readsSP: base == 31, stores: store,
						}
						if !ok || effects != want {
							t.Fatalf("SME word %#08x: %+v, %v; want %+v", word, effects, ok, want)
						}
					}
				}
			}
		}
	}
}

func TestARM64RawStateGPOutputsCannotInventCallerReturn(t *testing.T) {
	for _, word := range []uint32{0xd53b241e, 0xd53b243e, 0x483e7c82} {
		source := fmt.Sprintf("TEXT stateResult(SB),4,$0-0\nWORD $%#08x\nRET\n", word)
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
				Sigs: map[string]FuncSig{"stateResult": {Name: "stateResult", Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%#08x / %s: overwritten caller LR requires source restoration, got %v", word, triple, err)
			}
		}
	}
}

func TestARM64RawStateDecodersHaveSharedEffectsAndLowering(t *testing.T) {
	registry, err := parser.ParseFile(token.NewFileSet(), "arm64_raw_state_families.go", nil, 0)
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
			t.Fatalf("duplicate state family %s", decoder.Name)
		}
		registered[decoder.Name] = true
		return true
	})
	for _, name := range []string{
		"arm64_lower_word_streaming_mode.go", "arm64_lower_word_za_zero.go",
		"arm64_lower_word_sme_mopa.go", "arm64_lower_word_sme_tile_memory.go",
		"arm64_lower_ic.go", "arm64_lower_word_rndr.go", "arm64_lower_word_casp.go",
		"arm64_lower_cache_maintenance.go",
		"arm64_nzcv_transport.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "decodeARM64Raw") || fn.Type.Results == nil {
				continue
			}
			results := fn.Type.Results.List
			if len(results) != 2 {
				continue // Field extraction helpers are not encoding acceptors.
			}
			result, ok := results[1].Type.(*ast.Ident)
			if !ok || result.Name != "bool" {
				continue
			}
			if !registered[fn.Name.Name] {
				t.Errorf("%s has no shared effects/lowering family", fn.Name.Name)
			}
			delete(registered, fn.Name.Name)
		}
	}
	for name := range registered {
		t.Errorf("%s was registered outside the reviewed state families", name)
	}
}
