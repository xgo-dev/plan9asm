package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func arm64RawVectorFamilyOracleLines() []string {
	return []string{
		"aese v30.16b, v31.16b",
		"sm4e v30.4s, v31.4s",
		"sm3ss1 v30.4s, v31.4s, v29.4s, v28.4s",
		"sqrdmlah v30.4s, v31.4s, v29.4s",
		"addp d30, v31.2d",
		"sdot v30.4s, v31.16b, v29.16b",
		"smmla v30.4s, v31.16b, v29.16b",
		"tbl v30.16b, {v31.16b}, v29.16b",
		"sqrdmulh v30.4s, v31.4s, v29.4s",
		"suqadd v30.4s, v31.4s",
		"sqdmulh v30.4s, v31.4s, v29.4s",
		"mul v30.4s, v31.4s, v29.4s",
		"shadd v30.4s, v31.4s, v29.4s",
		"cmgt v30.4s, v31.4s, v29.4s",
		"mls v30.4s, v31.4s, v29.4s",
		"saddlp v30.2d, v31.4s",
		"umull v30.2d, v31.2s, v29.2s",
		"addhn v30.2s, v31.2d, v29.2d",
		"uzp1 v30.4s, v31.4s, v29.4s",
		"sqshrn v30.2s, v31.2d, #32",
		"sqshlu v30.2d, v31.2d, #63",
		"ushll v30.2d, v31.2s, #31",
		"umlal v30.2d, v31.2s, v29.2s",
		"dup v30.2d, v31.d[1]",
		"mla v30.4s, v31.4s, v29.4s",
		"eor v30.16b, v31.16b, v29.16b",
		"movi v30.4s, #255",
		"eor3 v30.16b, v31.16b, v29.16b, v28.16b",
	}
}

func TestARM64RawVectorDecodersHaveSharedEffectsAndLowering(t *testing.T) {
	registry, err := parser.ParseFile(token.NewFileSet(), "arm64_raw_vector_families.go", nil, 0)
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
			t.Fatalf("duplicate vector family %s", decoder.Name)
		}
		registered[decoder.Name] = true
		return true
	})
	// These are the complete existing register-only integer/crypto families
	// migrated here. Memory, GP extraction, system and SME use separate effects.
	files := []string{
		"arm64_lower_word_uhadd.go",
		"arm64_lower_integer_pairwise.go",
		"arm64_lower_word_cmgt.go",
		"arm64_lower_word_mla.go",
		"arm64_lower_word_umull.go",
		"arm64_lower_word_rdma.go",
		"arm64_lower_word_logical.go",
		"arm64_lower_word_sqshlu.go",
		"arm64_lower_word_sqrdmulh.go",
		"arm64_lower_saturating_shift_narrow.go",
		"arm64_lower_word_mul.go",
		"arm64_lower_word_mls.go",
		"arm64_lower_word_mixed_saturating_add.go",
		"arm64_lower_word_modified_immediate.go",
		"arm64_lower_word_add_high_narrow.go",
		"arm64_lower_word_table_lookup.go",
		"arm64_lower_word_sha3.go",
		"arm64_lower_word_uzp.go",
		"arm64_lower_word_dup_element.go",
		"arm64_lower_word_ushll.go",
		"arm64_lower_word_uadalp.go",
		"arm64_lower_word_sqdmulh.go",
		"arm64_lower_word_sm4.go",
		"arm64_lower_word_sm3.go",
		"arm64_lower_word_dot_product.go",
		"arm64_lower_aes.go",
		"arm64_lower_word_umlal.go",
		"arm64_lower_word_matrix_multiply.go",
	}
	for _, name := range files {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "decodeARM64Raw") {
				continue
			}
			if !registered[fn.Name.Name] {
				t.Errorf("%s has no shared effects/lowering family", fn.Name.Name)
			}
			delete(registered, fn.Name.Name)
		}
	}
	for name := range registered {
		t.Errorf("%s was registered outside the reviewed vector-only families", name)
	}
}

func TestARM64RawVectorFamiliesTranslateAndCompileLLVM22Targets(t *testing.T) {
	words := assembleARM64LLVMWords(t, arm64RawVectorFamilyOracleLines(), "+aes,+sm4,+sha3,+dotprod,+i8mm,+rdm")
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for i, word := range words {
		name := fmt.Sprintf("rawVectorFamily%d", i)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for r := 0; r < 32; r++ {
			fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.B16]\n", r)
		}
		fmt.Fprintf(&source, "WORD $%#08x\nVST1 [V30.B16],(R1)\nRET\n", word)
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-vector-families.ll", "raw-vector-families.o", ir)
		})
	}
}

func TestARM64RawVectorRegisterFamiliesPreserveGPAndSavedLink(t *testing.T) {
	lines := arm64RawVectorFamilyOracleLines()
	for index, word := range assembleARM64LLVMWords(t, lines, "+aes,+sm4,+sha3,+dotprod,+i8mm,+rdm") {
		t.Run(lines[index], func(t *testing.T) {
			if writes, known := arm64RawPoolGPWrites(word); !known || writes != 0 {
				t.Errorf("register-only SIMD family has unknown GP effects: writes=%#x, known=%v", writes, known)
			}
			caller := arm64ControlFromMap(map[string]bool{"return:outer": true})
			state := &arm64ControlState{
				regs:   map[Reg]arm64ControlValue{"R30": caller},
				memory: map[string]arm64ControlValue{"sp:0": caller},
			}
			state.transfer(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}, OpWORD, false, nil)
			if arm64ControlHas(state.regs["R30"], "") || arm64ControlHas(state.memory["sp:0"], "") {
				t.Error("vector register 30 must not clobber GP LR or memory")
			}
		})
	}
}
