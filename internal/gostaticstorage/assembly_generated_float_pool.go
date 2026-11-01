package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"text/scanner"
)

// ASMGeneratedFloatPool observes a source FCONST rewrite and its unchanged
// object-local DATA/TEXT associations. It is not an ASMGlobalLayout, readable
// literal, initialization, numerical, native-entry or storage permission.
type ASMGeneratedFloatPool struct {
	Definition ASMDataDefinition
	Owners     []ASMGeneratedFloatPoolOwner
}

type ASMGeneratedFloatPoolOwner struct {
	StatementOrdinal, TextSourceOrdinal, TextObjectOrdinal int
	TextNamespace                                          TextSymbolNamespace
	TextRelative, TextIndex                                uint32
	Opcode                                                 string
	SourceFloat64Bits                                      uint64
	RelocationOrdinal                                      int
	Relocation                                             TextRelocation
}

type asmGeneratedFloatPoolForm struct {
	width uint32
	move  bool
}

// Complete obj/x86.progedit FCONST producer directory. This small source
// metadata grammar neither assembles an instruction nor permits its execution.
// In particular VEX arithmetic is not one of Go's FCONST rewrites.
var asmGeneratedFloatPoolForms = map[string]asmGeneratedFloatPoolForm{
	"MOVSS": {4, true}, "VMOVSS": {4, true},
	"FMOVF": {4, false}, "FADDF": {4, false}, "FSUBF": {4, false}, "FSUBRF": {4, false},
	"FMULF": {4, false}, "FDIVF": {4, false}, "FDIVRF": {4, false},
	"FCOMF": {4, false}, "FCOMFP": {4, false},
	"ADDSS": {4, false}, "SUBSS": {4, false}, "MULSS": {4, false}, "DIVSS": {4, false},
	"COMISS": {4, false}, "UCOMISS": {4, false},
	"MOVSD": {8, true}, "VMOVSD": {8, true},
	"FMOVD": {8, false}, "FADDD": {8, false}, "FSUBD": {8, false}, "FSUBRD": {8, false},
	"FMULD": {8, false}, "FDIVD": {8, false}, "FDIVRD": {8, false},
	"FCOMD": {8, false}, "FCOMDP": {8, false},
	"ADDSD": {8, false}, "SUBSD": {8, false}, "MULSD": {8, false}, "DIVSD": {8, false},
	"COMISD": {8, false}, "UCOMISD": {8, false},
}

type asmGeneratedFloatPoolUse struct {
	owner ASMGeneratedFloatPoolOwner
	pool  int
}

func generatedASMFloatPools(source []byte, target string, member ASMDataMember, texts []ASMSourceText) ([]ASMGeneratedFloatPool, error) {
	if !bytes.Contains(source, []byte("$")) {
		return nil, nil // No source FCONST can occur without its immediate marker.
	}
	statements, err := asmDataStatements(source)
	if err != nil {
		return nil, err
	}
	if !X86SDKTarget(target) || len(texts) != len(member.Texts) || member.Flags&4 == 0 {
		return nil, contextError("generated float pool lacks its complete source/TEXT/target role")
	}
	seenTexts := make(map[int]bool, len(texts))
	for ordinal, owner := range texts {
		if owner.SourceOrdinal != ordinal || owner.ObjectOrdinal < 0 || owner.ObjectOrdinal >= len(member.Texts) || seenTexts[owner.ObjectOrdinal] {
			return nil, contextError("generated float pool source/TEXT ordinal changed")
		}
		text := member.Texts[owner.ObjectOrdinal]
		if owner.Name != text.Name || owner.ABI != text.ABI || owner.Namespace != text.Namespace ||
			owner.Relative != text.Relative || owner.Index != text.Index {
			return nil, contextError("generated float pool source/TEXT identity changed")
		}
		seenTexts[owner.ObjectOrdinal] = true
	}
	definitions := make(map[string][]ASMDataDefinition, len(member.Definitions))
	for _, definition := range member.Definitions {
		definitions[definition.Name] = append(definitions[definition.Name], definition)
	}
	var pools []ASMGeneratedFloatPool
	byName := make(map[string]int)
	uses := make([][]asmGeneratedFloatPoolUse, len(texts))
	textOrdinal := -1
	for ordinal, statement := range statements {
		// Labels do not produce an instruction or a DATA owner.
		for len(statement) >= 2 && statement[0].kind == scanner.Ident && statement[1].kind == ':' {
			statement = statement[2:]
		}
		if len(statement) == 0 {
			continue
		}
		if statement[0].text == "TEXT" {
			textOrdinal++
			continue // ASMSourceTextOrder already validated every exact declaration.
		}
		form, known := asmGeneratedFloatPoolForms[statement[0].text]
		if !known {
			continue
		}
		operands := asmDataOperands(statement[1:])
		if len(operands) < 1 || len(operands[0]) < 2 || operands[0][0].kind != '$' {
			continue
		}
		value, floating, err := asmGeneratedFloatPoolConstant(operands[0][1:])
		if err != nil {
			return nil, err
		}
		if !floating {
			continue // An integer immediate or symbolic address is not TYPE_FCONST.
		}
		if len(operands) != 2 || textOrdinal < 0 || textOrdinal >= len(texts) {
			return nil, contextError("generated float pool FCONST lacks its exact source TEXT/operand role")
		}
		if form.move && math.Float64bits(value) == 0 && asmGeneratedFloatPoolZeroXOR(operands[1]) {
			continue // The original float64 +0, not rounded f32 zero, selects XORPS.
		}
		bits := math.Float64bits(value)
		if form.width == 4 {
			bits = uint64(math.Float32bits(float32(value)))
		}
		name := fmt.Sprintf("$f%d.%0*x", form.width*8, form.width*2, bits)
		pool, present := byName[name]
		if !present {
			matches := definitions[name]
			if len(matches) != 1 || !validGeneratedFloatPoolDefinition(matches[0], form.width, bits, target) {
				return nil, contextError("generated float pool source/IEEE/name/hash/definition differs")
			}
			pool = len(pools)
			byName[name] = pool
			pools = append(pools, ASMGeneratedFloatPool{Definition: matches[0]})
		}
		text := texts[textOrdinal]
		uses[text.ObjectOrdinal] = append(uses[text.ObjectOrdinal], asmGeneratedFloatPoolUse{pool: pool,
			owner: ASMGeneratedFloatPoolOwner{StatementOrdinal: ordinal, TextSourceOrdinal: textOrdinal,
				TextObjectOrdinal: text.ObjectOrdinal, TextNamespace: text.Namespace,
				TextRelative: text.Relative, TextIndex: text.Index, Opcode: statement[0].text,
				SourceFloat64Bits: math.Float64bits(value)}})
	}
	if textOrdinal+1 != len(texts) {
		return nil, contextError("generated float pool source omitted its complete TEXT inventory")
	}
	if len(pools) == 0 {
		return nil, nil // Neither a symbol prefix nor its payload classifies DATA.
	}
	if err := joinGeneratedFloatPoolOwners(member, pools, byName, uses, target); err != nil {
		return nil, err
	}
	return pools, nil
}

func asmGeneratedFloatPoolConstant(tokens []asmDataToken) (float64, bool, error) {
	floating := false
	for _, token := range tokens {
		floating = floating || token.kind == scanner.Float
	}
	if !floating {
		return 0, false, nil
	}
	// Reuse the bounded Go assembler float grammar: float token, recursive
	// signs and parentheses only. ParseFloat handles hexadecimal/underscores;
	// integer-only and binary expressions never acquire this metadata role.
	parser := asmDataExpression{tokens: tokens}
	value := parser.floating()
	if parser.err != nil || parser.pos != len(tokens) {
		return 0, false, contextError("generated float pool has an unknown FCONST expression")
	}
	return value, true, nil
}

func asmGeneratedFloatPoolZeroXOR(operand []asmDataToken) bool {
	if len(operand) != 1 || operand[0].kind != scanner.Ident || !strings.HasPrefix(operand[0].text, "X") {
		return false
	}
	register, err := strconv.Atoi(strings.TrimPrefix(operand[0].text, "X"))
	return err == nil && register >= 0 && register <= 15 && operand[0].text == fmt.Sprintf("X%d", register)
}

func validGeneratedFloatPoolDefinition(definition ASMDataDefinition, width uint32, bits uint64, target string) bool {
	align := width
	if width == 8 && strings.HasSuffix(target, "/386") {
		align = 4
	}
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], bits)
	return definition.Namespace == TextSymbolHashed64 && definition.ABI == 0 && definition.Kind == 3 &&
		definition.Flags == 2 && definition.Flags2 == 0 && definition.Size == width && definition.Align == align &&
		len(definition.Relocations) == 0 && bytes.Equal(definition.Data, data[:width]) && bytes.Equal(definition.Hash, data[:])
}

func sameGeneratedFloatPools(first, second []ASMGeneratedFloatPool) bool {
	normalize := func(values []ASMGeneratedFloatPool) []ASMGeneratedFloatPool {
		result := append([]ASMGeneratedFloatPool(nil), values...)
		for index := range result {
			result[index].Definition.DataOffset = 0 // Full member observations retain physical offsets.
		}
		return result
	}
	return reflect.DeepEqual(normalize(first), normalize(second))
}

func asmDataWithoutGeneratedFloatPools(member ASMDataMember, pools []ASMGeneratedFloatPool) ASMDataMember {
	if len(pools) == 0 {
		return member
	}
	byIndex := make(map[uint32]ASMDataDefinition, len(pools))
	for _, pool := range pools {
		byIndex[pool.Definition.Index] = pool.Definition
	}
	definitions := make([]ASMDataDefinition, 0, len(member.Definitions))
	for _, definition := range member.Definitions {
		pool, present := byIndex[definition.Index]
		if !present || !reflect.DeepEqual(pool, definition) {
			definitions = append(definitions, definition)
		}
	}
	member.Definitions = definitions
	return member // Only the explicit DATA join sees this partition, never a literal reader.
}
