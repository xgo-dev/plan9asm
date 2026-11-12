package goasmrules

import (
	"fmt"
	"strings"
)

// X86PackedBinarySyntaxWitnesses expands the complete _yvandnpd grammar used
// by packed binary families. These are source-syntax candidates: low-bank X/Y
// spellings can select VEX even when an EVEX table row also matches. Actual Go
// objects and semantic oracles must independently establish encoding identity.
// Frontend architecture restrictions are likewise checked by the actual Go
// assembler, never silently pruned here.
func X86PackedBinarySyntaxWitnesses(rule X86AVXRule) ([]string, error) {
	if rule.Ytab != "_yvandnpd" {
		return nil, fmt.Errorf("%s is outside the audited packed binary table grammar", rule.Opcode)
	}
	return x86PackedBinarySyntaxWitnesses(rule)
}

func x86PackedBinarySyntaxWitnesses(rule X86AVXRule) ([]string, error) {
	return x86PackedSyntaxWitnesses(rule, false)
}

func x86PackedMoveTable(table string) bool {
	return table == "_yvmovdqa" || table == "_yvmovapd" || table == "_yvmovdqa32"
}

func x86PackedMoveStoreRow(rule X86AVXRule) bool {
	return x86PackedMoveTable(rule.Ytab) && (rule.ZCase == "Zvex_r_v_rm" ||
		rule.ZCase == "Zevex_r_v_rm" || rule.ZCase == "Zevex_r_k_rm")
}

// These three original ytabs share count transport, independently of mnemonic,
// lane width and numerical shift semantics. Encoding values remain in OpBytes.
func x86PackedUniformShiftTable(table string) bool {
	return table == "_yvpslld" || table == "_yvpsraq" || table == "_yvpslldq"
}

func x86PackedImmediateExtensionRow(rule X86AVXRule) bool {
	return (x86PackedUniformShiftTable(rule.Ytab) || rule.Ytab == "_yvprold") && (rule.ZCase == "Zvex_i_rm_vo" ||
		rule.ZCase == "Zevex_i_rm_vo" || rule.ZCase == "Zevex_i_rm_k_vo")
}

func x86PackedImmediateRegisterRow(rule X86AVXRule) bool {
	return rule.Ytab == "_yvpshufd" && (rule.ZCase == "Zvex_i_rm_r" ||
		rule.ZCase == "Zevex_i_rm_r" || rule.ZCase == "Zevex_i_rm_k_r")
}

// Integer widening spells both element sizes in its BW/BD/BQ/WD/WQ/DQ
// suffix. Keep that ratio independent of the register carrier's capacity;
// an X source alone cannot distinguish m2/m4/m8/m16 tuples.
func x86PackedWideningRatio(rule X86AVXRule) int {
	name := rule.Opcode
	if len(name) != 9 || !strings.HasPrefix(name, "VPMOVSX") && !strings.HasPrefix(name, "VPMOVZX") {
		return 0
	}
	input, output := strings.IndexByte("BWDQ", name[7]), strings.IndexByte("BWDQ", name[8])
	if input < 0 || output <= input {
		return 0
	}
	ratio := 1 << (output - input)
	table := "_yvbroadcastss"
	if ratio == 2 {
		table = "_yvcvtdq2pd"
	}
	if rule.Ytab != table {
		return 0
	}
	return ratio
}

func x86PackedWideningSource(destinationBytes, ratio int, evex bool) (string, int) {
	tuple, class := destinationBytes/ratio, "Yxm"
	if tuple > 16 {
		class = "Yym"
	}
	if evex {
		class += "Evex"
	}
	return class, tuple
}

func x86PackedSyntaxWitnesses(rule X86AVXRule, unary bool) ([]string, error) {
	move, store := x86PackedMoveTable(rule.Ytab), x86PackedMoveStoreRow(rule)
	shift, extension := x86PackedUniformShiftTable(rule.Ytab), x86PackedImmediateExtensionRow(rule)
	registerImmediate := x86PackedImmediateRegisterRow(rule)
	widening := x86PackedWideningRatio(rule)
	immediate := extension || registerImmediate
	scalar := rule.Ytab == "_yvaddsd" || rule.Ytab == "_yvgetexpsd"
	floating := rule.Ytab == "_yvaddpd" || scalar
	binaryTable := rule.Ytab == "_yvandnpd" || rule.Ytab == "_yvblendmpd" ||
		rule.Ytab == "_yvaddsubpd" || rule.Ytab == "_yvpcmpeqb" || rule.Ytab == "_yvprold" || floating || shift
	unaryTable := rule.Ytab == "_yvmovddup" || rule.Ytab == "_yvexpandpd" || move || registerImmediate || widening != 0
	if (!unary && !binaryTable || unary && !unaryTable) || rule.Prefix != "Pavx" {
		return nil, fmt.Errorf("%s is outside the audited packed vector table grammar", rule.Opcode)
	}
	maskCase := "Zevex_rm_v_k_r"
	if immediate {
		maskCase = "Zevex_i_rm_k_vo"
	}
	if registerImmediate {
		maskCase = "Zevex_i_rm_k_r"
	}
	if unary && !immediate {
		maskCase = "Zevex_rm_k_r"
	}
	if store {
		maskCase = "Zevex_r_k_rm"
	}
	masked := rule.ZCase == maskCase
	evex := masked || rule.ZCase == "Zevex_rm_v_r" || store && rule.ZCase == "Zevex_r_v_rm" ||
		extension && rule.ZCase == "Zevex_i_rm_vo" || registerImmediate && rule.ZCase == "Zevex_i_rm_r"
	if scalar {
		row := 0
		if rule.Ytab == "_yvaddsd" && evex {
			row++
		}
		if masked {
			row++
		}
		if rule.RowIndex != row {
			return nil, fmt.Errorf("scalar source row ordinal differs from its encoding/mask transport")
		}
	}
	if rule.Ytab == "_yvprold" && (!immediate || !evex) {
		return nil, fmt.Errorf("packed immediate rotates require an EVEX immediate format")
	}
	if rule.Ytab == "_yvpslldq" && (!immediate || masked) {
		return nil, fmt.Errorf("per-128-bit byte shifts require an unmasked immediate format")
	}
	maskResult := rule.Ytab == "_yvpcmpeqb" && evex
	if (rule.Ytab == "_yvaddsubpd" || rule.Ytab == "_yvmovdqa") && evex ||
		(rule.Ytab == "_yvexpandpd" || rule.Ytab == "_yvmovdqa32" || rule.Ytab == "_yvpsraq" || rule.Ytab == "_yvgetexpsd") && !evex {
		return nil, fmt.Errorf("%s encoding generation differs from its packed table", rule.Opcode)
	}
	if !evex && rule.ZCase != "Zvex_rm_v_r" && !(store && rule.ZCase == "Zvex_r_v_rm") &&
		!(extension && rule.ZCase == "Zvex_i_rm_vo") && !(registerImmediate && rule.ZCase == "Zvex_i_rm_r") {
		return nil, fmt.Errorf("%s has an unmodeled packed vector zcase %s", rule.Opcode, rule.ZCase)
	}
	count := 3
	if masked {
		count = 4
	}
	if unary && !immediate {
		count--
	}
	if len(rule.Classes) != count {
		return nil, fmt.Errorf("%s packed vector arity differs from its zcase", rule.Opcode)
	}
	bank := ""
	for _, candidate := range []struct {
		memory, register, bank string
	}{
		{"Yxm", "Yxr", "X"},
		{"Yym", "Yyr", "Y"},
		{"YxmEvex", "YxrEvex", "X"},
		{"YymEvex", "YyrEvex", "Y"},
		{"Yzm", "Yzr", "Z"},
	} {
		resultClass := candidate.register
		if maskResult {
			resultClass = "Yk"
		}
		firstClass, secondClass := candidate.memory, candidate.register
		if widening != 0 {
			bytes := map[string]int{"X": 16, "Y": 32, "Z": 64}[candidate.bank]
			firstClass, _ = x86PackedWideningSource(bytes, widening, evex)
		}
		if shift && !immediate {
			// Register/m128 counts retain X even when data/result is Y/Z.
			firstClass = "Yxm"
			if evex {
				firstClass += "Evex"
			}
		}
		if immediate {
			firstClass, secondClass = "Yu8", candidate.memory
			if !evex {
				if extension {
					secondClass = candidate.register
				}
				if rule.Classes[0] == "Yi8" {
					firstClass = "Yi8"
				}
			}
		}
		if store {
			firstClass, resultClass = candidate.register, candidate.memory
		}
		if rule.Classes[0] == firstClass && (unary && !immediate || rule.Classes[1] == secondClass) &&
			rule.Classes[count-1] == resultClass {
			bank = candidate.bank
			break
		}
	}
	if bank == "" || !evex && bank == "Z" || scalar && bank != "X" || masked && rule.Classes[count-2] != "Yknot0" {
		return nil, fmt.Errorf("%s has unmodeled packed vector operand classes %v", rule.Opcode, rule.Classes)
	}
	stride := 2
	if evex {
		stride = 3
	}
	if extension {
		stride++ // The selected opcode is followed by a literal ModRM /digit.
	}
	if rule.EncodingOffset < 0 || rule.EncodingOffset+stride > len(rule.OpBytes) {
		return nil, fmt.Errorf("%s encoding offset %d is outside its complete opBytes", rule.Opcode, rule.EncodingOffset)
	}
	encoding := rule.OpBytes[rule.EncodingOffset]
	width := map[string]string{"X": "128", "Y": "256", "Z": "512"}[bank]
	kind := "vex"
	if evex {
		kind = "evex"
	}
	if !hasEncodingTerm(encoding, kind+width) {
		return nil, fmt.Errorf("%s operand width %s differs from encoding %s", rule.Opcode, bank, encoding)
	}
	features := ""
	if evex {
		features = rule.OpBytes[rule.EncodingOffset+1]
	}
	rounding := hasEncodingTerm(features, "evexRoundingEnabled")
	sae := hasEncodingTerm(features, "evexSaeEnabled")
	if rounding && sae || (rounding || sae) && (!floating || !scalar && bank != "Z") {
		return nil, fmt.Errorf("%s adds unaudited rounding/SAE to the packed binary grammar", rule.Opcode)
	}
	if maskResult && hasEncodingTerm(features, "evexZeroingEnabled") {
		return nil, fmt.Errorf("%s adds vector zeroing to a mask result", rule.Opcode)
	}
	destination := bank + "2"
	if maskResult {
		destination = "K2"
	}
	var witnesses []string
	emit := func(source, suffix string) {
		last := destination
		if store {
			source, last = bank+"0", source
		}
		operands := []string{source}
		if immediate {
			literal := "$7"
			if rule.Classes[0] == "Yi8" {
				literal = "$-1"
			}
			operands = []string{literal, source}
		} else if !unary {
			operands = append(operands, bank+"1")
		}
		if masked {
			operands = append(operands, "K1")
		}
		operands = append(operands, last)
		witnesses = append(witnesses, rule.Opcode+suffix+" "+strings.Join(operands, ","))
	}
	sources := []string{bank + "0", "(AX)"}
	if widening != 0 {
		sources[0] = strings.ToUpper(rule.Classes[0][1:2]) + "0"
	}
	if shift && !immediate {
		sources[0] = "X0"
	}
	if extension && !evex {
		sources = sources[:1] // VEX immediate rows are register-only.
	}
	if store {
		sources[0] = destination
	}
	for _, source := range sources {
		if move && !store && source != "(AX)" {
			continue // Register alternatives select the earlier store row.
		}
		emit(source, "")
		if masked && hasEncodingTerm(features, "evexZeroingEnabled") {
			emit(source, ".Z")
		}
	}
	if hasEncodingTerm(features, "evexBcstN4") || hasEncodingTerm(features, "evexBcstN8") {
		emit("(AX)", ".BCST")
		if masked && hasEncodingTerm(features, "evexZeroingEnabled") {
			emit("(AX)", ".BCST.Z")
		}
	}
	if rounding {
		for _, control := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
			emit(bank+"0", "."+control)
			if masked && hasEncodingTerm(features, "evexZeroingEnabled") {
				emit(bank+"0", "."+control+".Z")
			}
		}
	}
	if sae {
		emit(bank+"0", ".SAE")
		if masked && hasEncodingTerm(features, "evexZeroingEnabled") {
			emit(bank+"0", ".SAE.Z")
		}
	}
	return witnesses, nil
}

func hasEncodingTerm(expression, term string) bool {
	for _, candidate := range strings.FieldsFunc(expression, func(r rune) bool {
		return r == '|' || r == '(' || r == ')' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if candidate == term {
			return true
		}
	}
	return false
}
