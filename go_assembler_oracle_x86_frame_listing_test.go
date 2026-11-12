package plan9asm

import (
	"bytes"
	"math"
	"reflect"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// This is only an original-Go diagnostic join, not a frame/operand permission.
// The selected SDK source and actual commands independently check obj6.go's
// preprocess rule: I386 has bpsize0, AUTO += deltasp and PARAM += deltasp+4.
// Its bounded context is literal NOSPLIT TEXT, one focused instruction, NOP
// and explicit W/L stack steps, ending at RET. Branches, calls, CPP, other
// writes to SP and post-RET source are deliberately not modeled as a CFG.
func goAssemblerOracleX86Mode32FrameListing(source, diagnostic string, original, listing []string) bool {
	data, ok := goasmoracle.ReadSource(source)
	if !ok {
		return false
	}
	marker := "(" + source + ":"
	_, position, found := strings.Cut(diagnostic, marker)
	number, _, ended := strings.Cut(position, ")")
	focus, err := strconv.Atoi(number)
	lines := strings.Split(string(data), "\n")
	if !found || !ended || err != nil || focus < 1 || strconv.Itoa(focus) != number || focus > len(lines) || len(lines) > 4096 {
		return false
	}
	statements := make([][]string, len(lines))
	start, end := -1, len(lines)
	for index, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			return false
		}
		tokens, valid := goAssemblerOracleX86FrameTokens(line)
		if !valid {
			return false
		}
		statements[index] = tokens
		if len(tokens) != 0 && tokens[0] == "TEXT" {
			if index < focus-1 {
				start = index
			} else if end == len(lines) {
				end = index
			}
		}
	}
	if start < 0 || !reflect.DeepEqual(statements[focus-1], original) {
		return false
	}
	frame, valid := goAssemblerOracleX86FrameText(statements[start])
	if !valid {
		return false
	}
	delta, atFocus := frame, int64(0)
	returned := false
	for index := start + 1; index < end; index++ {
		tokens := statements[index]
		if len(tokens) == 0 {
			continue
		}
		if returned {
			return false
		}
		if index == focus-1 {
			atFocus = delta
			continue
		}
		switch {
		case reflect.DeepEqual(tokens, []string{"NOP"}):
			continue
		case reflect.DeepEqual(tokens, []string{"RET"}):
			if index < focus-1 || delta != frame {
				return false
			}
			returned = true
		default:
			step, known := goAssemblerOracleX86FrameStep(tokens)
			if !known || delta+step < math.MinInt32 || delta+step > math.MaxInt32 {
				return false
			}
			delta += step
		}
	}
	if !returned {
		return false
	}
	opcode, suffix, args, valid := goAssemblerOracleX86Statement(original)
	if !valid {
		return false
	}
	rewritten := []string{opcode}
	for _, part := range strings.Split(strings.TrimPrefix(suffix, "."), ".") {
		if part != "" {
			rewritten = append(rewritten, ".", part)
		}
	}
	changed := false
	for index, operand := range args {
		adjusted, role, accepted := goAssemblerOracleX86FrameOperand(operand, atFocus)
		if !accepted {
			return false
		}
		if index != 0 {
			rewritten = append(rewritten, ",")
		}
		rewritten = append(rewritten, adjusted...)
		changed = changed || role
	}
	after, stable := goasmoracle.ReadSource(source)
	return changed && stable && bytes.Equal(data, after) && goAssemblerOracleX86Mode32Listing(rewritten, listing)
}

func goAssemblerOracleX86FrameTokens(line string) ([]string, bool) {
	var lex scanner.Scanner
	lex.Init(strings.NewReader(line))
	lex.Mode = scanner.ScanIdents | scanner.ScanInts | scanner.ScanComments | scanner.SkipComments
	lex.IsIdentRune = func(r rune, index int) bool {
		return r == '_' || r == '·' || r == '∕' || unicode.IsLetter(r) || index > 0 && unicode.IsDigit(r)
	}
	valid := true
	lex.Error = func(*scanner.Scanner, string) { valid = false }
	var tokens []string
	for token := lex.Scan(); token != scanner.EOF; token = lex.Scan() {
		if len(tokens) == 256 {
			return nil, false
		}
		tokens = append(tokens, lex.TokenText())
	}
	return tokens, valid
}

func goAssemblerOracleX86FrameInteger(tokens []string) (int64, bool) {
	if len(tokens) == 0 || len(tokens) > 2 {
		return 0, false
	}
	if len(tokens) == 2 && tokens[0] != "+" && tokens[0] != "-" {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.Join(tokens, ""), 0, 64)
	return value, err == nil
}

func goAssemblerOracleX86FrameText(tokens []string) (int64, bool) {
	opcode, suffix, args, ok := goAssemblerOracleX86Statement(tokens)
	if !ok || opcode != "TEXT" || suffix != "" || len(args) != 3 ||
		len(args[0]) != 4 || args[0][1] != "(" || args[0][2] != "SB" || args[0][3] != ")" ||
		!goAssemblerOracleX86FrameIdentifier(args[0][0]) ||
		!reflect.DeepEqual(args[1], []string{"4"}) || len(args[2]) < 4 || args[2][0] != "$" {
		return 0, false
	}
	size := args[2][1:]
	separator := 1
	if size[0] == "+" || size[0] == "-" {
		separator++
	}
	if len(size) != separator+2 || size[separator] != "-" {
		return 0, false
	}
	frame, frameOK := goAssemblerOracleX86FrameInteger(size[:separator])
	arguments, argsOK := goAssemblerOracleX86FrameInteger(size[separator+1:])
	if !frameOK || !argsOK || frame < math.MinInt32 || frame > math.MaxInt32 || arguments < 0 || arguments > math.MaxInt32 {
		return 0, false
	}
	if frame < 0 {
		frame = 0
	}
	return frame, frame%4 == 0
}

func goAssemblerOracleX86FrameStep(tokens []string) (int64, bool) {
	opcode, suffix, args, ok := goAssemblerOracleX86Statement(tokens)
	if !ok || suffix != "" {
		return 0, false
	}
	if opcode == "ADJSP" {
		if len(args) != 1 || len(args[0]) < 2 || args[0][0] != "$" {
			return 0, false
		}
		step, valid := goAssemblerOracleX86FrameInteger(args[0][1:])
		return step, valid && step >= math.MinInt32 && step <= math.MaxInt32
	}
	var step int64
	switch opcode {
	case "PUSHL", "PUSHFL":
		step = 4
	case "PUSHW", "PUSHFW":
		step = 2
	case "POPL", "POPFL":
		step = -4
	case "POPW", "POPFW":
		step = -2
	default:
		return 0, false
	}
	if strings.HasSuffix(opcode, "FL") || strings.HasSuffix(opcode, "FW") {
		return step, len(args) == 0
	}
	if len(args) != 1 || len(args[0]) != 1 {
		return 0, false
	}
	switch args[0][0] {
	case "AX", "BX", "CX", "DX", "BP", "SI", "DI":
		return step, true
	}
	return 0, false
}

func goAssemblerOracleX86FrameIdentifier(name string) bool {
	for _, first := range name {
		return first == '_' || first == '·' || first == '∕' || unicode.IsLetter(first)
	}
	return false
}

func goAssemblerOracleX86FrameOperand(operand []string, delta int64) ([]string, bool, bool) {
	start := 0
	if len(operand) != 0 && operand[0] == "$" {
		start++
	}
	open := start + 1
	for open < len(operand) && operand[open] != "(" {
		open++
	}
	if open+2 >= len(operand) || operand[open+2] != ")" || operand[open+1] != "FP" && operand[open+1] != "SP" {
		return operand, false, true
	}
	// A bare physical (SP) is not NAME_AUTO. Only an original identifier
	// before the pseudo-base may acquire the independently checked bias.
	name, valid := goAssemblerOracleX86FrameTokens(operand[start])
	if !valid || len(name) != 1 || name[0] != operand[start] || !goAssemblerOracleX86FrameIdentifier(name[0]) {
		return nil, false, false
	}
	offset := int64(0)
	if open > start+1 {
		offset, valid = goAssemblerOracleX86FrameInteger(operand[start+1 : open])
		if !valid {
			return nil, false, false
		}
	}
	tail := operand[open+3:]
	if len(tail) != 0 {
		if len(tail) != 5 || tail[0] != "(" || tail[2] != "*" || tail[4] != ")" {
			return nil, false, false
		}
		switch tail[1] {
		case "AX", "BX", "CX", "DX", "BP", "SI", "DI":
		default:
			return nil, false, false
		}
		if tail[3] != "1" && tail[3] != "2" && tail[3] != "4" && tail[3] != "8" {
			return nil, false, false
		}
	}
	if operand[open+1] == "FP" {
		delta += 4
	}
	if delta > 0 && offset > math.MaxInt64-delta || delta < 0 && offset < math.MinInt64-delta {
		return nil, false, false
	}
	offset += delta
	result := append([]string(nil), operand[:start+1]...)
	if offset != 0 {
		sign, digits := "+", strconv.FormatInt(offset, 10)
		if offset < 0 {
			sign, digits = "-", strings.TrimPrefix(digits, "-")
		}
		result = append(result, sign, digits)
	}
	result = append(result, operand[open:]...)
	return result, true, true
}
