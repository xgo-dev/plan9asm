package plan9asm

import (
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// These 40 nonidentity entries are the complete explicit archX86 aliases.
// They are diagnostic spellings, never a lowering or ISA-support table.
var goAssemblerOracleX86Aliases = map[string]string{
	"JA": "JHI", "JAE": "JCC", "JB": "JCS", "JBE": "JLS", "JC": "JCS",
	"JE": "JEQ", "JG": "JGT", "JHS": "JCC", "JL": "JLT", "JLO": "JCS",
	"JNA": "JLS", "JNAE": "JCS", "JNB": "JCC", "JNBE": "JHI", "JNC": "JCC",
	"JNG": "JLE", "JNGE": "JLT", "JNL": "JGE", "JNLE": "JGT", "JNO": "JOC",
	"JNP": "JPC", "JNS": "JPL", "JNZ": "JNE", "JO": "JOS", "JP": "JPS",
	"JPE": "JPS", "JPO": "JPC", "JS": "JMI", "JZ": "JEQ",
	"MASKMOVDQU": "MASKMOVOU", "MOVD": "MOVQ", "MOVDQ2Q": "MOVQ",
	"MOVNTDQ": "MOVNTO", "MOVOA": "MOVO", "PSLLDQ": "PSLLO", "PSRLDQ": "PSRLO",
	"PADDD": "PADDL", "MOVBELL": "MOVBEL", "MOVBEQQ": "MOVBEQ", "MOVBEWW": "MOVBEW",
}

func goAssemblerOracleX86SourceDiagnostic(source, arch, output string) bool {
	if arch != "amd64" && arch != "386" {
		return false
	}
	// asmins appends two operand-class numbers after the complete Prog.
	// Consume that metadata only in its exact backend/mode diagnostic, never
	// as an arbitrary instruction suffix or an amd64 instruction permission.
	const mode32 = "asm: asmins: illegal in mode 32: "
	var ordinary []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, mode32) {
			if arch == "386" && goasmoracle.SourceDiagnosticLineWithListing(source, line, 0,
				func(original, listing []string) bool {
					return goAssemblerOracleX86Mode32Listing(original, listing) ||
						goAssemblerOracleX86Mode32FrameListing(source, line, original, listing)
				}) {
				return true
			}
			continue
		}
		ordinary = append(ordinary, line)
	}
	return goasmoracle.SourceDiagnosticLineWithListing(source, strings.Join(ordinary, "\n"), 0,
		func(original, listing []string) bool {
			return goAssemblerOracleX86Listing(original, listing) ||
				goAssemblerOracleX86AddressListing(original, listing, arch)
		})
}

func goAssemblerOracleX86Mode32Listing(original, listing []string) bool {
	if len(listing) < 5 {
		return false
	}
	tail := listing[len(listing)-4:]
	if tail[0] != "(" || tail[3] != ")" {
		return false
	}
	for _, token := range tail[1:3] {
		class, err := strconv.Atoi(token)
		// Go's complete Yxxx..Yindir directory is [0,Ymax), not an ISA
		// acceptance table. The current SDK test checks every directory entry.
		if err != nil || class < 0 || class >= 90 || strconv.Itoa(class) != token {
			return false
		}
	}
	instruction := listing[:len(listing)-4]
	return reflect.DeepEqual(original, instruction) || goAssemblerOracleX86Listing(original, instruction) ||
		goAssemblerOracleX86AddressListing(original, instruction, "386")
}

func goAssemblerOracleX86Statement(tokens []string) (opcode, suffix string, args [][]string, ok bool) {
	if len(tokens) == 0 {
		return "", "", nil, false
	}
	opcode, next := tokens[0], 1
	for next < len(tokens) && tokens[next] == "." {
		if next+1 >= len(tokens) {
			return "", "", nil, false
		}
		suffix += "." + tokens[next+1]
		next += 2
	}
	if next == len(tokens) {
		return opcode, suffix, nil, true
	}
	var delimiters []string
	start := next
	for i := next; i < len(tokens); i++ {
		switch tokens[i] {
		case ";", "\n", ":":
			return "", "", nil, false
		case "(", "[":
			delimiters = append(delimiters, tokens[i])
		case ")", "]":
			if len(delimiters) == 0 ||
				(tokens[i] == ")" && delimiters[len(delimiters)-1] != "(") ||
				(tokens[i] == "]" && delimiters[len(delimiters)-1] != "[") {
				return "", "", nil, false
			}
			delimiters = delimiters[:len(delimiters)-1]
		case ",":
			if len(delimiters) == 0 {
				if i == start {
					return "", "", nil, false
				}
				args = append(args, tokens[start:i])
				start = i + 1
			}
		}
	}
	if len(delimiters) != 0 || start == len(tokens) {
		return "", "", nil, false
	}
	args = append(args, tokens[start:])
	return opcode, suffix, args, true
}

func goAssemblerOracleX86Listing(original, listing []string) bool {
	sourceOp, suffix, args, sourceOK := goAssemblerOracleX86Statement(original)
	listedOp, listedSuffix, listedArgs, listingOK := goAssemblerOracleX86Statement(listing)
	if !sourceOK || !listingOK || suffix != listedSuffix || len(args) != len(listedArgs) {
		return false
	}
	switch suffix {
	case "", ".Z", ".SAE", ".SAE.Z", ".RN_SAE", ".RZ_SAE", ".RD_SAE", ".RU_SAE",
		".RN_SAE.Z", ".RZ_SAE.Z", ".RD_SAE.Z", ".RU_SAE.Z", ".BCST", ".BCST.Z":
	default:
		return false
	}
	if canonical, alias := goAssemblerOracleX86Aliases[sourceOp]; alias && canonical == listedOp {
		for i := range args {
			if !goAssemblerOracleX86OperandListing(args[i], listedArgs[i]) {
				return false
			}
		}
		return true
	}
	switch sourceOp {
	case "MOVSS", "MOVSD", "VMOVSS", "VMOVSD":
	default:
		return false
	}
	if listedOp != "XORPS" || len(args) < 2 || len(args[0]) < 2 || args[0][0] != "$" {
		return false
	}
	// Preserve the original lexical FLOAT leaf. Joining integer/dot tokens
	// must not invent a FLOAT that Go never read, such as `$0 . 0`.
	leaves := 0
	for _, token := range args[0][1:] {
		switch token {
		case "+", "-", "(", ")":
		default:
			if _, valid := parseGoFloatLiteral(token); !valid {
				return false
			}
			leaves++
		}
	}
	if leaves != 1 {
		return false
	}
	value, valid := parseGoFloatLiteral(strings.Join(args[0][1:], ""))
	if !valid || math.Float64bits(value) != 0 {
		return false
	}
	destination := args[len(args)-1]
	if len(destination) != 1 || !strings.HasPrefix(destination[0], "X") {
		return false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(destination[0], "X"))
	if err != nil || index < 0 || index > 15 || "X"+strconv.Itoa(index) != destination[0] ||
		!reflect.DeepEqual(destination, listedArgs[0]) {
		return false
	}
	for i := 1; i < len(args); i++ {
		if !reflect.DeepEqual(args[i], listedArgs[i]) {
			return false
		}
	}
	return true
}
