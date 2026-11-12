package plan9asm

import (
	"reflect"
	"strconv"
	"strings"
)

func goAssemblerOracleX86IntegerLiteral(tokens []string) (int64, bool) {
	negative := len(tokens) == 2 && tokens[0] == "-"
	if len(tokens) == 2 && (tokens[0] == "+" || negative) {
		tokens = tokens[1:]
	}
	if len(tokens) != 1 {
		return 0, false
	}
	value, err := strconv.ParseUint(tokens[0], 0, 64)
	if negative {
		value = -value
	}
	return int64(value), err == nil
}

// obj.Addr.writeNameTo renders NAME_NONE literal offsets as signed decimal.
// Zero is omitted only with a base, not for an absolute/index-only address.
// This diagnostic join grants no address, frame, instruction or ABI role.
func goAssemblerOracleX86MemoryLiteralListing(original, listing []string) bool {
	open := len(original)
	for index, text := range original {
		if text == "(" {
			open = index
			break
		}
	}
	value, valid := goAssemblerOracleX86IntegerLiteral(original[:open])
	if !valid {
		return false
	}
	address, base := original[open:], false
	if len(address) != 0 {
		if len(address) < 3 || address[1] == "SB" || address[1] == "FP" || address[1] == "SP" {
			return false // Symbolic and AUTO/PARAM rebasing retain separate observations.
		}
		if _, valid := goAssemblerOracleX86AddressRole(address, ""); !valid {
			return false
		}
		base = address[2] == ")"
		if !base && len(address) != 5 {
			return false
		}
	}
	var want []string
	if value != 0 || !base {
		printed := strconv.FormatInt(value, 10)
		if strings.HasPrefix(printed, "-") {
			want, printed = append(want, "-"), strings.TrimPrefix(printed, "-")
		}
		want = append(want, printed)
	}
	return reflect.DeepEqual(append(want, address...), listing)
}
