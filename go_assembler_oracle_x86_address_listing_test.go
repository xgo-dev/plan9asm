package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// This directory identifies lexical registers in the selected Go frontend.
// It grants neither a valid memory addressing form nor instruction support.
var goAssemblerOracleX86AddressRegisters struct {
	sync.Once
	names map[string]bool
}

func goAssemblerOracleX86AddressRegister(name, arch string) bool {
	goAssemblerOracleX86AddressRegisters.Do(func() {
		path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/list6.go")
		data, valid := goasmoracle.ReadSource(path)
		if !valid {
			return
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			return
		}
		var arrays []*ast.CompositeLit
		ast.Inspect(file, func(node ast.Node) bool {
			entry, ok := node.(*ast.ValueSpec)
			if !ok || len(entry.Names) != 1 || entry.Names[0].Name != "Register" || len(entry.Values) != 1 {
				return true
			}
			if array, ok := entry.Values[0].(*ast.CompositeLit); ok {
				arrays = append(arrays, array)
			}
			return false
		})
		if len(arrays) != 1 {
			return
		}
		names := make(map[string]bool)
		for _, entry := range arrays[0].Elts {
			literal, ok := entry.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil || names[name] {
				return
			}
			names[name] = true
		}
		if names["AX"] && names["SP"] && names["X0"] {
			goAssemblerOracleX86AddressRegisters.names = names
		}
	})
	return goAssemblerOracleX86AddressRegisters.names[name] || name == "g" && arch == "amd64"
}

func goAssemblerOracleX86AddressRole(tokens []string, arch string) (external, valid bool) {
	first := -1
	for index, text := range tokens {
		if text == "(" {
			first = index
			break
		}
	}
	if first < 0 || first+2 >= len(tokens) {
		return false, false
	}
	base := tokens[first+1]
	pseudo := base == "SB" || base == "FP" || base == "SP"
	if first > 0 {
		for index, text := range tokens[:first] {
			if index == 0 && pseudo && !goAssemblerOracleX86AddressRegister(text, arch) &&
				len(text) > 0 && (unicode.IsLetter([]rune(text)[0]) || strings.HasPrefix(text, "_")) {
				continue
			}
			if text == "+" || text == "-" || text == "<" || text == ">" {
				continue
			}
			if _, err := strconv.ParseUint(text, 0, 64); err != nil {
				return false, false
			}
		}
	}
	for position := first; position < len(tokens); {
		if position+2 >= len(tokens) || tokens[position] != "(" {
			return false, false
		}
		register := tokens[position+1]
		if !(position == first && pseudo) && !goAssemblerOracleX86AddressRegister(register, arch) {
			return false, false
		}
		end := position + 2
		if tokens[end] == "*" {
			if end+2 >= len(tokens) || position == first && pseudo {
				return false, false
			}
			switch tokens[end+1] {
			case "1", "2", "4", "8":
			default:
				return false, false
			}
			end += 2
		}
		if tokens[end] != ")" {
			return false, false
		}
		position = end + 1
	}
	return base == "SB", true
}

func goAssemblerOracleX86AddressListing(original, listing []string, arch string) bool {
	sourceOp, suffix, args, sourceOK := goAssemblerOracleX86Statement(original)
	listedOp, listedSuffix, listedArgs, listedOK := goAssemblerOracleX86Statement(listing)
	if !sourceOK || !listedOK || suffix != "" || listedSuffix != "" ||
		len(args) != 2 || len(listedArgs) != 2 || len(args[0]) < 4 || args[0][0] != "$" {
		return false
	}
	if canonical, alias := goAssemblerOracleX86Aliases[sourceOp]; alias {
		sourceOp = canonical
	}
	want := map[string]string{"MOVL": "LEAL", "MOVQ": "LEAQ"}[sourceOp]
	if want == "" || listedOp != want {
		return false
	}
	address := args[0][1:]
	external, valid := goAssemblerOracleX86AddressRole(address, arch)
	// Go excludes EXTERN and STATIC TYPE_ADDR only on I386. It is the source
	// mode, not host architecture or LLVM's interpretation of an LEA.
	return valid && !(arch == "386" && external) &&
		reflect.DeepEqual(address, listedArgs[0]) && reflect.DeepEqual(args[1], listedArgs[1])
}
