package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// This is the selected cmd/asm lexical namespace, not this library's register
// grammar. In particular R18/R28/R31 and old SDK Z/P/PN names can be symbols.
var arm64OracleLexicalNames struct {
	once      sync.Once
	registers map[string]bool
	reserved  map[string]bool
}

func arm64OracleIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for index, ch := range name {
		if !unicode.IsLetter(ch) && ch != '_' && ch != '·' && ch != '∕' &&
			!(index > 0 && unicode.IsDigit(ch)) {
			return false
		}
	}
	return true
}

func goAssemblerOracleARM64BareSymbol(name string) bool {
	arm64OracleLoadLexicalNames()
	return arm64OracleIdentifier(name) && arm64OracleLexicalNames.reserved != nil &&
		!arm64OracleLexicalNames.reserved[name]
}

func goAssemblerOracleARM64Register(name string) bool {
	arm64OracleLoadLexicalNames()
	return name != "SB" && name != "FP" && name != "PC" && name != "SP" &&
		arm64OracleLexicalNames.registers[name]
}

func arm64OracleLoadLexicalNames() {
	arm64OracleLexicalNames.once.Do(func() {
		files := make(map[string]*ast.File)
		for key, relative := range map[string]string{
			"arch":    "cmd/asm/internal/arch/arch.go",
			"aliases": "cmd/asm/internal/arch/arm64.go",
			"system":  "cmd/internal/obj/arm64/sysRegEnc.go",
			"special": "cmd/internal/obj/arm64/a.out.go",
		} {
			path := filepath.Join(runtime.GOROOT(), "src", relative)
			data, valid := goasmoracle.ReadSource(path)
			if !valid {
				return
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
			if err != nil {
				return
			}
			files[key] = file
		}
		registers, reserved, valid := arm64OracleLexicalNamespace(files)
		if valid {
			arm64OracleLexicalNames.registers = registers
			arm64OracleLexicalNames.reserved = reserved
		}
	})
}

func arm64OracleASTText(node ast.Node) string {
	var output bytes.Buffer
	if format.Node(&output, token.NewFileSet(), node) != nil {
		return ""
	}
	return strings.Join(strings.Fields(output.String()), " ")
}

func arm64OracleLiteralNames(file *ast.File, name string, firstColumn bool) ([]string, bool) {
	var result []string
	declarations := 0
	valid := true
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != name {
			return true
		}
		declarations++
		if len(value.Values) != 1 {
			valid = false
			return false
		}
		array, ok := value.Values[0].(*ast.CompositeLit)
		if !ok || len(array.Elts) == 0 {
			valid = false
			return false
		}
		if firstColumn && arm64OracleASTText(array.Type) != "[]struct { Name string Reg int16 Enc uint32 AccessFlags uint8 }" {
			valid = false
			return false
		}
		for _, element := range array.Elts {
			if firstColumn {
				row, ok := element.(*ast.CompositeLit)
				if !ok || len(row.Elts) != 4 {
					valid = false
					return false
				}
				element = row.Elts[0]
			}
			literal, ok := element.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				valid = false
				return false
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil || !arm64OracleIdentifier(name) {
				valid = false
				return false
			}
			result = append(result, name)
		}
		return false
	})
	return result, valid && declarations == 1
}

func arm64OracleLexicalNamespace(files map[string]*ast.File) (map[string]bool, map[string]bool, bool) {
	for _, key := range []string{"arch", "aliases", "system", "special"} {
		if files[key] == nil {
			return nil, nil, false
		}
	}
	registers := make(map[string]bool)
	var factory *ast.FuncDecl
	for _, declaration := range files["arch"].Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "archArm64" {
			if factory != nil || function.Body == nil {
				return nil, nil, false
			}
			factory = function
		}
	}
	if factory == nil {
		return nil, nil, false
	}
	banks := make(map[string]bool)
	processedWrites, actualWrites := 0, 0
	ast.Inspect(factory.Body, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for _, left := range assignment.Lhs {
				if index, ok := left.(*ast.IndexExpr); ok && arm64OracleASTText(index.X) == "register" {
					actualWrites++
				}
			}
		}
		return true
	})
	prefixes, system, finished := false, false, false
	for _, statement := range factory.Body.List {
		text := arm64OracleASTText(statement)
		if text == "instructions := make(map[string]obj.As)" {
			finished = true
			break
		}
		switch text {
		case "register := make(map[string]int16)":
		case "register[obj.Rconv(arm64.REGSP)] = int16(arm64.REGSP)":
			registers["RSP"] = true
			processedWrites++
		case `register["R18_PLATFORM"] = register["R18"]`:
			registers["R18_PLATFORM"] = true
			processedWrites++
		case `delete(register, "R18")`:
			delete(registers, "R18")
		case `delete(register, "R28")`:
			delete(registers, "R28")
		case `register["LR"] = arm64.REGLINK`, `register["SB"] = RSB`,
			`register["FP"] = RFP`, `register["PC"] = RPC`, `register["SP"] = RSP`,
			`register["g"] = arm64.REG_R28`:
			index := statement.(*ast.AssignStmt).Lhs[0].(*ast.IndexExpr)
			name, _ := strconv.Unquote(index.Index.(*ast.BasicLit).Value)
			registers[name] = true
			processedWrites++
		case "for i := 0; i < len(arm64.SystemReg); i++ { register[arm64.SystemReg[i].Name] = arm64.SystemReg[i].Reg }":
			if system {
				return nil, nil, false
			}
			names, valid := arm64OracleLiteralNames(files["system"], "SystemReg", true)
			if !valid {
				return nil, nil, false
			}
			for _, name := range names {
				if registers[name] {
					return nil, nil, false
				}
				registers[name] = true
			}
			system = true
			processedWrites++
		default:
			bank := ""
			for prefix, maximum := range map[string]int{"R": 31, "F": 31, "V": 31, "Z": 31, "P": 15, "PN": 15} {
				if text == fmt.Sprintf("for i := arm64.REG_%s0; i <= arm64.REG_%s%d; i++ { register[obj.Rconv(i)] = int16(i) }", prefix, prefix, maximum) {
					bank = prefix
					if banks[bank] {
						return nil, nil, false
					}
					banks[bank] = true
					for number := 0; number <= maximum; number++ {
						name := fmt.Sprintf("%s%d", bank, number)
						if bank == "R" && number == 31 {
							name = "ZR"
						}
						registers[name] = true
					}
					processedWrites++
				}
			}
			if bank != "" {
				continue
			}
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 ||
				arm64OracleASTText(assignment.Lhs[0]) != "registerPrefix" || prefixes {
				return nil, nil, false
			}
			literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
			if !ok || len(literal.Elts) != len(banks) {
				return nil, nil, false
			}
			seen := make(map[string]bool)
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					return nil, nil, false
				}
				name, err := strconv.Unquote(arm64OracleASTText(pair.Key))
				if err != nil || !banks[name] || seen[name] || arm64OracleASTText(pair.Value) != "true" {
					return nil, nil, false
				}
				seen[name] = true
			}
			prefixes = true
		}
	}
	if !finished || !prefixes || !system || processedWrites != actualWrites ||
		!banks["R"] || !banks["F"] || !banks["V"] || registers["R18"] || registers["R28"] {
		return nil, nil, false
	}
	reserved := make(map[string]bool, len(registers))
	for name := range registers {
		reserved[name] = true
	}
	groups := 0
	specials := make(map[string]bool)
	for _, declaration := range files["special"].Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		var names []string
		for _, spec := range group.Specs {
			value := spec.(*ast.ValueSpec)
			for _, name := range value.Names {
				if strings.HasPrefix(name.Name, "SPOP_") {
					names = append(names, name.Name)
				}
			}
		}
		if len(names) == 0 {
			continue
		}
		groups++
		if len(names) != len(group.Specs) || len(names) < 3 ||
			names[0] != "SPOP_PLDL1KEEP" || names[1] != "SPOP_BEGIN" || names[len(names)-1] != "SPOP_END" {
			return nil, nil, false
		}
		for _, name := range names {
			if name != "SPOP_BEGIN" && name != "SPOP_END" {
				word := strings.TrimPrefix(name, "SPOP_")
				if reserved[word] || !arm64OracleIdentifier(word) {
					return nil, nil, false
				}
				reserved[word] = true
				specials[word] = true
			}
		}
	}
	aliases := 0
	valid := true
	ast.Inspect(files["aliases"], func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || arm64OracleASTText(assignment.Lhs[0]) != "specialMapping" {
			return true
		}
		aliases++
		if len(assignment.Rhs) != 1 {
			valid = false
			return false
		}
		literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
		if !ok || len(literal.Elts) == 0 {
			valid = false
			return false
		}
		for _, element := range literal.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok {
				valid = false
				return false
			}
			name, err := strconv.Unquote(arm64OracleASTText(pair.Key))
			selector, selected := pair.Value.(*ast.SelectorExpr)
			if !selected || arm64OracleASTText(selector.X) != "arm64" || !strings.HasPrefix(selector.Sel.Name, "SPOP_") {
				valid = false
				return false
			}
			target := strings.TrimPrefix(selector.Sel.Name, "SPOP_")
			if err != nil || !arm64OracleIdentifier(name) || reserved[name] || !specials[target] {
				valid = false
				return false
			}
			reserved[name] = true
		}
		return false
	})
	return registers, reserved, valid && groups == 1 && aliases == 1
}
