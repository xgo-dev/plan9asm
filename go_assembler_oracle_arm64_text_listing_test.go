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

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// PKGINIT is a source flag only in newer SDKs. Determine its actual projection
// from that SDK's InitTextSym, not from the translator build version.
func goAssemblerOracleTextPKGInit() (present, valid bool) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/plist.go")
	data, valid := goasmoracle.ReadSource(path)
	if !valid {
		return false, false
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		return false, false
	}
	functions, projections := 0, 0
	valid = true
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "InitTextSym" {
			continue
		}
		functions++
		ast.Inspect(function, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			attribute, attrOK := call.Args[0].(*ast.Ident)
			if !ok || !attrOK || method.Sel.Name != "Set" || attribute.Name != "AttrPkgInit" {
				return true
			}
			projections++
			condition, ok := call.Args[1].(*ast.BinaryExpr)
			if !ok || condition.Op != token.NEQ {
				valid = false
				return true
			}
			mask, ok := condition.X.(*ast.BinaryExpr)
			zero, zeroOK := condition.Y.(*ast.BasicLit)
			if !ok || !zeroOK || mask.Op != token.AND || zero.Kind != token.INT || zero.Value != "0" {
				valid = false
				return true
			}
			flag, flagOK := mask.X.(*ast.Ident)
			name, nameOK := mask.Y.(*ast.Ident)
			present = flagOK && nameOK && flag.Name == "flag" && name.Name == "PKGINIT"
			valid = valid && present
			return true
		})
	}
	return present, valid && functions == 1 && projections <= 1
}

func goAssemblerOracleARM64TextListing(original, listing []string, detail string) bool {
	opcode, suffix, args, valid := goAssemblerOracleX86Statement(original)
	listedOpcode, listedSuffix, listedArgs, listedValid := goAssemblerOracleX86Statement(listing)
	if !valid || !listedValid || opcode != "TEXT" || listedOpcode != "TEXT" ||
		suffix != "" || listedSuffix != "" || len(args) < 2 || len(args) > 3 ||
		len(listedArgs) < 2 || len(listedArgs) > 3 || !reflect.DeepEqual(args[0], listedArgs[0]) {
		return false
	}
	flags := int64(0)
	if len(args) == 3 {
		if len(args[1]) != 1 {
			return false
		}
		var err error
		flags, err = strconv.ParseInt(args[1][0], 0, 32)
		if err != nil || flags < 0 || flags >= 1<<14 {
			return false
		}
	}
	frameTokens := args[len(args)-1]
	if len(frameTokens) < 2 || frameTokens[0] != "$" {
		return false
	}
	position, sign := 1, int64(1)
	if frameTokens[position] == "-" {
		position, sign = position+1, -1
	}
	if position >= len(frameTokens) {
		return false
	}
	frame, err := strconv.ParseInt(frameTokens[position], 0, 32)
	if err != nil || frame < 0 {
		return false
	}
	frame *= sign
	position++
	wantSize := "$" + strconv.FormatInt(frame, 10)
	if position < len(frameTokens) {
		if len(frameTokens)-position != 2 || frameTokens[position] != "-" {
			return false
		}
		argc, err := strconv.ParseInt(frameTokens[position+1], 0, 32)
		if err != nil || argc < 0 {
			return false
		}
		wantSize += "-" + strconv.FormatInt(argc, 10)
	}
	if strings.Join(listedArgs[len(listedArgs)-1], "") != wantSize || frame == -8 {
		return false
	}
	autosize := frame
	if flags&512 == 0 {
		if frame > 1<<31-1-8 {
			return false
		}
		autosize += 8
	}
	if autosize == 0 || autosize%16 == 8 || autosize&15 == 0 {
		return false
	}
	wantError := "unaligned frame size " + strconv.FormatInt(autosize-8, 10) + " - must be 16 aligned"
	if detail != wantError {
		return false
	}
	var attributes []string
	for _, attribute := range []struct {
		bit  int64
		name string
	}{
		{2, "DUPOK"}, {4, "NOSPLIT"}, {1024, "REFLECTMETHOD"}, {32, "WRAPPER"},
		{64, "NEEDCTXT"}, {512, "NOFRAME"}, {4096, "ABIWRAPPER"},
	} {
		if flags&attribute.bit != 0 {
			attributes = append(attributes, attribute.name)
		}
	}
	if flags&8192 != 0 {
		present, valid := goAssemblerOracleTextPKGInit()
		if !valid {
			return false
		}
		if present {
			attributes = append(attributes, "PKGINIT")
		}
	}
	if flags&2048 != 0 {
		attributes = append(attributes, "TOPFRAME")
	}
	if len(attributes) == 0 {
		return len(listedArgs) == 2
	}
	return len(listedArgs) == 3 && strings.Join(listedArgs[1], "") == strings.Join(attributes, "|")
}
