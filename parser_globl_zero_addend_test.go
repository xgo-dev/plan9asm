package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// cmd/asm's asmGlobl calls address -> symbolReference -> expr and then
// validSymbol(..., false). The complete integer expression must evaluate to
// zero; its spelling is not part of the symbol's identity. These spellings
// exercise the independent Go grammar, not splitSymPlusOff's implementation.
var globlZeroAddendCases = []struct{ name, addend string }{
	{"omitted", ""},
	{"positive", "+0"},
	{"negative", "-0"},
	{"hexadecimal", "+0x0"},
	{"octal", "+00"},
	{"binary", "+0b0"},
	{"explicit_octal", "+0o0"},
	{"positive_spaces", " + 0 "},
	{"negative_spaces", " - 0 "},
	{"subtract", "+(1-1)"},
	{"multiply_spaces", " + ((8 * 3) - 24) "},
	{"shift", "+((1<<7)-128)"},
	{"remainder", "+(17%17)"},
	{"divide", "+(17/17-1)"},
	{"bitwise", "+((17&3)^1)"},
	{"or", "+(0|0)"},
	{"complement_wrap", "+~0+1"},
	{"character", "+('A'-65)"},
	{"nested_sign", "+(-(-0))"},
}

type globlZeroAddendSymbol struct {
	name, sourceName, caseName string
	readOnly, local            bool
}

func globlZeroAddendSource(withFunction bool) (string, []globlZeroAddendSymbol) {
	var source strings.Builder
	var symbols []globlZeroAddendSymbol
	for index, row := range globlZeroAddendCases {
		for _, local := range []bool{false, true} {
			for _, readOnly := range []bool{false, true} {
				name := fmt.Sprintf("zero_globl_%02d_%t_%t", index, local, readOnly)
				originalName := name
				if local {
					originalName += "<>"
				}
				fmt.Fprintf(&source, "DATA %s+0(SB)/8,$0x1122334455667788\n", originalName)
				fmt.Fprintf(&source, "DATA %s+16(SB)/8,$\"a+0;b\"\n", originalName)
				fmt.Fprintf(&source, "DATA %s+36(SB)/4,$0xa1b2c3d4\n", originalName)
				fmt.Fprintf(&source, "DATA %s+71(SB)/1,$0x5a\n", originalName)
				if readOnly {
					fmt.Fprintf(&source, "GLOBL %s%s(SB),8,$72\n", originalName, row.addend)
				} else {
					// The legacy two-operand spelling has the same address grammar.
					fmt.Fprintf(&source, "GLOBL %s%s(SB),$72\n", originalName, row.addend)
				}
				symbols = append(symbols, globlZeroAddendSymbol{
					name: name, sourceName: originalName, caseName: row.name,
					readOnly: readOnly, local: local,
				})
			}
		}
	}
	if withFunction {
		source.WriteString("TEXT ·Probe(SB),4,$0-0\nRET\n")
	}
	return source.String(), symbols
}

func globlZeroAddendInitialBytes() []byte {
	// This expected image is independent of both source parsers/emitters. It
	// includes sparse holes, a padded quoted payload and the final extent byte.
	want := make([]byte, 72)
	binary.LittleEndian.PutUint64(want, 0x1122334455667788)
	copy(want[16:24], "a+0;b")
	binary.LittleEndian.PutUint32(want[36:40], 0xa1b2c3d4)
	want[71] = 0x5a
	return want
}

func TestParseGLOBLZeroAddendFiveArchitectures(t *testing.T) {
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			for _, row := range globlZeroAddendCases {
				for _, name := range []string{"literal", "literal<>", "·literal", "·literal<>"} {
					for _, flags := range []string{"", "RODATA,"} {
						t.Run(row.name+"/"+name+"/"+flags, func(t *testing.T) {
							baseline, err := Parse(target.arch, "GLOBL "+name+"(SB),"+flags+"$72\n")
							if err != nil || len(baseline.Globl) != 1 {
								t.Fatal("the no-addend control must parse", err)
							}
							file, err := Parse(target.arch, "GLOBL "+name+row.addend+"(SB),"+flags+"$72\n")
							if err != nil || len(file.Globl) != 1 {
								t.Fatal("Go's zero displacement is a legal GLOBL address", err)
							}
							if !reflect.DeepEqual(file.Globl, baseline.Globl) {
								t.Fatalf("zero displacement changed identity, flags or extent: got=%+v want=%+v", file.Globl, baseline.Globl)
							}
						})
					}
				}
			}
		})
	}
}

func globlZeroAddendGoObject(t *testing.T, goos, goarch, source string, symbols []globlZeroAddendSymbol) {
	t.Helper()
	directory := t.TempDir()
	input, object := filepath.Join(directory, "globl.s"), filepath.Join(directory, "globl.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "literal", "-o", object, input)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS="+goos, "GOARCH="+goarch)
	listing, commandErr := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, listing, commandErr, ctx.Err(), true, goarch, "literal"); failure != nil {
		t.Fatalf("actual original GLOBL object: %v\n%s", failure, listing)
	}
	inputBytes, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(inputBytes, []byte(source)) {
		t.Fatal("the observed original source changed", err)
	}
	objectBytes, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	header := strings.Fields(string(bytes.SplitN(objectBytes, []byte("\n"), 2)[0]))
	if len(header) < 5 || header[0] != "go" || header[1] != "object" ||
		header[2] != goos || header[3] != goarch || header[4] != runtime.Version() {
		t.Fatal("the original object does not bind the selected SDK and target", header)
	}
	globlZeroAddendCheckGoListing(t, string(listing), symbols)
	t.Logf("actual GLOBL original object: SDK=%s target=%s/%s symbols=%d source=%x object=%x listing=%x",
		runtime.Version(), goos, goarch, len(symbols), sha256.Sum256(inputBytes), sha256.Sum256(objectBytes), sha256.Sum256(listing))
}

func globlZeroAddendCheckGoListing(t *testing.T, listing string, symbols []globlZeroAddendSymbol) {
	t.Helper()
	wanted := make(map[string]globlZeroAddendSymbol, len(symbols))
	for _, symbol := range symbols {
		wanted[symbol.name] = symbol
	}
	seen := make(map[string]bool, len(symbols))
	lines := strings.Split(listing, "\n")
	for line, text := range lines {
		fields := strings.Fields(text)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "zero_globl_") {
			continue
		}
		symbol, exists := wanted[fields[0]]
		if !exists || seen[fields[0]] || len(fields) < 3 {
			t.Fatal("actual GLOBL has a changed/duplicate symbol identity", text)
		}
		kind := "SDATA"
		if symbol.readOnly {
			kind = "SRODATA"
		}
		if fields[1] != kind || strings.Contains(" "+text+" ", " static ") != symbol.local ||
			!strings.Contains(" "+text+" ", " size=72 ") {
			t.Fatal("actual GLOBL changed its static/readonly/extent role", text)
		}
		var got []byte
		for offset := 0; offset < 72; offset += 16 {
			rowIndex := line + 1 + offset/16
			if rowIndex >= len(lines) {
				t.Fatal("actual GLOBL byte dump was truncated", symbol.name)
			}
			row := strings.Fields(lines[rowIndex])
			width := 16
			if width > 72-offset {
				width = 72 - offset
			}
			if len(row) < width+1 || row[0] != fmt.Sprintf("0x%04x", offset) {
				t.Fatal("actual GLOBL byte range is missing or reordered", lines[rowIndex])
			}
			fragment, err := hex.DecodeString(strings.Join(row[1:width+1], ""))
			if err != nil {
				t.Fatal("actual GLOBL byte dump is not hexadecimal", err)
			}
			got = append(got, fragment...)
		}
		if !bytes.Equal(got, globlZeroAddendInitialBytes()) {
			t.Fatalf("actual GLOBL %s bytes=%x, want=%x", symbol.name, got, globlZeroAddendInitialBytes())
		}
		seen[symbol.name] = true
	}
	if len(seen) != len(wanted) {
		t.Fatalf("actual original GLOBL inventory=%d, want=%d\n%s", len(seen), len(wanted), listing)
	}
}

func TestGLOBLZeroAddendOriginalGoObjectsFiveArchitectures(t *testing.T) {
	source, symbols := globlZeroAddendSource(false)
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			globlZeroAddendGoObject(t, target.goos, target.goarch, source, symbols)
		})
	}
}

func TestGLOBLZeroAddendCompleteObjectsThreeAPIsFiveArchitectures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("the complete GLOBL regression requires exact LLVM22")
	}
	source, symbols := globlZeroAddendSource(true)
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			globlZeroAddendGoObject(t, target.goos, target.goarch, source, symbols)
			file, err := Parse(target.arch, source)
			if err != nil {
				t.Fatal(err)
			}
			pkg := x86AddSubLiteralPackage(t, target.goarch, "func Probe()\n")
			options := Options{Goarch: target.goarch, TargetTriple: target.triple, ResolveSym: dataGlobalAlignmentResolve,
				Sigs: map[string]FuncSig{"Probe": {Name: "Probe", Ret: Void}}}
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					var module llvm.Module
					var err error
					switch api {
					case "text":
						var ir string
						ir, err = Translate(file, options)
						if err == nil {
							module, err = parseIRModuleInContext(ctx, ir)
						}
					case "module":
						module, err = TranslateModuleInContext(ctx, file, options)
					case "GoModule":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
							GOARCH: target.goarch, TargetTriple: target.triple, ResolveSym: dataGlobalAlignmentResolve})
						if result != nil {
							module = result.Module
						}
					}
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err != nil || module.IsNil() {
						t.Fatal("a complete Go-accepted GLOBL program must translate", err)
					}
					for _, symbol := range symbols {
						t.Run(symbol.caseName+"/"+symbol.sourceName, func(t *testing.T) {
							global := module.NamedGlobal(symbol.name)
							if global.IsNil() || global.IsDeclaration() || global.IsGlobalConstant() != symbol.readOnly ||
								(global.Linkage() == llvm.InternalLinkage) != symbol.local ||
								global.Initializer() != ctx.ConstString(string(globlZeroAddendInitialBytes()), false) {
								t.Fatalf("zero displacement changed actual bytes/extent/identity/readonly role for %s", symbol.sourceName)
							}
						})
					}
					for global := module.FirstGlobal(); !global.IsNil(); global = llvm.NextGlobal(global) {
						if strings.ContainsAny(global.Name(), "+-() \t") || strings.HasSuffix(global.Name(), "<>") {
							t.Errorf("an offset spelling escaped as a separate data identity: %q", global.Name())
						}
					}
					compileLLVMToObject(t, llc, target.triple, "globl-zero.ll", "globl-zero.o", module.String())
				})
			}
		})
	}
}

func TestGLOBLNonzeroUnknownAndQuotedAddendsDoNotBecomeZero(t *testing.T) {
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			for _, addend := range []string{
				"+1", "-1", "+(2-1)", "+(0x100000000)",
				"+UNRESOLVED", "+(UNRESOLVED-UNRESOLVED)", "+(1/0)", "+(1", "+0junk",
			} {
				t.Run(addend, func(t *testing.T) {
					statement := "GLOBL literal<>" + addend + "(SB),8,$72\n"
					goAssemblerOracleOutput(t, target.goarch, statement, "", false)
					file, err := Parse(target.arch, statement)
					if err == nil && (len(file.Globl) != 1 || file.Globl[0].Sym == "literal<>") {
						t.Fatal("a nonzero or unknown displacement was collapsed into a valid zero-address identity", file.Globl)
					}
				})
			}
			// Go's symbol grammar begins with scanner.Ident, not a quoted
			// string. Preserve that distinction instead of using an invalid
			// quoted symbol as a positive actual-object witness.
			goAssemblerOracleOutput(t, target.goarch, "GLOBL \"literal+0\"(SB),8,$72\n", "", false)
		})
	}
	for _, name := range []string{`"literal+0"`, `"literal-0"`, `"literal\"+0"`, `"literal\\+0"`} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			for _, addend := range []string{"", "+0", "-0", "+(1-1)"} {
				got, offset := SplitSymbolOffset(name + addend)
				if got != name || offset != 0 {
					t.Fatalf("quoted content was mistaken for an offset: %q -> %q, %d", name+addend, got, offset)
				}
			}
			if global, err := parseGLOBLStmt(name + "(SB),8,$72"); err == nil && global.Sym != name {
				t.Fatalf("quoted +0 was truncated into another symbol: %+v", global)
			}
		})
	}
}
