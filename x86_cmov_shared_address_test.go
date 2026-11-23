package plan9asm

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialCMOVSharedAddressObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, mode := range []struct {
		arch, triple string
		register     string
	}{
		{"amd64", "x86_64-unknown-linux-gnu", "R11"},
		{"386", "i386-unknown-linux-gnu", "AX"},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			var assembly, declarations strings.Builder
			var symbols, locations []string
			var original []x86OfficialPackedCase
			line := 0
			encodings := x86OfficialCMOVSharedAddressEncodings(t)
			for _, name := range x86CMOVOracleNames(mode.arch) {
				symbol := "Shared" + name
				instruction := fmt.Sprintf("%s (%s),%s", name, mode.register, mode.register)
				source, declaration := x86ConditionalMoveInitializedFunction(symbol, instruction, mode.register, mode.arch)
				location := instruction
				if mode.arch == "amd64" {
					row := encodings[name]
					offset := strings.Index(source, "\n"+instruction+"\n")
					if len(row.code) == 0 || offset < 0 {
						t.Fatalf("missing exact Go encoding or source for %s", instruction)
					}
					location = row.location
					original = append(original, x86OfficialPackedCase{
						row: location, symbol: symbol, line: line + strings.Count(source[:offset+1], "\n") + 1,
						witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: row.code},
					})
				}
				line += strings.Count(source, "\n")
				assembly.WriteString(source)
				declarations.WriteString(declaration)
				symbols = append(symbols, symbol)
				locations = append(locations, location)
			}
			source := assembly.String()
			listing, err := x86ScalarLiteralGoListing(t, mode.arch, source)
			if err != nil {
				t.Fatal(err)
			}
			if mode.arch == "amd64" {
				if err := x86OfficialPackedVerifyListing(listing, original); err != nil {
					t.Fatal(err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), mode.arch, mode.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						object := x86PackedStringCompileObject(t, llc, mode.triple, ir, level)
						requireX86ELFTestFunctions(t, mode.arch, object, symbols, locations)
					}
				})
			}
		})
	}
}

type x86CMOVSharedAddressEncoding struct {
	location string
	code     []byte
}

func x86OfficialCMOVSharedAddressEncodings(t *testing.T) map[string]x86CMOVSharedAddressEncoding {
	t.Helper()
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata", "amd64enc.s")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^(CMOV[WLQ][A-Z]+)\s+\(R11\),\s*R11\s+//\s+([0-9a-f]+)$`)
	rows := make(map[string]x86CMOVSharedAddressEncoding)
	for line, raw := range strings.Split(string(data), "\n") {
		match := pattern.FindStringSubmatch(strings.TrimSpace(raw))
		if match == nil {
			continue
		}
		code, err := hex.DecodeString(match[2])
		if err != nil || rows[match[1]].code != nil {
			t.Fatalf("invalid or duplicate Go encoding at amd64enc.s:%d", line+1)
		}
		rows[match[1]] = x86CMOVSharedAddressEncoding{fmt.Sprintf("amd64enc.s:%d", line+1), code}
	}
	if len(rows) != 48 {
		t.Fatalf("found %d official CMOV shared-address rows, want 48", len(rows))
	}
	return rows
}
