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

type x86OfficialAMD64Encoding struct {
	instruction, location string
	code                  []byte
}

func x86OfficialAMD64EncodingRows(t *testing.T, filename, format string) []x86OfficialAMD64Encoding {
	t.Helper()
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile("^(?:" + format + ")$")
	var rows []x86OfficialAMD64Encoding
	for index, raw := range strings.Split(string(data), "\n") {
		instruction, encoding, _ := strings.Cut(raw, "//")
		instruction = strings.TrimSpace(instruction)
		if !match.MatchString(instruction) {
			continue
		}
		location := fmt.Sprintf("%s:%d", filename, index+1)
		code, err := hex.DecodeString(strings.TrimSpace(encoding))
		if err != nil || len(code) == 0 {
			t.Fatalf("missing Go encoding for %s: %v", location, err)
		}
		rows = append(rows, x86OfficialAMD64Encoding{instruction, location, code})
	}
	return rows
}

func requireX86OfficialAMD64Objects(t *testing.T, llc, source, declarations string, witnesses []x86OfficialPackedCase) {
	t.Helper()
	const arch, triple = "amd64", "x86_64-unknown-linux-gnu"
	listing, err := x86ScalarLiteralGoListing(t, arch, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, witnesses); err != nil {
		t.Fatal(err)
	}
	var symbols, locations []string
	for _, witness := range witnesses {
		symbols = append(symbols, witness.symbol)
		locations = append(locations, witness.row)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				object := x86PackedStringCompileObject(t, llc, triple, ir, level)
				requireX86ELFTestFunctions(t, arch, object, symbols, locations)
			}
		})
	}
}

func TestX86OfficialScalarSharedAddressObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, family := range []struct {
		name, format, result string
		count                int
	}{
		{"arithmetic", `(?:ADC|ADD|AND|OR|SBB|SUB|XOR)[BWLQ] R11,\s*\(R11\)`, "R11", 28},
		{"compare", `(?:CMP[BWLQ] \(R11\),\s*R11|(?:CMP|TEST)[BWLQ] R11,\s*\(R11\))`, "AX", 12},
		{"carry-chain", `AD(?:CX|OX)[LQ] \(R11\),\s*R11`, "R11", 4},
		{"multiply", `IMUL[WLQ] \(R11\),\s*R11`, "R11", 3},
		{"move", `MOV[BWL] R11,\s*\(R11\)`, "R11", 3},
		{"byte-swapped-move", `MOVBE[WLQ] R11,\s*\(R11\)`, "R11", 3},
		{"double-shift", `SH[LR][WLQ] (?:CL|\$7),\s*R11,\s*\(R11\)`, "R11", 12},
	} {
		t.Run(family.name, func(t *testing.T) {
			rows := x86OfficialAMD64EncodingRows(t, "amd64enc.s", family.format)
			if len(rows) != family.count {
				t.Fatalf("found %d official shared-address rows, want %d", len(rows), family.count)
			}
			var source, declarations strings.Builder
			var witnesses []x86OfficialPackedCase
			line := 0
			for index, row := range rows {
				symbol := fmt.Sprintf("Shared%d", index)
				header := fmt.Sprintf("TEXT ·%s(SB),4,$0-16\nMOVQ address+0(FP),R11\nMOVL $7,CX\nXORL AX,AX\n", symbol)
				observe := ""
				if family.result == "AX" {
					observe = "SETEQ AL\n"
				}
				body := fmt.Sprintf("%s%s\n%sMOVQ %s,ret+8(FP)\nRET\n", header, row.instruction, observe, family.result)
				source.WriteString(body)
				fmt.Fprintf(&declarations, "func %s(address uintptr) uintptr\n", symbol)
				witnesses = append(witnesses, x86OfficialPackedCase{
					row: row.location, symbol: symbol, line: line + strings.Count(header, "\n") + 1,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: row.instruction, Encoding: row.code},
				})
				line += strings.Count(body, "\n")
			}
			requireX86OfficialAMD64Objects(t, llc, source.String(), declarations.String(), witnesses)
		})
	}
}

func TestX86ScalarSharedAddressRequiresWholeInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		base := Reg("R11")
		if arch == "386" {
			base = BX
		}
		word := x86ResultPointerWord(arch)
		slot, mask, _ := x86ResultGP(base, word, arch)
		index, _, _ := x86ResultGP(SI, word, arch)
		other, _, _ := x86ResultGP(DX, word, arch)
		count, _, _ := x86ResultGP(CX, word, arch)
		for _, form := range []struct {
			head string
			step func(Instr, *x86ResultState, []bool, int64, string) (bool, bool)
		}{
			{"MOVBEW", x86LoweredMOVBEResultStep},
			{"SHLW CL,", x86LoweredScalarShiftMemory},
		} {
			t.Run(arch+"/"+form.head, func(t *testing.T) {
				original := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s, 7(%s)(SI*2)", form.head, base, base))
				var state x86ResultState
				state.flags = x86ByteFlagsAll
				state.gp[slot], state.gp[index], state.gp[other], state.gp[count] = mask, mask, mask, mask
				accepted := state
				if yes, known := form.step(original, &accepted, nil, 0, arch); !known || !yes ||
					accepted.gp != state.gp || accepted.pointerGP != state.pointerGP {
					t.Fatal("complete address alias added an unrelated register or pointer fact", yes, known)
				}
				for byteIndex := int64(0); byteIndex < word; byteIndex++ {
					partial := state
					partial.gp[slot] &^= 1 << byteIndex
					if yes, known := form.step(original, &partial, nil, 0, arch); !known || yes {
						t.Fatalf("borrowed undefined base byte %d", byteIndex)
					}
				}
				missingIndex := state
				missingIndex.gp[index] = 0
				if yes, known := form.step(original, &missingIndex, nil, 0, arch); !known || yes {
					t.Fatal("borrowed undefined address index")
				}
				unrelated := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s, 7(DX)(SI*2)", form.head, base))
				if yes, known := form.step(unrelated, &state, nil, 0, arch); !known || yes {
					t.Fatal("borrowed unrelated numerical base")
				}
			})
		}
	}
}
