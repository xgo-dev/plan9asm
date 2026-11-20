package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

type x86LockScalarOracleForm struct {
	op   string
	text string
}

// This inventory is independent of the production dispatch. Intel's complete
// LOCK list contains these fourteen stems plus the five existing exchange and
// compare-exchange stems. Go's yxorb/yaddl/yscond/yincl/yincq/ybtl ordered tables
// determine their immediate, register and memory operand forms.
func x86LockScalarOracleForms(arch string) []x86LockScalarOracleForm {
	widths := "BWL"
	if arch == "amd64" {
		widths += "Q"
	}
	var forms []x86LockScalarOracleForm
	for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR"} {
		for _, width := range widths {
			op, register := stem+string(width), "CX"
			if width == 'B' {
				register = "CL"
			}
			for _, source := range []string{register, "$1"} {
				forms = append(forms, x86LockScalarOracleForm{op, op + " " + source + ",1(SI)"})
			}
		}
	}
	for _, stem := range []string{"INC", "DEC", "NEG", "NOT"} {
		for _, width := range widths {
			op := stem + string(width)
			forms = append(forms, x86LockScalarOracleForm{op, op + " 1(SI)"})
		}
	}
	for _, stem := range []string{"BTC", "BTR", "BTS"} {
		for _, width := range strings.TrimPrefix(widths, "B") {
			op := stem + string(width)
			for _, source := range []string{"CX", "$1"} {
				forms = append(forms, x86LockScalarOracleForm{op, op + " " + source + ",1(SI)"})
			}
		}
	}
	return forms
}

func TestX86LockScalarRMWCompleteGoTables(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := x86LockScalarEncoderCarrier(data); err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\s*\{A((?:ADC|ADD|AND|OR|SBB|SUB|XOR|INC|DEC|NEG|NOT|BTC|BTR|BTS)[BWLQ]),\s*(\w+),`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 53 {
		t.Fatalf("complete scalar LOCK opcode inventory changed: %d", len(rows))
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		op, table := row[1], row[2]
		if seen[op] {
			t.Fatal("duplicate Go opcode registration", op)
		}
		seen[op] = true
		width, stem := op[len(op)-1], op[:len(op)-1]
		want := "yaddl"
		switch stem {
		case "BTC", "BTR", "BTS":
			want = "ybtl"
		case "INC", "DEC":
			want = "yincq"
			if width == 'B' {
				want = "yscond"
			} else if width == 'L' {
				want = "yincl"
			}
		case "NEG", "NOT":
			want = "yscond"
		default:
			if width == 'B' {
				want = "yxorb"
			}
		}
		if table != want {
			t.Fatalf("Go ordered-table role changed: %s/%s, want %s", op, table, want)
		}
	}
	for _, form := range x86LockScalarOracleForms("amd64") {
		if !seen[form.op] {
			t.Fatal("independent syntax inventory is absent from actual Go tables", form.op)
		}
	}
}

func x86LockScalarOriginalInstruction(t *testing.T, arch, source string) []byte {
	t.Helper()
	code := x86OrderingHintGoBytes(t, arch, source)
	mode := 64
	if arch == "386" {
		mode = 32
	}
	for offset := 0; offset < len(code); {
		instruction, err := x86asm.Decode(code[offset:], mode)
		if err != nil || instruction.Len <= 0 {
			t.Fatalf("actual original Go bytes cannot be decoded at %d: %v", offset, err)
		}
		if code[offset] == 0xf0 {
			return append([]byte(nil), code[offset:offset+instruction.Len]...)
		}
		offset += instruction.Len
	}
	t.Fatalf("actual complete Go object lacks its LOCK-prefixed instruction: %x", code)
	return nil
}

func TestX86LockScalarRMWWholeSourceAdmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		forms := x86LockScalarOracleForms(arch)
		want := 90
		if arch == "386" {
			want = 66
		}
		if len(forms) != want {
			t.Fatal("complete accepted operand-form denominator changed", arch, len(forms))
		}
		for _, form := range forms {
			t.Run(arch+"/"+form.text, func(t *testing.T) {
				source := x86NamedLockOracleSource(arch, "CMPL AX,AX\n\tLOCK\n\t"+form.text)
				machine := x86LockScalarOriginalInstruction(t, arch, source)
				t.Logf("actual original LOCK object bytes=%x", machine)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source,
							"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
						if err != nil || !strings.Contains(ir, "lock; "+strings.ToLower(form.op)) {
							t.Fatalf("actual Go accepted whole scalar LOCK RMW lacks its ordered atomic effect: %v", err)
						}
					})
				}
			})
		}
	}
}

func TestX86LockScalarRMWRawWholeInstructionRetainsContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, form := range x86LockScalarOracleForms(arch) {
			t.Run(arch+"/"+form.text, func(t *testing.T) {
				source := x86NamedLockOracleSource(arch, "CMPL AX,AX\n\tLOCK\n\t"+form.text)
				machine := x86LockScalarOriginalInstruction(t, arch, source)
				var body strings.Builder
				for _, value := range machine {
					fmt.Fprintf(&body, "BYTE $%d\n", value)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api,
							x86NamedLockOracleSource(arch, "CMPL AX,AX\n\t"+body.String()),
							"package ordering\nfunc locked(p *[16]byte)\n", arch, testTargetTriple("linux", arch))
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("raw LOCK lost its unresolved whole physical-prefix contract", err)
						}
					})
				}
			})
		}
	}
}
