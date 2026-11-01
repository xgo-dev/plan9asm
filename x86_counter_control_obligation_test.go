package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Go's yloop rows share a target grammar. Only JCXZL emits address-size
// override; the historical W/Q spellings both use the source mode's word.
var x86CounterControlOracle = []struct {
	op          string
	bytes       byte
	decrement   bool
	zeroFlag    bool
	halfCounter bool
}{
	{"JCXZW", 0xe3, false, false, false},
	{"JCXZL", 0xe3, false, false, true},
	{"JCXZQ", 0xe3, false, false, false},
	{"LOOP", 0xe2, true, false, false},
	{"LOOPEQ", 0xe1, true, true, false},
	{"LOOPNE", 0xe0, true, true, false},
}

func x86CounterControlSource(arch, op, name, omission string, backedge, observe bool) x86GPFaultingFixture {
	word, move, suffix, typ := 8, "MOVQ", "Q", "uint64"
	if arch == "386" {
		word, move, suffix, typ = 4, "MOVL", "L", "uint32"
	}
	var body strings.Builder
	fmt.Fprintf(&body, "%s p+%d(FP),SI\nMOVL (SI),DI\n", move, 2*word)
	if omission != "counter" {
		producer := move
		if omission == "low-word" {
			producer = "MOVW"
		} else if omission == "low-dword" {
			producer = "MOVL"
		}
		field, offset := "count", 0
		if omission == "pointer-counter" {
			field, offset = "p", 2*word
		}
		fmt.Fprintf(&body, "%s %s+%d(FP),CX\n", producer, field, offset)
	}
	if omission != "zero-flag" {
		fmt.Fprintf(&body, "%s seed+%d(FP),AX\nCMP%s AX,$0\n", move, word, suffix)
	}
	body.WriteString("STC\n")
	if backedge {
		fmt.Fprintf(&body, "%s $0,BX\nagain:\nLEA%s 1(BX),BX\n%s again\n", move, suffix, op)
	} else {
		fmt.Fprintf(&body, "%s taken\n%s $200,BX\nJMP done\ntaken:\n%s $100,BX\ndone:\n", op, move, move)
	}
	if observe {
		// Read CF/ZF before arithmetic changes them, and observe both the
		// branch decision and LOOP's counter write in the returned value.
		extend := "MOVBQZX"
		if arch == "386" {
			extend = "MOVBLZX"
		}
		fmt.Fprintf(&body, "SETCS DL\nSETEQ AL\n%s DL,DX\n%s AL,AX\nSHL%s $1,AX\nADD%s DX,AX\nLEA%s (BX)(CX*4),BX\nADD%s AX,BX\n",
			extend, extend, suffix, suffix, suffix, suffix)
	}
	fmt.Fprintf(&body, "%s BX,ret+%d(FP)\nRET\n", move, 3*word)
	return x86GPFaultingFixture{
		name: name, source: fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s", name, 4*word, body.String()),
		declaration: fmt.Sprintf("func %s(count,seed %s,p *uint32) %s", name, typ, typ),
	}
}

func x86CounterControlGoObjects(t *testing.T, arch string, fixtures []x86GPFaultingFixture) {
	t.Helper()
	for start := 0; start < len(fixtures); start += 32 {
		end := start + 32
		if end > len(fixtures) {
			end = len(fixtures)
		}
		var source strings.Builder
		var names []string
		for _, fixture := range fixtures[start:end] {
			source.WriteString(fixture.source)
			names = append(names, fixture.name)
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal("complete counter source must be accepted by actual Go", err)
		}
		code := x86GPSegmentListingBytes(t, listing, names)
		mode := 64
		if arch == "386" {
			mode = 32
		}
		for _, fixture := range fixtures[start:end] {
			counterBranches := 0
			for offset := 0; offset < len(code[fixture.name]); {
				instruction, err := x86asm.Decode(code[fixture.name][offset:], mode)
				if err != nil || instruction.Len == 0 {
					t.Fatal("actual Go counter function could not be independently decoded", fixture.name, offset, err)
				}
				for _, row := range x86CounterControlOracle {
					if !strings.Contains(fixture.source, "\n"+row.op+" ") {
						continue
					}
					if byte(instruction.Opcode>>24) == row.bytes {
						want := mode
						if row.halfCounter {
							want /= 2
						}
						if instruction.AddrSize != want {
							t.Fatal("actual Go encoded a different counter address width", fixture.name, instruction, want)
						}
						counterBranches++
					}
				}
				offset += instruction.Len
			}
			if counterBranches != 1 {
				t.Fatal("actual Go lost the one complete counter branch", fixture.name, counterBranches)
			}
		}
	}
}

func TestX86CounterControlCompleteReachingInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var fixtures []x86GPFaultingFixture
			for _, row := range x86CounterControlOracle {
				for _, backedge := range []bool{false, true} {
					if backedge && !row.decrement {
						continue
					}
					for _, omission := range []string{"", "counter", "pointer-counter", "low-word", "low-dword", "zero-flag"} {
						fixture := x86CounterControlSource(arch, row.op, fmt.Sprintf("Counter%d", len(fixtures)), omission, backedge, false)
						fixture.accept = omission == "" || omission == "low-dword" ||
							omission == "zero-flag" && !row.zeroFlag || omission == "low-word" && arch == "386" && row.halfCounter
						fixture.label = fmt.Sprintf("%s/backedge=%t/%s", row.op, backedge, omission)
						fixtures = append(fixtures, fixture)
					}
				}
			}
			x86CounterControlGoObjects(t, arch, fixtures)
			for _, fixture := range fixtures {
				t.Run(fixture.label, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, arch, testTargetTriple("linux", arch), api)
							if fixture.accept {
								if err != nil || ir == "" {
									t.Fatal("INITIALIZED_COUNTER_REJECTED", err, fixture.source)
								}
							} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("COUNTER_INPUT_NOT_PROVED", err, fixture.source)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86CounterControlCompleteObjectPrograms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var fixtures []x86GPFaultingFixture
			var source, declarations strings.Builder
			for _, row := range x86CounterControlOracle {
				for _, backedge := range []bool{false, true} {
					if backedge && !row.decrement {
						continue
					}
					fixture := x86CounterControlSource(target.arch, row.op, fmt.Sprintf("Counter%d", len(fixtures)), "", backedge, true)
					fixtures = append(fixtures, fixture)
					source.WriteString(fixture.source)
					declarations.WriteString(fixture.declaration + "\n")
				}
			}
			x86CounterControlGoObjects(t, target.arch, fixtures)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("INITIALIZED_COUNTER_OBJECT_REJECTED", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}
}
