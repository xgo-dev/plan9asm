package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
	"golang.org/x/arch/x86/x86asm"
)

func TestX86X87CompareRawListingRejectsPartialCarrier(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		cases := []x86OfficialPackedCase{{row: "displaced", witness: goasmrules.X86PackedBinaryWitness{
			Instruction: "FCOMD 7(AX),F0", Encoding: []byte{0xdc, 0x50, 7},
		}}}
		source, _ := x86X87CompareAssembly(cases, arch, false, true, true)
		listing, err := x86ScalarLiteralGoListing(t, arch, source)
		if err != nil || x86OfficialPackedVerifyListing(listing, cases) != nil {
			t.Fatal("complete raw carrier listing rejected", err)
		}
		for _, change := range []string{"truncate-displacement", "extra-BYTE", "wrong-PC", "wrong-line"} {
			t.Run(arch+"/"+change, func(t *testing.T) {
				candidate := append([]x86OfficialPackedCase(nil), cases...)
				text := listing
				switch change {
				case "truncate-displacement":
					candidate[0].witness.Encoding = candidate[0].witness.Encoding[:2]
				case "extra-BYTE":
					modified := strings.Replace(source, cases[0].witness.Instruction+"\n", cases[0].witness.Instruction+"\nBYTE $0x90\n", 1)
					var err error
					text, err = x86ScalarLiteralGoListing(t, arch, modified)
					if err != nil {
						t.Fatal(err)
					}
				case "wrong-PC", "wrong-line":
					lines := strings.Split(text, "\n")
					changed := false
					for i, line := range lines {
						m := x86OfficialPackedListingInstruction.FindStringSubmatch(line)
						if m == nil || m[4] != "BYTE" || m[3] != strconv.Itoa(cases[0].line+1) {
							continue
						}
						if change == "wrong-PC" {
							lines[i] = strings.Replace(line, m[0], strings.Replace(m[0], "0x"+m[1]+" "+m[2], "0xffff 65535", 1), 1)
						} else {
							lines[i] = strings.Replace(line, ":"+m[3]+")", ":99999)", 1)
						}
						changed = lines[i] != line
						break
					}
					if !changed {
						t.Fatal("listing mutation did not touch its exact BYTE")
					}
					text = strings.Join(lines, "\n")
				}
				defer func() {
					if value := recover(); value != nil {
						t.Fatalf("invalid raw listing caused a slice panic: %v", value)
					}
				}()
				if err := x86OfficialPackedVerifyListing(text, candidate); err == nil {
					t.Fatal("partial/extra/noncontiguous raw carrier accepted", change)
				}
			})
		}
	}
}

func TestX86X87CompareDecoderMetadataAndPrefixes(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, code := range [][]byte{{0xde, 0x10}, {0xda, 0x18}, {0xd8, 0x10}, {0xdc, 0x58, 7}, {0xdb, 0xe9}, {0xde, 0xd9}} {
			inst, err := x86asm.Decode(code, mode)
			if err != nil {
				t.Fatal(err)
			}
			if _, known, err := decodedX86X87CompareSyntax(inst, code); !known || err != nil {
				t.Fatal("complete physical compare rejected", inst, err)
			}
			for _, change := range []string{"length", "mode", "width", "opcode", "operand", "prefix", "encoding"} {
				t.Run(fmt.Sprintf("%d/%x/%s", mode, code, change), func(t *testing.T) {
					candidate := inst
					bytes := append([]byte(nil), code...)
					switch change {
					case "length":
						candidate.Len++
					case "mode":
						candidate.Mode = 16
					case "width":
						candidate.MemBytes++
					case "opcode":
						candidate.Opcode++
					case "operand":
						candidate.Args[0] = x86asm.R8
					case "prefix":
						candidate.Prefix[0] = x86asm.PrefixLOCK
					case "encoding":
						bytes[0] ^= 1
					}
					if _, known, err := decodedX86X87CompareSyntax(candidate, bytes); !known || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("forged decoder shape accepted", change, err)
					}
				})
			}
		}
		for _, prefix := range []byte{0x66, 0x67, 0xf0, 0x64} {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+x86RawDisplacementDirectives([]byte{prefix, 0xdc, 0xd7})+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			arch := "386"
			if mode == 64 {
				arch = "amd64"
			}
			if _, err := normalizeX86RawFile(file, arch); err == nil {
				t.Fatal("prefixed undecoded DC form lost its boundary", mode, prefix)
			}
		}
	}
}

func TestX86X87CompareRawCanonicalShape(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86X87Rows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		count, refused := 0, 0
		for _, row := range rows {
			spec, known := x86X87ValueSpecForName(Op(row.Opcode))
			if !known || spec.kind != x86X87Compare {
				continue
			}
			for _, witness := range row.Witnesses {
				count++
				t.Run(arch+"/"+row.ID+"/"+witness.Instruction, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(witness.Encoding)+"RET\n")
					if err != nil {
						t.Fatal(err)
					}
					normalized, err := normalizeX86RawFile(file, arch)
					invalid := spec.pop == 2 && witness.Instruction != row.Opcode+" F0,F1"
					if invalid {
						refused++
						if err == nil {
							t.Fatal("original invalid two-pop bytes were changed to a valid F1 compare")
						}
						return
					}
					if err != nil || normalized == nil {
						t.Fatal("actual canonical compare failed raw normalization", err)
					}
					actual := normalized.Funcs[0].Instrs[1]
					expected := x86X87ValueInstruction(t, witness.Instruction)
					if actual.Op != expected.Op || !reflect.DeepEqual(actual.Args, expected.Args) || actual.x86SourceRaw == nil {
						t.Fatalf("canonical physical shape lost: actual=%s args=%+v expected=%s %+v", actual.Op, actual.Args, expected.Op, expected.Args)
					}
				})
			}
		}
		if count != 40 || refused != 2 {
			t.Fatal("incomplete original canonical compare inventory", arch, count, refused)
		}
	}
}

func TestX86OfficialX87CompareCanonicalMemoryAndRawObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw%t", target.triple, raw), func(t *testing.T) {
				build := func(source goasmrules.X86LegacyCatalog, _ []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
					return x86X87CompareNamedRows(source, target.arch)
				}
				x86OfficialPackedRowsObjectsForTarget(t, target.arch, target.triple, build, 20, 38, 0,
					func(cases []x86OfficialPackedCase) (string, string) {
						return x86X87CompareAssembly(cases, target.arch, false, true, raw)
					}, func(*testing.T, string, []x86OfficialPackedCase) {})
			})
		}
	}
}

func TestX86X87CompareRawRequiresWholeReplayIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		cases := []x86OfficialPackedCase{{witness: goasmrules.X86PackedBinaryWitness{Instruction: "FCOMD F1,F0", Encoding: []byte{0xd8, 0xd1}}}}
		source, declarations := x86X87CompareAssembly(cases, arch, false, true, true)
		pkg := mustGoPackage(t, "compare", "package compare\n"+declarations)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		resolve := func(s string) string { return strings.TrimPrefix(s, "·") }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, arch)
		if err != nil {
			t.Fatal(err)
		}
		fn, sig := normalized.Funcs[0], sigs[cases[0].symbol]
		for _, change := range []string{"none", "standalone", "missing-replay", "wrong-mode", "raw-source", "normalized-op", "original-args", "copied-token", "address-size", "segment", "raw-return"} {
			t.Run(arch+"/"+change, func(t *testing.T) {
				candidate := fn
				candidate.Instrs = cloneX86ReplayInstrs(fn.Instrs)
				replay := *fn.x86RawReplay
				replay.original = cloneX86ReplayInstrs(replay.original)
				replay.decoded = cloneX86ReplayInstrs(replay.decoded)
				replay.normalized = cloneX86ReplayInstrs(replay.normalized)
				candidate.x86RawReplay = &replay
				ordinal := -1
				for i, ins := range candidate.Instrs {
					if ins.x86SourceRaw != nil {
						ordinal = i
						break
					}
				}
				if ordinal < 0 {
					t.Fatal("missing raw source witness")
				}
				mode := arch
				switch change {
				case "missing-replay":
					candidate.x86RawReplay = nil
				case "wrong-mode":
					if mode == "amd64" {
						mode = "386"
					} else {
						mode = "amd64"
					}
				case "raw-source":
					replay.source = strings.Replace(replay.source, "$0xd1", "$0xd7", 1)
				case "normalized-op":
					replay.normalized[ordinal].Op = "NOP"
				case "original-args":
					candidate.Instrs[ordinal].x86SourceRaw.args = nil
				case "copied-token":
					candidate.Sym += "Copy"
				case "address-size":
					candidate.Instrs[ordinal].x86AddressBits = 16
				case "segment":
					candidate.Instrs[ordinal].x86SegmentPrefix = 0x64
				case "raw-return":
					candidate.Instrs[ordinal].x86RawNearReturn = new(x86RawNearReturnForm)
				}
				var err error
				if change == "standalone" {
					err = CheckX86ABI0ResultInitialization(candidate, sig, mode)
				} else {
					consumer := &amd64Ctx{fpScalarSource: candidate, sig: sig, fpSourceSig: sig, goarch: mode, x87Mode: X87Software}
					err = consumer.checkLoweredScalarFPResultInitialization()
				}
				if change == "none" {
					if err != nil {
						t.Fatal("actual complete replay rejected", err)
					}
				} else if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed/copy/standalone raw source acquired a compare role", err)
				}
			})
		}
	}
}
