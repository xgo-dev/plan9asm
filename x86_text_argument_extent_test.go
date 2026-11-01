package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

// cmd/asm preserves an omitted argument size as ArgsSizeUnknown, not zero.
// An ordinary typed declaration still bounds every actual FP input; omission
// grants neither an unbounded frame nor an explicit extent mismatch.
func TestX86OmittedTEXTArgsKeepTypedVoidExtent(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			extent string
			valid  bool
		}{
			{"$0", true}, {"$0-4", true}, {"$0-8", true},
			{"$0-0", false}, {"$0-3", false}, {"$0-4097", false},
		} {
			t.Run(target.triple+"/"+row.extent, func(t *testing.T) {
				source := "TEXT ·Value(SB),4," + row.extent + "\nKMOVD value+0(FP),K1\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(value uint32)\n", target.arch, target.triple, api)
					if !row.valid {
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("explicit TEXT mismatch gained typed argument authority", api, err)
						}
						continue
					}
					if err != nil {
						t.Fatal("valid omitted or matching argument extent rejected", api, err)
					}
					compileLLVMToObject(t, llc, target.triple, "text-extent.ll", "text-extent.o", ir)
				}
			})
		}
	}
}

func TestParseTEXTArgumentSizeOmission(t *testing.T) {
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchARM64, ArchWASM} {
		for _, row := range []struct {
			text        string
			frame, args int64
			specified   bool
		}{
			{"$0", 0, 0, false}, {"$-8", -8, 0, false},
			{"$0-0", 0, 0, true}, {"$-8-4", -8, 4, true},
			{"$16-8", 16, 8, true},
		} {
			file, err := Parse(arch, "TEXT ·Value(SB),4,"+row.text+"\nRET\n")
			if err != nil || len(file.Funcs) != 1 {
				t.Fatal("valid original TEXT failed", arch, row.text, err)
			}
			fn := file.Funcs[0]
			_, rest := splitOpcode(fn.Instrs[0].Raw)
			actual, err := parseTEXTFrameSpec(strings.Split(rest, ","))
			if err != nil || actual.frameSize != row.frame || actual.argSize != row.args ||
				actual.argsSpecified != row.specified || fn.FrameSize != row.frame || fn.ArgSize != row.args {
				t.Fatal("TEXT lost its independent frame/argument-size axes", arch, row, actual, err)
			}
		}
		if _, err := Parse(arch, "TEXT ·Value(SB),4,$0-\nRET\n"); err == nil {
			t.Fatal("an explicit but missing argument integer became omission", arch)
		}
	}
}

func TestX86OmittedTEXTRequiresMatchingOriginalHeader(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(*Func)
	}{
		{"no-header", func(fn *Func) { fn.Instrs = fn.Instrs[1:] }},
		{"empty-original", func(fn *Func) { fn.Instrs[0].Raw = "" }},
		{"wrong-opcode", func(fn *Func) { fn.Instrs[0].Raw = "DATA ·Value(SB),4,$0" }},
		{"explicit-zero", func(fn *Func) { fn.Instrs[0].Raw += "-0" }},
		{"explicit-nonzero", func(fn *Func) { fn.Instrs[0].Raw += "-4" }},
		{"dangling-argument", func(fn *Func) { fn.Instrs[0].Raw += "-" }},
		{"changed-frame", func(fn *Func) { fn.FrameSize = 8 }},
		{"changed-arguments", func(fn *Func) { fn.ArgSize = 4 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0\nRET\n")
			if err != nil || !x86TEXTArgumentsUnspecified(file.Funcs[0]) {
				t.Fatal("original omitted-argument control rejected", err)
			}
			mutate.apply(&file.Funcs[0])
			if x86TEXTArgumentsUnspecified(file.Funcs[0]) {
				t.Fatal("missing or mismatched source header acquired omission")
			}
		})
	}
}

func TestX86OmittedTEXTDoesNotInventInputOrStorage(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, declaration, body string }{
			{"empty-declaration", "func Value()", "KMOVD value+0(FP),K1"},
			{"partial-input", "func Value(value uint16)", "KMOVD value+0(FP),K1"},
			{"past-input", "func Value(value uint32)", "KMOVD value+4(FP),K1"},
			{"unknown-register", "func Value(value uint32)", "KMOVD AX,K1"},
			{"physical-stack", "func Value(value uint32)", "KMOVD (SP),K1"},
			{"unknown-memory", "func Value(value uint32)", "KMOVD (AX),K1"},
			{"input-store", "func Value(value uint32)", "KMOVD value+0(FP),K1\nKMOVD K1,value+0(FP)"},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0\n" + row.body + "\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unknown extent created an input or storage role", api, err)
					}
				}
			})
		}
	}
}
