package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64SVEAddSubFormSpec struct {
	op           string
	unpredicated bool
	predicated   bool
	immediate    bool
}

var arm64SVEAddSubCompleteFamily = []arm64SVEAddSubFormSpec{
	{op: "ZSUB", unpredicated: true, predicated: true, immediate: true},
	{op: "ZSUBR", predicated: true, immediate: true},
	{op: "ZSQADD", unpredicated: true, predicated: true, immediate: true},
	{op: "ZSQSUB", unpredicated: true, predicated: true, immediate: true},
	{op: "ZSQSUBR", predicated: true},
	{op: "ZUQADD", unpredicated: true, predicated: true, immediate: true},
	{op: "ZUQSUB", unpredicated: true, predicated: true, immediate: true},
	{op: "ZUQSUBR", predicated: true},
}

func arm64SVEAddSubForms(function string, specs []arm64SVEAddSubFormSpec) string {
	var source strings.Builder
	source.WriteString("TEXT " + function + "(SB),$0-0\n")
	for _, spec := range specs {
		for widthIndex, width := range []string{"B", "H", "S", "D"} {
			if spec.unpredicated {
				source.WriteString("\t" + spec.op + " Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
			}
			if spec.predicated {
				source.WriteString("\t" + spec.op + " Z4." + width + ", Z5." + width + ", P" + string(rune('0'+widthIndex)) + ".M, Z5." + width + "\n")
			}
			if spec.immediate {
				immediate := "255"
				if width != "B" {
					immediate = "65280"
				}
				source.WriteString("\t" + spec.op + " $" + immediate + ", Z6." + width + ", Z6." + width + "\n")
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEAddSubCompleteGo127Family(t *testing.T) {
	for _, spec := range arm64SVEAddSubCompleteFamily {
		spec := spec
		t.Run(spec.op, func(t *testing.T) {
			function := "sve" + strings.ToLower(spec.op)
			source := arm64SVEAddSubForms(function, []arm64SVEAddSubFormSpec{spec})
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{
						TargetTriple: triple,
						Goarch:       "arm64",
						Sigs:         map[string]FuncSig{function: {Name: function, Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
					wants := []string{}
					if spec.op == "ZSUB" || spec.op == "ZSUBR" {
						wants = append(wants, " sub <vscale x ")
					} else {
						wants = append(wants, "@llvm."+arm64SVEAddSubSpecs[Op(spec.op)].intrinsic+".nxv")
					}
					if spec.predicated {
						wants = append(wants, " select <vscale x ")
					}
					for _, want := range wants {
						if !strings.Contains(ll, want) {
							t.Fatalf("%s SVE add/sub family omitted %q:\n%s", triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-add-sub.ll", "arm64-sve-add-sub.o", ll)
				})
			}
		})
	}
}

func TestTranslateARM64RawSVESubtractCompleteFamily(t *testing.T) {
	// Go 1.27 has unpredicated, predicated, and immediate SUB, and the
	// predicated and immediate reverse-SUB forms. lightning emits 0x04230404.
	var source strings.Builder
	source.WriteString("TEXT rawSVESubtract(SB),$0-0\n")
	for size := uint32(0); size < 4; size++ {
		words := []uint32{
			0x04200400 | size<<22 | 3<<16 | 0<<5 | 4,
			0x04010000 | size<<22 | 3<<5 | 1<<10 | 4,
			0x2521c000 | size<<22 | 32<<5 | 4,
			0x04030000 | size<<22 | 3<<5 | 1<<10 | 4,
			0x2523c000 | size<<22 | 32<<5 | 4,
		}
		for _, word := range words {
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVESubtract": {Name: "rawSVESubtract", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				" sub <vscale x ",
				" select <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw SVE subtract IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-subtract.ll", "arm64-raw-sve-subtract.o", ll)
		})
	}
}

func TestDecodeARM64RawSVESubtractBoundaries(t *testing.T) {
	op, form, ok := decodeARM64RawSVEAddSub(0x04230404)
	if !ok || op != "ZSUB" || form.mode != arm64SVEAddUnpredicated ||
		form.elementBits != 8 || form.first != 0 || form.second != 3 || form.destination != 4 {
		t.Fatalf("decode lightning SUB = %s %+v, %v", op, form, ok)
	}
	for _, word := range []uint32{
		0x2521c000 | 1<<13, // shifted B immediate is reserved
		0x04200c00,         // adjacent unpredicated opcode
		0x04020000,         // adjacent predicated opcode
	} {
		if op, form, ok := decodeARM64RawSVEAddSub(word); ok {
			t.Errorf("decoded reserved SUB %#08x as %s %+v", word, op, form)
		}
	}
}

func TestTranslateARM64SVEAddSubRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSUBR Z1.S, Z2.S, Z3.S",
		"ZSQSUBR $1, Z2.H, Z2.H",
		"ZUQSUBR Z1.D, Z2.D, Z3.D",
		"ZSUB Z1.S, Z2.S, P0.M, Z3.S",
		"ZSQADD Z1.B, Z2.H, Z3.B",
		"ZUQSUB Z1.S, Z2.S, P0.Z, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveaddsub(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"badsveaddsub": {Name: "badsveaddsub", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE add/sub family", instruction)
			}
		})
	}
}
