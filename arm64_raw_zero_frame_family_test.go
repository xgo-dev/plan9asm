package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Reuse the independently MC-encoded complete scalar/GP-pair/FP-pair matrix.
// Unlike the framed-leaf family this source receives no Go prologue, owns only
// its explicit negative-SP envelope, and also exercises local raw BL returns.
func arm64RawZeroFrameFamilyFixture(t *testing.T) (*File, map[string]FuncSig, string, []arm64RawPrivateMemoryCase) {
	t.Helper()
	base := arm64RawPrivateMemoryCases()
	var native []string
	for _, tc := range base {
		native = append(native, tc.store, tc.load)
	}
	words := assembleARM64LLVMWords(t, native, "")
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var cases []arm64RawPrivateMemoryCase
	for index, original := range base {
		for _, call := range []bool{false, true} {
			tc := original
			tc.name = "zero_" + tc.name
			if call {
				tc.name += "_local_call"
			}
			prep := "MOVD (R0),R4\nMOVD 8(R0),R5\n"
			outputs := "MOVD R9,(R1)\n"
			if tc.count == 2 {
				outputs += "MOVD R10,8(R1)\n"
			}
			if tc.floating {
				prep = "FMOVQ (R0),F0\nFMOVQ 16(R0),F1\n"
				op := map[int]string{4: "FMOVS", 8: "FMOVD", 16: "FMOVQ"}[tc.width]
				outputs = op + " F2,(R1)\n"
				if tc.count == 2 {
					outputs += fmt.Sprintf("%s F3,%d(R1)\n", op, tc.width)
				}
			}
			body := "WORD $0xd10183ff\n" + prep +
				fmt.Sprintf("WORD $%#08x\nWORD $%#08x\n", words[2*index], words[2*index+1]) +
				outputs + "WORD $0x910183ff\n"
			flags := 4
			if index&1 != 0 {
				flags = 516
			}
			fixture := strings.Replace(arm64RawZeroFrameFixture(flags, call, body), "rawZero", tc.name, 1)
			source.WriteString(fixture)
			sig := arm64RawZeroFrameSig()
			sig.Name = tc.name
			sigs[tc.name] = sig
			cases = append(cases, tc)
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		if !arm64RawZeroFrameUnexposed(fn) {
			t.Fatalf("complete private envelope rejected %s", fn.Sym)
		}
	}
	return file, sigs, source.String(), cases
}

func TestARM64RawZeroFrameMemoryFamilyObjects(t *testing.T) {
	file, sigs, _, cases := arm64RawZeroFrameFamilyFixture(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-zero-family.ll", "raw-zero-family.o", ir)
		})
	}
	t.Logf("actual Go + LLVM22 objects: %d typed scalar/GP-pair/FP-pair offset/writeback/raw-local-call variants", len(cases))
}

func TestARM64RawZeroFrameGoMemorySpellings(t *testing.T) {
	// asm7 AMOVB/H/W aliases, AMOVD, floating S/D/Q and all typed pair
	// widths share this ownership proof, not a guessed raw write mask.
	for _, pair := range []struct{ store, load string }{
		{"MOVB R4", "MOVB"}, {"MOVBU R4", "MOVBU"},
		{"MOVH R4", "MOVH"}, {"MOVHU R4", "MOVHU"},
		{"MOVW R4", "MOVW"}, {"MOVWU R4", "MOVWU"}, {"MOVD R4", "MOVD"},
		{"FMOVS F0", "FMOVS"}, {"FMOVD F0", "FMOVD"}, {"FMOVQ F0", "FMOVQ"},
		{"STP (R4,R5)", "LDP"}, {"STPW (R4,R5)", "LDPW"}, {"STPW (R4,R5)", "LDPSW"},
		{"FSTPS (F0,F1)", "FLDPS"}, {"FSTPD (F0,F1)", "FLDPD"}, {"FSTPQ (F0,F1)", "FLDPQ"},
	} {
		for _, mode := range []string{"offset", "pre_post", "post_pre"} {
			t.Run(pair.store+"/"+pair.load+"/"+mode, func(t *testing.T) {
				storeOp, values, _ := strings.Cut(pair.store, " ")
				destination := "R9"
				if strings.HasPrefix(pair.load, "F") {
					destination = "F2"
				}
				if strings.Contains(values, ",") {
					destination = "(R9,R10)"
					if strings.HasPrefix(pair.load, "F") {
						destination = "(F2,F3)"
					}
				}
				store := fmt.Sprintf("%s %s,16(RSP)", storeOp, values)
				load := fmt.Sprintf("%s 16(RSP),%s", pair.load, destination)
				if mode == "pre_post" {
					store = fmt.Sprintf("%s.W %s,-32(RSP)", storeOp, values)
					load = fmt.Sprintf("%s.P 32(RSP),%s", pair.load, destination)
				} else if mode == "post_pre" {
					store = fmt.Sprintf("%s.P %s,32(RSP)", storeOp, values)
					load = fmt.Sprintf("%s.W -32(RSP),%s", pair.load, destination)
				}
				body := "SUB $96,RSP\n" + store + "\n" + load + "\nMOVD R4,(R1)\nADD $96,RSP\n"
				source := arm64RawZeroFrameFixture(516, false, body)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				if !arm64RawZeroFrameUnexposed(file.Funcs[0]) {
					t.Fatal("Go-accepted complete memory spelling lost ownership")
				}
			})
		}
	}
}
