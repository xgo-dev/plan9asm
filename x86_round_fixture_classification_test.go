package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// A real source refusal is neither an object success nor a native fault.
// Keep all three public APIs negative without guessing the refusal's error class.
func x86RoundRejectedGoSource(t *testing.T, source, declarations, arch, triple string) {
	t.Helper()
	goAssemblerOracleOutput(t, arch, "#include \"textflag.h\"\n"+source, "", false)
	for _, api := range []string{"text", "module", "Go"} {
		if ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api); ir != "" || err == nil {
			t.Fatal("Go-refused ordinary ROUND source was accepted by public API", api, err)
		}
	}
}

// This retains the original mixed fixture exactly, observes every statement,
// and emits only independently Go-selected statements in its ordinary object.
func x86RoundOriginalSourceClassifiedObjects(t *testing.T, original, arch, triple string) string {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86RoundRejectedGoSource(t, original, "func roundforms()", arch, triple)
	file, err := Parse(ArchAMD64, original)
	if err != nil {
		t.Fatal(err)
	}
	var selected strings.Builder
	selected.WriteString("TEXT roundforms(SB),NOSPLIT,$0-0\n")
	accepted, refused, originalRows := 0, 0, 0
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == OpTEXT || ins.Op == OpRET {
			continue
		}
		originalRows++
		scalarVEX := ins.Op == "VROUNDSS" || ins.Op == "VROUNDSD"
		bad := scalarVEX && (arch == "386" || ins.Args[0].Imm < 0)
		row := "TEXT roundoriginal(SB),NOSPLIT,$0-0\n" + ins.Raw + "\nRET\n"
		t.Run(fmt.Sprint("original-", originalRows), func(t *testing.T) {
			if bad {
				x86RoundRejectedGoSource(t, row, "func roundoriginal()", arch, triple)
			} else {
				x86LEAActualTargetGoObject(t, arch, triple, "#include \"textflag.h\"\n"+row)
			}
		})
		if bad {
			refused++
		} else {
			accepted++
			selected.WriteString(ins.Raw + "\n")
		}
		if scalarVEX && ins.Args[0].Imm < 0 {
			// Yu8 cannot encode this original negative spelling. Keep its
			// independent ordinary AMD64 counterpart instead of erasing it.
			counterpart := strings.Replace(ins.Raw, "$-1", "$255", 1)
			counterSource := "TEXT roundcounterpart(SB),NOSPLIT,$0-0\n" + counterpart + "\nRET\n"
			if arch == "amd64" {
				ir := x86UnboundVoidScalarFormatObject(t, counterSource, "roundcounterpart", arch, triple)
				x86PackedStringCompileObject(t, llc, triple, ir, "-O0")
			}
		}
		if arch == "386" && scalarVEX {
			// Physical low-bank VEX bytes exist in mode32 even though the
			// ordinary Go frontend rejects four operands. Obtain the bytes
			// from real Go/AMD64 using Yu8, then keep raw mode32 separate.
			physical := strings.Replace(ins.Raw, "$-1", "$255", 1)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+physical+"\nRET\n")
			if len(code) < 2 || code[len(code)-1] != 0xc3 {
				t.Fatal("actual scalar ROUND lost its complete RET boundary")
			}
			raw := "TEXT roundphysical(SB),4,$0-0\n" + x86DwordProductDirectives(code[:len(code)-1]) + "\nRET\n"
			ir := x86UnboundVoidRawScalarFormatObject(t, raw, arch, triple)
			x86PackedStringCompileObject(t, llc, triple, ir, "-O0")
		}
	}
	wantAccepted, wantRefused := 20, 2
	if arch == "386" {
		wantAccepted, wantRefused = 16, 6
	}
	if originalRows != 22 || accepted != wantAccepted || refused != wantRefused {
		t.Fatal("original ROUND inventory changed", originalRows, accepted, refused)
	}
	selected.WriteString("RET\n")
	t.Logf("original ROUND statements=%d ordinary-Go-selected=%d refused=%d; physical raw format objects are separate", originalRows, accepted, refused)
	return x86UnboundVoidScalarFormatObject(t, selected.String(), "roundforms", arch, triple)
}
