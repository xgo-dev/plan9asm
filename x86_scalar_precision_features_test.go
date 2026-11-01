package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarPrecisionCompleteMinimalNativeFeatures(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarPrecisionOracleRows(arch) {
			instruction := x86ScalarLaneInstruction(t, row.instruction())
			want := "+sse2"
			if row.vector {
				want = "+avx"
				if row.high || row.control != "" || row.mode == "merge" || row.mode == "zero" {
					want = "+avx512f"
				}
			}
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{instruction}}); got != want {
				t.Fatal("isolated named precision form lost its minimum native ISA", arch, row.instruction(), got, want)
			}
		}
		for _, row := range x86ScalarPrecisionRawCases() {
			if arch == "386" && (row.row.mode == "merge" || row.row.mode == "zero") {
				continue // The physical decoder retains its separate current mode32 mask boundary.
			}
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t,
				"TEXT ·RawMinimum(SB),4,$0-0\n"+x86RawDisplacementDirectives(row.code)+"RET\n"), arch)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"legacy": "+sse2", "VEX": "+avx", "EVEX": "+avx512f"}[row.generation]
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0]); got != want {
				t.Fatal("low-bank physical precision generation lost its minimum native ISA", arch, row.generation, row.row.instruction(), got, want)
			}
		}
		for _, source := range []string{
			"CVTSS2SD", "CVTSD2SS Y0,X1", "VCVTSS2SD.SAE (AX),X1,X2",
			"VCVTSD2SS.SAE X0,X1,X2", "VCVTSS2SD.Z X0,X1,X2",
		} {
			instruction := x86ScalarLaneInstruction(t, source)
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{instruction}}); got != "" {
				t.Fatal("malformed scalar precision source acquired a native ISA profile", arch, source, got)
			}
		}
	}
}

// Every function has just one conversion and its own inferred feature set.
// Compiling them in one module cannot borrow an SSE/AVX/EVEX sibling's profile.
// These original uninitialized Go/emitter objects remain public Context, not
// initialized execution, caller memory or a native-entry certificate.
func TestX86ScalarPrecisionIsolatedNativeProfileObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("isolated scalar precision native profiles require LLVM22")
	}
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		for index, row := range x86ScalarPrecisionOracleRows(arch) {
			if row.source == "FP" {
				continue // The independent owned scalar-input matrix, not an unbound native format.
			}
			fmt.Fprintf(&source, "TEXT ·NamedMinimum%d(SB),4,$0-0\n%s\nRET\n", index, row.instruction())
		}
		for index, row := range x86ScalarPrecisionRawCases() {
			if arch == "386" && (row.row.mode == "merge" || row.row.mode == "zero") {
				continue
			}
			fmt.Fprintf(&source, "TEXT ·RawMinimum%d(SB),4,$0-0\n%sRET\n", index, x86RawDisplacementDirectives(row.code))
		}
		targets := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			targets = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range targets {
			t.Run(arch+"/"+triple, func(t *testing.T) {
				file, signatures := x86UnboundVoidFormatSources(t, source.String(), arch, triple)
				normalized, err := normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ir := x86ScalarFormatObjectUnit(t, normalized, signatures, arch, triple, 0)
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					compileLLVMToObject(t, llc, triple, "precision-minimum.ll", "precision-minimum.o", text)
				}
			})
		}
	}
}
