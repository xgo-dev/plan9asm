package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestTranslateARM64VectorPermuteCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT ·vectorpermuteforms(SB), $0-0\n")
	for _, op := range []string{"VZIP1", "VZIP2", "VUZP1", "VUZP2", "VTRN1", "VTRN2"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			src.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V2." + arrangement + "\n")
		}
	}
	src.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, src.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"vectorpermuteforms": {Name: "vectorpermuteforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		// The 42 operations each emit one result shuffle. The three 64-bit
		// arrangements also narrow both inputs, adding 36 shuffles.
		if got := strings.Count(ll, "shufflevector"); got != 78 {
			t.Fatalf("%s emitted %d vector shuffles, want 78:\n%s", triple, got, ll)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-permute.ll", "arm64-vector-permute.o", ll)
	}
}

func TestTranslateARM64VectorPermuteRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VZIP1 V0.B8, V1.B8",
		"VUZP2 V0.B8, V1.B16, V2.B8",
		"VTRN1 V0.D1, V1.D1, V2.D1",
		"VTRN2 V0.S4, V1.S4, V2.S4, V3.S4",
		"VZIP2 V0, V1, V2",
		"VUZP1.P V0.B16, V1.B16, V2.B16",
	} {
		t.Run(strings.Fields(instruction)[0]+"-"+strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT ·badvectorpermute(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, src, false)
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"badvectorpermute": {Name: "badvectorpermute", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector permute optab", instruction)
			}
		})
	}
}

func requireARM64GoAssemblerResult(t *testing.T, src string, wantSuccess bool) {
	requireARM64GoAssemblerResultWithExperiment(t, src, wantSuccess, "")
}

func requireARM64SVEGoAssemblerResult(t *testing.T, src string, wantSuccess bool) {
	requireARM64GoAssemblerResultWithExperiment(t, src, wantSuccess, "simd")
}

func requireARM64GoAssemblerResultWithExperiment(t *testing.T, src string, wantSuccess bool, experiment string) {
	t.Helper()
	// These fixtures are derived from the Go 1.27 assembler tables. Older Go
	// compatibility lanes must still parse, translate, and compile them through
	// LLVM 22, but their own assembler cannot serve as the 1.27 form oracle.
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "forms.s")
	if err := os.WriteFile(asm, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-p", "example.com/forms", "-o", filepath.Join(dir, "forms.o"), asm)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	if experiment != "" {
		cmd.Env = append(cmd.Env, "GOEXPERIMENT="+experiment)
	}
	out, err := cmd.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("Go 1.27 assembler rejected accepted forms: %v\n%s", err, out)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("Go 1.27 assembler accepted a form expected outside the optab:\n%s", src)
	}
}

func goToolchainAtLeast(version string, wantMajor, wantMinor int) bool {
	start := strings.Index(version, "go")
	if start < 0 {
		return false
	}
	parts := strings.SplitN(version[start+2:], ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minorText := parts[1]
	end := 0
	for end < len(minorText) && minorText[end] >= '0' && minorText[end] <= '9' {
		end++
	}
	if end == 0 {
		return false
	}
	minor, err := strconv.Atoi(minorText[:end])
	if err != nil {
		return false
	}
	return major > wantMajor || major == wantMajor && minor >= wantMinor
}

func TestGoToolchainAtLeast(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "go1.26.9", want: false},
		{version: "go1.27", want: true},
		{version: "go1.27rc1", want: true},
		{version: "go1.28.0", want: true},
		{version: "devel go1.28-abcdef", want: true},
		{version: "devel", want: false},
	}
	for _, test := range tests {
		if got := goToolchainAtLeast(test.version, 1, 27); got != test.want {
			t.Errorf("goToolchainAtLeast(%q, 1, 27) = %v, want %v", test.version, got, test.want)
		}
	}
}
