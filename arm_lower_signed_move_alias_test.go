package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const armSignedMoveAliasForms = `TEXT signedMoveAliases(SB),$0-0
	MOVBS R5, R6
	MOVBS R1, (R2)
	MOVBS.P R1, (R2)
	MOVBS.W R1, 32(R2)
	MOVBS (R2), R1
	MOVBS.P 32(R2), R1
	MOVBS.W -32(R2), R1
	MOVBS R0, math·Exp(SB)
	MOVBS math·Exp(SB), R0
	MOVBS R2@>0, R8
	MOVHS R5, R6
	MOVHS R4, (R3)
	MOVHS.P R4, (R3)
	MOVHS.W R3, 32(R4)
	MOVHS (R9), R8
	MOVHS.P 34(R9), R8
	MOVHS.W -36(R9), R8
	MOVHS R0, math·Exp(SB)
	MOVHS math·Exp(SB), R0
	MOVHS R3@>8, R9
	RET
`

func requireARMGoAssemblerResult(t *testing.T, src string, wantSuccess bool) {
	t.Helper()
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "forms.s")
	if err := os.WriteFile(asm, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-p", "example.com/forms", "-o", filepath.Join(dir, "forms.o"), asm)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm")
	out, err := cmd.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("Go 1.27 ARM assembler rejected accepted forms: %v\n%s", err, out)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("Go 1.27 ARM assembler accepted a form expected outside the optab:\n%s", src)
	}
}

func TestTranslateARMSignedMoveAliasCompleteFormats(t *testing.T) {
	requireARMGoAssemblerResult(t, armSignedMoveAliasForms, true)
	ll := translateARMForTest(t, armSignedMoveAliasForms, map[string]FuncSig{
		"example.signedMoveAliases": {Name: "example.signedMoveAliases", Ret: Void},
	})
	for _, want := range []string{
		"sext i8", "sext i16", "trunc i32", "llvm.fshr.i32", "@math.Exp",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("signed move alias lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-signed-move-alias.ll", "arm-signed-move-alias.o", ll)
}

func TestTranslateARMSignedMoveAliasRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"MOVBS R1", "MOVHS R1, R2, R3"} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARMGoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "armv7-unknown-linux-gnueabihf",
			Goarch:       "arm",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM MOVBS/MOVHS optab", instruction)
		}
	}
}
