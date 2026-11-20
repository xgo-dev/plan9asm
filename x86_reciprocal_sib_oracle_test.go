package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func x86ReciprocalSIBBoundSource(source []byte) bool {
	switch string(source) {
	case "TEXT f(SB),4,$0-0\nVRCPSS 16(R9)(CX*2),X1,X2\nRET\n",
		"TEXT f(SB),4,$0-0\nVRSQRTSS 16(R9)(CX*2),X1,X2\nRET\n":
		return true
	}
	return false
}

func (schema x86SegmentMOVEncoderSchema) reciprocalSIBDiagnostic() (string, bool) {
	index, hasIndex := schema.registers["REG_CX"]
	base, hasBase := schema.registers["REG_R9"]
	if !hasIndex || !hasBase || index <= 0 || base <= 0 || index == base {
		return "", false
	}
	if schema.namedDiagnostic {
		return "asm: asmidx: bad address 2/CX/R9\nasm: assembly failed\n", true
	}
	return fmt.Sprintf("asm: asmidx: bad address 2/%d/%d\nasm: assembly failed\n", index, base), true
}

// This observes only these two complete source rejections. It neither relaxes
// the generic positionless diagnostic reader nor grants physical permission
// to another extended mode32 address or to the retained unbound observations.
func (schema x86SegmentMOVEncoderSchema) acceptsReciprocalSIBDiagnostic(filename, wantFilename string,
	source, wantSource []byte, arch, diagnostic string) bool {
	if filename != wantFilename || !filepath.IsAbs(filename) || arch != "386" ||
		!bytes.Equal(source, wantSource) || !x86ReciprocalSIBBoundSource(source) {
		return false
	}
	current, regular := goAssemblerOracleFixture(filename)
	if !regular || !bytes.Equal(current, source) {
		return false
	}
	expected, known := schema.reciprocalSIBDiagnostic()
	return known && diagnostic == expected
}

func x86ReciprocalSIBOriginalGoRejection(t *testing.T, arch, source string) {
	t.Helper()
	if arch != "386" || !x86ReciprocalSIBBoundSource([]byte(source)) {
		t.Fatalf("unbound reciprocal SIB rejection fixture: %s / %q", arch, source)
	}
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	expected, known := producer.schema.reciprocalSIBDiagnostic()
	if !known {
		t.Fatal("actual selected producer lacks the complete CX/R9 register tuple")
	}
	driver, _ := x86LEAActualSDKDriver(t)
	dir := t.TempDir()
	input, object := filepath.Join(dir, "forms.s"), filepath.Join(dir, "forms.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	before, regular := goAssemblerOracleFixture(input)
	if !regular || !bytes.Equal(before, []byte(source)) {
		t.Fatal("original reciprocal source is not the complete regular fixture")
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	include := filepath.Join(runtime.GOROOT(), "pkg", "include")
	command := exec.CommandContext(ctx, driver, "tool", "asm", "-I", include,
		"-p", "example.com/forms", "-o", object, input)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := x86UnnamedAsmidxOutcome(output, err, ctx.Err(), expected); failure != nil {
		t.Fatalf("exact reciprocal source rejection lost its tuple/exit/lifecycle: %v\n%s", failure, output)
	}
	if !producer.schema.acceptsReciprocalSIBDiagnostic(input, input, before, []byte(source), arch, string(output)) {
		t.Fatal("actual reciprocal rejection lost its original source/selected producer identity")
	}
	t.Logf("ORIGINAL_RECIPROCAL_SIB_REJECTION arch=%s sourceSHA=%x outputSHA=%x output=%q",
		arch, sha256.Sum256(before), sha256.Sum256(output), output)
}
