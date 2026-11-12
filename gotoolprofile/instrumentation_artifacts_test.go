package gotoolprofile

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func artifactTestObservation(index int, ir, object int64) (OutputProof, *InstrumentationLLVMArtifacts) {
	irName, objectName := instrumentationArtifactNames(index)
	digest := strings.Repeat("1", 64)
	return OutputProof{Part: irName, IR: digest, Object: digest}, &InstrumentationLLVMArtifacts{
		Protocol: InstrumentationArtifactProtocol,
		IR:       InstrumentationLLVMArtifact{Role: "llvm_ir", Name: irName, Bytes: ir, SHA256: digest},
		Object:   InstrumentationLLVMArtifact{Role: "llvm_object", Name: objectName, Bytes: object, SHA256: digest},
	}
}

func TestInstrumentationArtifactSharedBudgetAndOverflow(t *testing.T) {
	budget := &InstrumentationLLVMArtifactBudget{}
	for index := 0; index < 3; index++ {
		output, proof := artifactTestObservation(index, InstrumentationIRByteLimit, InstrumentationObjectByteLimit)
		if err := ValidateInstrumentationLLVMArtifacts(index, output, proof, budget); err != nil {
			t.Fatal(err)
		}
	}
	output, proof := artifactTestObservation(3, 64<<20-1, 1)
	if err := ValidateInstrumentationLLVMArtifacts(3, output, proof, budget); err != nil || budget.bytes != InstrumentationArtifactByteLimit {
		t.Fatalf("exact shared bound: %v, %d", err, budget.bytes)
	}
	output, proof = artifactTestObservation(4, 1, 1)
	if err := ValidateInstrumentationLLVMArtifacts(4, output, proof, budget); err == nil {
		t.Fatal("a new file obtained a new invocation budget")
	}
	for _, used := range []int64{-1, math.MaxInt64} {
		output, proof := artifactTestObservation(0, 1, 1)
		if err := ValidateInstrumentationLLVMArtifacts(0, output, proof, &InstrumentationLLVMArtifactBudget{bytes: used}); err == nil {
			t.Fatal("invalid/overflowed private counter accepted")
		}
	}
}

func TestInstrumentationArtifactRoleAndOrdinalTripwires(t *testing.T) {
	for name, mutate := range map[string]func(*OutputProof, *InstrumentationLLVMArtifacts){
		"old protocol":     func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.Protocol = "legacy" },
		"deleted protocol": func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.Protocol = "" },
		"source as IR":     func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR.Role = "module_source" },
		"source name":      func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR.Name = "original.s" },
		"swapped roles":    func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR, p.Object = p.Object, p.IR },
		"empty hash":       func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR.SHA256 = "" },
		"changed hash":     func(o *OutputProof, _ *InstrumentationLLVMArtifacts) { o.IR = strings.Repeat("0", 64) },
		"foreign object":   func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.Object.Name = "instrumented-0001.o" },
		"escaped IR":       func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR.Name = "../instrumented-0000.ll" },
		"changed output":   func(o *OutputProof, _ *InstrumentationLLVMArtifacts) { o.Part = "instrumented-0001.ll" },
		"IR over bound":    func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR.Bytes = InstrumentationIRByteLimit + 1 },
		"object over bound": func(_ *OutputProof, p *InstrumentationLLVMArtifacts) {
			p.Object.Bytes = InstrumentationObjectByteLimit + 1
		},
		"negative bytes": func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.IR.Bytes = -1 },
		"empty object":   func(_ *OutputProof, p *InstrumentationLLVMArtifacts) { p.Object.Bytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			output, proof := artifactTestObservation(0, 1, 1)
			mutate(&output, proof)
			budget := &InstrumentationLLVMArtifactBudget{}
			if err := ValidateInstrumentationLLVMArtifacts(0, output, proof, budget); err == nil || budget.bytes != 0 || budget.ordinal != 0 {
				t.Fatal("invalid role mutated the budget or supplied evidence")
			}
		})
	}
	output, proof := artifactTestObservation(0, 1, 1)
	budget := &InstrumentationLLVMArtifactBudget{}
	if err := ValidateInstrumentationLLVMArtifacts(0, output, proof, budget); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstrumentationLLVMArtifacts(0, output, proof, budget); err == nil {
		t.Fatal("duplicate ordinal accepted")
	}
	if err := ValidateInstrumentationLLVMArtifacts(0, output, nil, &InstrumentationLLVMArtifactBudget{}); err == nil {
		t.Fatal("paired deletion accepted")
	}
	if err := ValidateInstrumentationLLVMArtifacts(0, output, proof, nil); err == nil {
		t.Fatal("missing invocation budget accepted")
	}
}

func TestInstrumentationArtifactPhysicalBoundsPrecedeStreaming(t *testing.T) {
	for _, test := range []struct {
		name       string
		ir, object int64
	}{
		{"IR above its generated limit", InstrumentationIRByteLimit + 1, 1},
		{"object above its generated limit", 1, InstrumentationObjectByteLimit + 1},
		{"empty IR", 0, 1},
		{"empty object", 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			ir, object := instrumentationArtifactNames(0)
			for name, size := range map[string]int64{ir: test.ir, object: test.object} {
				file, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				truncateErr, closeErr := file.Truncate(size), file.Close()
				if truncateErr != nil || closeErr != nil {
					t.Fatalf("stat-only fixture: %v; %v", truncateErr, closeErr)
				}
			}
			// Sparse invalid size fixtures establish pre-read refusal only;
			// they are not valid LLVM or source/compiler certificates.
			if _, err := CaptureInstrumentationLLVMArtifacts(root, 0, &InstrumentationLLVMArtifactBudget{}); err == nil ||
				!strings.Contains(err.Error(), "must be a nonempty bounded regular artifact") {
				t.Fatalf("unbounded/empty artifact did not reach its physical byte-bound rejection: %v", err)
			}
		})
	}
}

func TestInstrumentationArtifactEqualByteReplacementLosesReservedIdentity(t *testing.T) {
	// The private reservation helper requires a physical root; public capture
	// resolves its caller's root before reserving any generated artifact.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := "instrumented-0000.ll"
	path := filepath.Join(root, name)
	bytes := []byte("artifact inode fixture; no compiler/source claim\n")
	if err := os.WriteFile(path, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	reserved, err := instrumentationLLVMArtifactInfo(root, name, "llvm_ir", InstrumentationIRByteLimit)
	if err != nil {
		t.Fatalf("regular artifact reservation at original root %q: %v", root, err)
	}
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureInstrumentationLLVMArtifact(root, name, "llvm_ir", InstrumentationIRByteLimit, reserved); err == nil {
		t.Fatal("equal bytes replaced the reserved physical file identity")
	}
}
