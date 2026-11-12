package gotoolprofile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const (
	InstrumentationArtifactProtocol  = "actual_go_instrumentation_generated_artifacts_v1"
	InstrumentationIRByteLimit       = int64(256 << 20)
	InstrumentationObjectByteLimit   = int64(64 << 20)
	InstrumentationArtifactByteLimit = int64(1 << 30)
)

// Generated LLVM outputs have their own defensive budgets. They are not CPP,
// Go or authenticated module sources; these observations supply no source role
// or object credit without the independent complete consumption proof.
type InstrumentationLLVMArtifact struct {
	Role   string `json:"role"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type InstrumentationLLVMArtifacts struct {
	Protocol string                      `json:"protocol"`
	IR       InstrumentationLLVMArtifact `json:"ir"`
	Object   InstrumentationLLVMArtifact `json:"object"`
}

// One budget belongs to one invocation, not one file. Its private counters
// prevent repeated ordinals and overflow; it never grants source permissions.
type InstrumentationLLVMArtifactBudget struct {
	bytes   int64
	ordinal int
}

func instrumentationArtifactNames(index int) (string, string) {
	stem := fmt.Sprintf("instrumented-%04d", index)
	return stem + ".ll", stem + ".o"
}

func (budget *InstrumentationLLVMArtifactBudget) check(index int, ir, object int64) error {
	if budget == nil || budget.bytes < 0 || budget.bytes > InstrumentationArtifactByteLimit ||
		budget.ordinal < 0 || index != budget.ordinal || ir <= 0 || ir > InstrumentationIRByteLimit ||
		object <= 0 || object > InstrumentationObjectByteLimit {
		return fmt.Errorf("generated LLVM artifact role, ordinal or individual byte bound is invalid")
	}
	remaining := InstrumentationArtifactByteLimit - budget.bytes
	if ir > remaining || object > remaining-ir {
		return fmt.Errorf("generated LLVM artifacts exceed the shared invocation byte bound")
	}
	return nil
}

// ValidateInstrumentationLLVMArtifacts replays only the generated-output
// observation. The enclosing validator still proves actual Go/CPP/types,
// LLVM22 compilation, selected-file coverage and the independently bound output.
func ValidateInstrumentationLLVMArtifacts(index int, output OutputProof, proof *InstrumentationLLVMArtifacts, budget *InstrumentationLLVMArtifactBudget) error {
	ir, object := instrumentationArtifactNames(index)
	if proof == nil || proof.Protocol != InstrumentationArtifactProtocol || output.Part != ir ||
		proof.IR.Role != "llvm_ir" || proof.IR.Name != ir || proof.Object.Role != "llvm_object" || proof.Object.Name != object ||
		!discoverySHA256Pattern.MatchString(proof.IR.SHA256) || !discoverySHA256Pattern.MatchString(proof.Object.SHA256) ||
		proof.IR.SHA256 != output.IR || proof.Object.SHA256 != output.Object {
		return fmt.Errorf("generated LLVM artifacts lack their exact role/output identity")
	}
	if err := budget.check(index, proof.IR.Bytes, proof.Object.Bytes); err != nil {
		return err
	}
	budget.bytes += proof.IR.Bytes + proof.Object.Bytes
	budget.ordinal++
	return nil
}

// CaptureInstrumentationLLVMArtifacts uses canonical regular files and a
// bounded streaming digest. No LLVM text/object is read into a source buffer.
// The directory, open inode, size and origin are rechecked after each read.
func CaptureInstrumentationLLVMArtifacts(root string, index int, budget *InstrumentationLLVMArtifactBudget) (*InstrumentationLLVMArtifacts, error) {
	if budget == nil || index < 0 || budget.ordinal != index || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("generated LLVM artifacts lack a canonical invocation origin/ordinal")
	}
	physicalRoot, err := sourcepath.Resolve(root)
	if err != nil {
		return nil, err
	}
	rootInfo, err := sourcepath.Lstat(physicalRoot)
	if err != nil || !rootInfo.IsDir() {
		return nil, fmt.Errorf("generated LLVM artifact origin is not an actual directory: %v", err)
	}
	ir, object := instrumentationArtifactNames(index)
	irInfo, err := instrumentationLLVMArtifactInfo(physicalRoot, ir, "llvm_ir", InstrumentationIRByteLimit)
	if err != nil {
		return nil, err
	}
	objectInfo, err := instrumentationLLVMArtifactInfo(physicalRoot, object, "llvm_object", InstrumentationObjectByteLimit)
	if err != nil {
		return nil, err
	}
	// Reserve the whole invocation envelope before opening or hashing either
	// file. The completed observations must fit that same envelope again.
	if err := budget.check(index, irInfo.Size(), objectInfo.Size()); err != nil {
		return nil, err
	}
	proof := &InstrumentationLLVMArtifacts{Protocol: InstrumentationArtifactProtocol}
	proof.IR, err = captureInstrumentationLLVMArtifact(physicalRoot, ir, "llvm_ir", InstrumentationIRByteLimit, irInfo)
	if err != nil {
		return nil, err
	}
	proof.Object, err = captureInstrumentationLLVMArtifact(physicalRoot, object, "llvm_object", InstrumentationObjectByteLimit, objectInfo)
	if err != nil {
		return nil, err
	}
	afterRoot, err := sourcepath.Resolve(root)
	if err != nil || afterRoot != physicalRoot {
		return nil, fmt.Errorf("generated LLVM artifact origin changed during readback: %v", err)
	}
	afterInfo, err := os.Stat(physicalRoot)
	if err != nil || !os.SameFile(rootInfo, afterInfo) {
		return nil, fmt.Errorf("generated LLVM artifact directory was replaced: %v", err)
	}
	output := OutputProof{Part: ir, IR: proof.IR.SHA256, Object: proof.Object.SHA256}
	if err := ValidateInstrumentationLLVMArtifacts(index, output, proof, budget); err != nil {
		return nil, err
	}
	return proof, nil
}

func captureInstrumentationLLVMArtifact(root, name, role string, limit int64, reserved os.FileInfo) (result InstrumentationLLVMArtifact, resultErr error) {
	path := filepath.Join(root, name)
	before, err := instrumentationLLVMArtifactInfo(root, name, role, limit)
	if err != nil {
		return result, err
	}
	if reserved == nil || !os.SameFile(reserved, before) || before.Size() != reserved.Size() || !before.ModTime().Equal(reserved.ModTime()) {
		return result, fmt.Errorf("generated LLVM artifact changed after its budget reservation: %s", name)
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() != before.Size() || !opened.Mode().IsRegular() {
		return result, fmt.Errorf("generated LLVM artifact open identity changed: %s: %v", name, err)
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(file, before.Size()+1))
	if err != nil || count != before.Size() {
		return result, fmt.Errorf("generated LLVM artifact changed or exceeded its streaming bound: %s: %v", name, err)
	}
	after, err := os.Lstat(path)
	resolved, resolveErr := sourcepath.Resolve(path)
	if err != nil || resolveErr != nil || resolved != path || !os.SameFile(before, after) ||
		after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !after.Mode().IsRegular() {
		return result, fmt.Errorf("generated LLVM artifact was replaced or changed: %s: %v", name, errors.Join(err, resolveErr))
	}
	return InstrumentationLLVMArtifact{Role: role, Name: name, Bytes: count, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

func instrumentationLLVMArtifactInfo(root, name, role string, limit int64) (os.FileInfo, error) {
	path := filepath.Join(root, name)
	resolved, err := sourcepath.Resolve(path)
	if err != nil || resolved != path {
		return nil, fmt.Errorf("generated LLVM artifact is missing or redirected: %s: %v", name, err)
	}
	info, err := sourcepath.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("generated %s must be a nonempty bounded regular artifact: %s: %v", role, name, err)
	}
	return info, nil
}
