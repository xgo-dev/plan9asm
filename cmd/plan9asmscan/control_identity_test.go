package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanGoAssemblerKeepsRejectedControlsSeparate(t *testing.T) {
	const ordinary = "VADDPD X2, X9, X2"
	// This is the original Go 1.20 amd64enc_extra.s observation. Its
	// z=1/aaa=0 bytes are invalid; a historical encoder bug is not NUM.
	const invalid = "VADDPD.Z X30, X1, X0"
	root := t.TempDir()
	path := filepath.Join(root, "src/cmd/asm/internal/asm/testdata/amd64enc_extra.s")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(ordinary+"\n"+invalid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ops, forms, parseErrors, files, err := scanGoAssemblerTestdata(root, plan9asm.ArchAMD64, "amd64")
	if err != nil || len(parseErrors) != 0 || files != 1 || len(forms) != 2 {
		t.Fatalf("original probes merged: files=%d forms=%d parse=%v err=%v", files, len(forms), parseErrors, err)
	}
	report := buildReport("go-asm", "go1.20.invalid-encoding-fixture", "linux", "amd64",
		0, 0, files, ops, forms, nil, nil, nil, nil, parseErrors)
	if report.UniqueForms != 2 || report.SupportedForms != 1 || report.UnsupportedForms != 1 || report.ContextForms != 0 {
		t.Fatalf("invalid source changed ordinary acceptance or became context: %+v", report.Forms)
	}
	if len(report.UnsupportedByForm) != 1 {
		t.Fatalf("lost the actual failed source: %+v", report.UnsupportedByForm)
	}
	failure := report.UnsupportedByForm[0]
	if failure.Opcode != "VADDPD" || failure.Form != "VADDPD.Z xmm,xmm,xmm" || failure.Count != 1 ||
		len(failure.Examples) != 1 || failure.Examples[0] != invalid ||
		len(failure.Files) != 1 || failure.Files[0] != "amd64enc_extra.s" ||
		len(failure.Errors) != 1 || !strings.Contains(failure.Errors[0], invalid) ||
		failure.RuntimeVerified || failure.CompileOnly {
		t.Fatalf("failure lost its exact controls/source/diagnostic or acquired evidence: %+v", failure)
	}
}

func TestControlledFormsDoNotInheritBaseEvidence(t *testing.T) {
	rows := []string{
		"VADDPD Z0,Z1,K1,Z2", "VADDPD.Z Z0,Z1,K1,Z2",
		"VADDPD (AX),Z1,K1,Z2", "VADDPD.BCST (AX),Z1,K1,Z2", "VADDPD.BCST.Z (AX),Z1,K1,Z2",
		"VADDPD.RN_SAE Z0,Z1,K1,Z2", "VADDPD.RD_SAE Z0,Z1,K1,Z2",
		"VADDPD.RU_SAE Z0,Z1,K1,Z2", "VADDPD.RZ_SAE Z0,Z1,K1,Z2", "VADDPD.RN_SAE.Z Z0,Z1,K1,Z2",
		"VMAXPD Z0,Z1,K1,Z2", "VMAXPD.SAE Z0,Z1,K1,Z2", "VMAXPD.SAE.Z Z0,Z1,K1,Z2",
	}
	forms := map[string]*formStat{}
	manifest := map[string]struct{}{}
	for index, row := range rows {
		ins := compactProbeInstructions(t, row)[0]
		descriptor := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, "amd64", ins)
		addFormStat(forms, plan9asm.ArchAMD64, "amd64", ins, "controls.s")
		if index == 0 {
			manifest["amd64\x00"+descriptor.Form] = struct{}{}
		}
	}
	if len(forms) != len(rows) {
		t.Fatalf("distinct memory, rounding, SAE or zeroing controls collapsed: forms=%d rows=%d", len(forms), len(rows))
	}
	report := buildReport("go-asm", "go1.test", "linux", "amd64", 0, 0, 1,
		nil, forms, nil, nil, manifest, manifest, nil)
	if report.RuntimeVerifiedForms != 1 || report.CompileOnlyForms != 1 {
		t.Fatalf("a base-form association supplied evidence to other controls: runtime=%d compile=%d", report.RuntimeVerifiedForms, report.CompileOnlyForms)
	}
	for _, form := range report.Forms {
		if strings.Contains(form.Form, ".") && (form.RuntimeVerified || form.CompileOnly) {
			t.Fatalf("source controls inherited a base-form association: %+v", form)
		}
	}
}
