package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestReportSeparatesProbeFromObjectAndExecutionEvidence(t *testing.T) {
	for _, contextual := range []bool{false, true} {
		form := &formStat{Descriptor: plan9asm.InstructionDescriptor{
			Arch: plan9asm.ArchAMD64, Goarch: "amd64", Opcode: "MOVQ",
			Family: "move", Form: "MOVQ immediate,gpr64",
		}, SupportedCount: 1}
		if contextual {
			form.SupportedCount, form.ContextCount = 0, 1
		}
		// A manifest entry declares a test association, not a fresh execution.
		manifest := map[string]struct{}{"amd64\x00MOVQ immediate,gpr64": {}}
		rep := buildReport("go-asm", "go1.test", "linux", "amd64", 0, 0, 1,
			nil, map[string]*formStat{"mov": form}, nil, nil, manifest, manifest, nil)
		data, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Evidence map[string]struct {
				Status string `json:"status"`
				Forms  *int   `json:"forms"`
			} `json:"evidence_levels"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		ir := decoded.Evidence["ir_text_generation"]
		if ir.Status != "probe" || ir.Forms == nil || *ir.Forms != rep.SupportedForms {
			t.Errorf("IR evidence must count accepted probes only: %+v", ir)
		}
		for _, stage := range []string{"llvm_object_compilation", "runtime_execution"} {
			got, present := decoded.Evidence[stage]
			if !present || got.Status != "not_run" || got.Forms != nil {
				t.Errorf("manifest/classification promoted to %s evidence: %+v", stage, got)
			}
		}
		markdown := string(renderMarkdown(rep))
		for _, want := range []string{
			"IR text generation", "LLVM 22 object compilation", "Runtime execution",
			"not run by this scanner", "manifest-registered", "Context is not successful translation",
		} {
			if !strings.Contains(markdown, want) {
				t.Errorf("missing evidence boundary %q", want)
			}
		}
	}
}
