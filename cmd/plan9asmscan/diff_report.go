package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/xgo-dev/plan9asm/internal/diffreport"
)

// diffExecutionReport mirrors the execution report written by
// TestAMD64MachineCodeDifferentialGate / TestAMD64ConformanceLLVMRuntime when
// PLAN9ASM_DIFF_REPORT_OUT is set.
type diffExecutionReport = diffreport.Report
type diffCaseExecResult = diffreport.Case

func loadDiffExecutionReport(path string) (*diffExecutionReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var dr diffExecutionReport
	if err := json.Unmarshal(data, &dr); err != nil {
		return nil, fmt.Errorf("parse diff report %s: %w", path, err)
	}
	if dr.SchemaVersion != 1 {
		return nil, fmt.Errorf("diff report %s has unsupported schema_version %d (want 1)", path, dr.SchemaVersion)
	}
	if dr.Goarch == "" {
		return nil, fmt.Errorf("diff report %s missing goarch", path)
	}
	return &dr, nil
}

// The case, input assembly and supported forms must describe the same test in
// the current checkout. Otherwise an older report can credit unrelated forms.
func (m *conformanceManifest) checkDiffCases(r *diffExecutionReport) error {
	byID := make(map[string]conformanceCase, len(m.Cases))
	for _, c := range m.Cases {
		if _, exists := byID[c.ID]; exists {
			return fmt.Errorf("duplicate manifest case %q", c.ID)
		}
		byID[c.ID] = c
	}
	for _, c := range r.Cases {
		want, ok := byID[c.ID]
		if !ok || want.Validation != "execute" || want.Goarch != r.Goarch || want.Asm != c.Asm || len(want.Forms) != len(c.Forms) || len(c.Forms) == 0 {
			return fmt.Errorf("diff case %q does not match its executable manifest entry", c.ID)
		}
		forms := make(map[string]bool, len(want.Forms))
		for _, form := range want.Forms {
			forms[form] = true
		}
		for _, form := range c.Forms {
			if !forms[form] {
				return fmt.Errorf("unexpected or repeated form %q in diff case %q", form, c.ID)
			}
			delete(forms, form)
		}
	}
	return nil
}

func attachDiffExecutionReport(rep *report, dr *diffExecutionReport) error {
	if dr == nil {
		return nil
	}
	if err := dr.Validate(); err != nil {
		return err
	}
	if dr.Goarch != rep.Goarch || dr.Goos != rep.Goos || dr.GoVersion != rep.GoVersion {
		return fmt.Errorf("diff target %s/%s %s does not match scan %s/%s %s", dr.Goos, dr.Goarch, dr.GoVersion, rep.Goos, rep.Goarch, rep.GoVersion)
	}
	if rep.ObjectCompileLLVMVersion != "" && diffreport.LLVM22(dr.LLVMVersion) != rep.ObjectCompileLLVMVersion {
		return fmt.Errorf("diff LLVM %q does not match scan LLVM %q", dr.LLVMVersion, rep.ObjectCompileLLVMVersion)
	}

	type formExecAgg struct {
		passed       bool
		expectedOnly bool
		hwPending    bool
		failed       bool
		cases        map[string]struct{}
		missingHW    map[string]struct{}
	}
	byForm := map[string]*formExecAgg{}
	nativeComparedInputs := 0
	for _, tc := range dr.Cases {
		isNativeDiff := dr.NativeOracleRan && tc.VerificationMode == "native_diff" && tc.ComparedInputs > 0
		if isNativeDiff && tc.Status == "passed" && tc.FailedInputs == 0 {
			nativeComparedInputs += tc.ComparedInputs
		}
		for _, form := range tc.Forms {
			agg := byForm[form]
			if agg == nil {
				agg = &formExecAgg{
					cases:     map[string]struct{}{},
					missingHW: map[string]struct{}{},
				}
				byForm[form] = agg
			}
			agg.cases[tc.ID] = struct{}{}
			switch tc.Status {
			case "failed":
				agg.failed = true
			case "passed":
				if isNativeDiff && tc.FailedInputs == 0 {
					agg.passed = true
				} else if tc.VerificationMode == "expected_value_only" {
					agg.expectedOnly = true
				}
			case "expected_value_only", "portable_only":
				agg.expectedOnly = true
			case "hw_pending":
				agg.hwPending = true
				for _, feat := range tc.MissingHWFeatures {
					if feat != "" {
						agg.missingHW[feat] = struct{}{}
					}
				}
			}
		}
	}

	rep.DiffReportLoaded = true
	rep.DiffReportNativeOracle = dr.NativeOracleRan
	rep.DiffReportComparedInputs = nativeComparedInputs
	rep.DiffVerifiedForms = 0
	rep.DiffExpectedOnlyForms = 0
	rep.DiffFailedForms = 0
	rep.HWPendingForms = 0
	rep.HWPendingByForm = nil

	for i := range rep.Forms {
		rep.Forms[i].DiffCases = nil
		rep.Forms[i].DiffStatus = ""
		agg := byForm[rep.Forms[i].Form]
		if agg == nil {
			continue
		}
		caseList := make([]string, 0, len(agg.cases))
		for id := range agg.cases {
			caseList = append(caseList, id)
		}
		sort.Strings(caseList)
		rep.Forms[i].DiffCases = caseList

		switch {
		case agg.failed:
			rep.Forms[i].DiffStatus = "failed"
			rep.DiffFailedForms++
		case agg.passed:
			rep.Forms[i].DiffStatus = "passed"
			rep.DiffVerifiedForms++
		case agg.hwPending:
			rep.Forms[i].DiffStatus = "hw_pending"
			rep.HWPendingForms++
			missing := make([]string, 0, len(agg.missingHW))
			for feat := range agg.missingHW {
				missing = append(missing, feat)
			}
			sort.Strings(missing)
			rep.HWPendingByForm = append(rep.HWPendingByForm, hwPendingFormReport{
				Form:              rep.Forms[i].Form,
				Family:            rep.Forms[i].Family,
				Opcode:            rep.Forms[i].Opcode,
				HWFeatures:        rep.Forms[i].HWFeatures,
				MissingHWFeatures: missing,
				Cases:             caseList,
			})
		case agg.expectedOnly:
			rep.Forms[i].DiffStatus = "expected_value_only"
			rep.DiffExpectedOnlyForms++
		}
	}
	sort.Slice(rep.HWPendingByForm, func(i, j int) bool {
		return rep.HWPendingByForm[i].Form < rep.HWPendingByForm[j].Form
	})
	return nil
}
