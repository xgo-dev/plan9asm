// plan9asmgooracle retains strict stock-Go observations of the selected decoder
// families. Source refusals are distinct from infrastructure/verification errors.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

type options struct {
	cases, families, driver, goroot, output string
}

type result struct {
	Index                                   int
	CorpusRow, Instruction, Source, Object  string
	SourceSHA256, ObjectSHA256              string
	ObjectKind, ObjectTarget, ObjectVersion string
	ObjectPhysical                          string
	ObjectIdentity                          map[string]string
	Argv                                    []string
	Started, Ended                          time.Time
	Status                                  string
	ExitCode, PID, PGID                     int
	Waited, Attempted, Complete, Reported   bool
	TimedOut                                bool
	Stdout, Stderr, Failure                 string
	guard                                   *gooriginalsrc.Snapshot
	directory                               os.FileInfo
}

type report struct {
	Protocol                                          string
	Selected, Accepted, Rejected, Failed              int
	Attempted, Unattempted, TimedOut, ReportFailures  int
	InventoryComplete, Verified, Passed, InputsStable bool
	SetupFailure, InputFailure                        string
	Results                                           []result
}

var selectedOpcode = regexp.MustCompile(`^([A-Z][A-Z0-9.]*)\s`)

func writeJSON(path string, value any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(value)
	return errors.Join(encodeErr, file.Close())
}

func writeNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	if written != len(data) {
		writeErr = errors.Join(writeErr, fmt.Errorf("incomplete new file write"))
	}
	return errors.Join(writeErr, file.Close())
}

func instruction(row string) (string, bool) {
	_, asm, found := strings.Cut(row, "|")
	asm = strings.TrimSpace(asm)
	return asm, found && asm != "" && !strings.ContainsAny(asm, "\r\n")
}

// Preserve the original whole-file selector, including row order/duplicates.
// There is no sampling, success-only denominator or unsupported-family filter.
func selectedRows(data, family []byte) []string {
	names := make(map[string]bool)
	for _, line := range strings.Split(string(family), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			names[line] = true
		}
	}
	var rows []string
	for _, line := range strings.Split(string(data), "\n") {
		asm, ok := instruction(line)
		if !ok {
			continue
		}
		match := selectedOpcode.FindStringSubmatch(asm)
		if match != nil && names[strings.SplitN(match[1], ".", 2)[0]] {
			rows = append(rows, line)
		}
	}
	return rows
}

func finalize(value *report, inputStable bool, deadline error) {
	value.Accepted, value.Rejected, value.Failed = 0, 0, 0
	value.Attempted, value.Unattempted, value.TimedOut = 0, 0, 0
	value.InputsStable = inputStable
	complete := value.SetupFailure == "" && value.Selected > 0 &&
		len(value.Results) == value.Selected && inputStable && deadline == nil &&
		value.ReportFailures == 0
	for _, item := range value.Results {
		if item.Attempted {
			value.Attempted++
		} else {
			value.Unattempted++
		}
		if item.TimedOut {
			value.TimedOut++
		}
		complete = complete && item.Attempted && item.Waited && item.Complete && item.Reported && !item.TimedOut
		switch item.Status {
		case "accepted":
			value.Accepted++
		case "rejected":
			value.Rejected++
		default:
			value.Failed++
		}
	}
	value.InventoryComplete = complete
	value.Verified = complete && value.Failed == 0
	value.Passed = value.Verified && value.Accepted > 0
	value.Unattempted = value.Selected - value.Attempted
}

func retainResult(value *report, caseDir string, item result) error {
	var err error
	if item.directory == nil {
		err = fmt.Errorf("case directory never acquired an owned identity")
	} else {
		current, statErr := os.Lstat(caseDir)
		physical, pathErr := sourcepath.Resolve(caseDir)
		if statErr != nil || pathErr != nil || !current.IsDir() || !os.SameFile(item.directory, current) || physical != caseDir {
			err = fmt.Errorf("case directory identity changed before report")
		}
	}
	if err == nil {
		item.Reported = true
		err = writeJSON(filepath.Join(caseDir, "result.json"), item)
	}
	if err != nil {
		item.Reported = false
		value.ReportFailures++
	}
	value.Results = append(value.Results, item)
	return err
}

func execute(ctx context.Context, opt options) (report, error) {
	value := report{Protocol: "actual_go_arm64_decoder_oracle_v1"}
	if !filepath.IsAbs(opt.output) {
		return value, fmt.Errorf("new report directory must be absolute")
	}
	if err := os.Mkdir(opt.output, 0700); err != nil {
		return value, err
	}
	inputs, err := captureInputs(ctx, opt)
	if err != nil {
		value.SetupFailure = err.Error()
		return value, errors.Join(err, writeJSON(filepath.Join(opt.output, "before.json"), inputs.record),
			writeJSON(filepath.Join(opt.output, "report.json"), value))
	}
	rows := selectedRows(inputs.corpus, inputs.family)
	value.Selected = len(rows)
	inputs.record.SelectedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(rows, "\n")+"\n")))
	if len(rows) < 300 {
		value.SetupFailure = fmt.Sprintf("required-family selection unexpectedly small: %d", len(rows))
	}
	var failures []error
	if err := writeJSON(filepath.Join(opt.output, "before.json"), inputs.record); err != nil {
		value.ReportFailures++
		failures = append(failures, err)
	}
	// A failed before receipt or incomplete selection cannot start consumers.
	if value.SetupFailure == "" && len(failures) == 0 {
		for index, row := range rows {
			caseDir := filepath.Join(opt.output, fmt.Sprintf("case-%06d", index))
			item := probe(ctx, caseDir, inputs, index, row)
			if err := retainResult(&value, caseDir, item); err != nil {
				failures = append(failures, fmt.Errorf("case %d report: %w", index, err))
			}
		}
	}
	after, captureErr := captureInputs(ctx, opt)
	stable := false
	if captureErr == nil {
		after.record.SelectedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(selectedRows(after.corpus, after.family), "\n")+"\n")))
		stable = inputs.snapshot.Verify() == nil && reflect.DeepEqual(inputs.record.Identity, after.record.Identity) &&
			inputs.record.SelectedSHA256 == after.record.SelectedSHA256
		if err := writeJSON(filepath.Join(opt.output, "after.json"), after.record); err != nil {
			value.ReportFailures++
			failures = append(failures, err)
		}
	} else {
		value.InputFailure = captureErr.Error()
		failures = append(failures, captureErr)
		if err := writeJSON(filepath.Join(opt.output, "after.json"), after.record); err != nil {
			value.ReportFailures++
			failures = append(failures, err)
		}
	}
	if !stable {
		value.InputFailure = strings.TrimSpace(value.InputFailure + " original corpus/SDK/selected tool inputs changed or could not be reobserved")
		failures = append(failures, fmt.Errorf("%s", value.InputFailure))
	}
	for _, item := range value.Results {
		if item.guard != nil && item.guard.Verify() != nil {
			stable = false
			value.InputFailure = strings.TrimSpace(value.InputFailure + fmt.Sprintf(" case %d original source/object changed", item.Index))
			failures = append(failures, fmt.Errorf("case %d original source/object changed", item.Index))
		}
	}
	var accepted []string
	for _, item := range value.Results {
		if item.Status == "accepted" {
			accepted = append(accepted, item.CorpusRow)
		}
	}
	if err := writeNew(filepath.Join(opt.output, "accepted.txt"), []byte(strings.Join(accepted, "\n")+"\n")); err != nil {
		value.ReportFailures++
		failures = append(failures, err)
	}
	finalize(&value, stable, ctx.Err())
	if err := writeJSON(filepath.Join(opt.output, "report.json"), value); err != nil {
		value.ReportFailures++
		value.InventoryComplete, value.Verified, value.Passed = false, false, false
		failures = append(failures, err)
	}
	if !value.Passed {
		failures = append(failures, fmt.Errorf("oracle incomplete or failed: selected=%d accepted=%d rejected=%d failed=%d unattempted=%d timed_out=%d report_failures=%d",
			value.Selected, value.Accepted, value.Rejected, value.Failed, value.Unattempted, value.TimedOut, value.ReportFailures))
	}
	return value, errors.Join(append(failures, ctx.Err())...)
}

func run() error {
	var opt options
	flag.StringVar(&opt.cases, "cases", "", "complete exact decoder corpus")
	flag.StringVar(&opt.families, "families", "", "complete required-family manifest")
	flag.StringVar(&opt.driver, "go", "", "explicit original stock-Go driver")
	flag.StringVar(&opt.goroot, "goroot", "", "explicit original SDK")
	flag.StringVar(&opt.output, "out", "", "new retained report directory")
	flag.Parse()
	if flag.NArg() != 0 || opt.cases == "" || opt.families == "" || opt.driver == "" || opt.goroot == "" || opt.output == "" {
		return fmt.Errorf("all five exact inputs are required, without positional arguments")
	}
	// The setup, every child and final reobservation share this original bound.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	value, err := execute(ctx, opt)
	fmt.Printf("x/arch required families: selected=%d native_go_accepted=%d decoder_only_rejected=%d failed=%d inventory_complete=%t verified=%t passed=%t\n",
		value.Selected, value.Accepted, value.Rejected, value.Failed, value.InventoryComplete, value.Verified, value.Passed)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
