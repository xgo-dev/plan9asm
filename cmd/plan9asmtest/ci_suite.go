package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
)

type ciRootReceipt struct {
	Name    string   `json:"name"`
	Command []string `json:"command"`
	Stem    string   `json:"artifact_stem"`
	Exit    int      `json:"actual_exit"`
	Output  string   `json:"stdout_sha256"`
	Stderr  string   `json:"stderr_sha256"`
	Status  string   `json:"status"`
	Error   string   `json:"error"`
}

type ciReport struct {
	Plan   ciPlan          `json:"plan"`
	Go     string          `json:"actual_go_executable"`
	Owner  int             `json:"owner"`
	Roots  []ciRootReceipt `json:"owned_root_receipts"`
	Final  *ciScope        `json:"final_scope"`
	Status string          `json:"status"`
	Error  string          `json:"error"`
}

func ciWriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func ciReadJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return fmt.Errorf("bounded regular report required: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing report JSON: %v", err)
	}
	return nil
}

func ciPrepare(cfg config) (config, error) {
	if cfg.Workers < 0 || cfg.Workers > 1 {
		return cfg, fmt.Errorf("selected-CI owners remain serial; workers must be one")
	}
	if cfg.CISelector == "" || cfg.CIIsolate == "" || cfg.Timeout <= 0 || cfg.Shards < 2 || cfg.Shards > 1024 || cfg.Package == "" || strings.ContainsAny(cfg.Package, " \t\r\n*?[") || strings.Contains(cfg.Package, "...") || os.Getenv("GOFLAGS") != "" {
		return cfg, fmt.Errorf("complete CI selector/isolate/owners, positive timeout, one exact package and empty GOFLAGS required")
	}
	if os.Getenv("GOENV") != "off" || os.Getenv("GOWORK") != "off" || os.Getenv("GOTOOLCHAIN") != "local" {
		return cfg, fmt.Errorf("CI invocation requires explicit GOENV=off, GOWORK=off, GOTOOLCHAIN=local before launching tools")
	}
	flags, profile, err := validateFlags(cfg.Flags)
	if err != nil {
		return cfg, err
	}
	if profile != "" {
		return cfg, fmt.Errorf("selected-CI coverage merging is not registered; use ordinary exhaustive suite")
	}
	for _, flag := range flags {
		name, _, _ := strings.Cut(flag, "=")
		switch name {
		case "-overlay", "-modfile", "-gcflags", "-asmflags", "-ldflags":
			return cfg, fmt.Errorf("selected-CI external compiler inputs are not source-indexed: %s (ordinary mode unchanged)", name)
		}
	}
	cfg.Flags = flags
	if cfg.CIVerify == "" {
		if cfg.CIOwner < 0 || cfg.CIOwner >= cfg.Shards {
			return cfg, fmt.Errorf("CI owner outside complete plan")
		}
	} else if cfg.CIOwner != -1 {
		return cfg, fmt.Errorf("CI reader cannot also execute an owner")
	}
	cfg.Go, err = exec.LookPath(cfg.Go)
	if err == nil {
		cfg.Go, err = filepath.Abs(cfg.Go)
	}
	if err == nil {
		cfg.Dir, err = filepath.Abs(cfg.Dir)
	}
	if err == nil {
		cfg.Out, err = filepath.Abs(cfg.Out)
	}
	if err == nil {
		err = os.Mkdir(cfg.Out, 0755)
	}
	return cfg, err
}

func captureCIPlan(ctx context.Context, cfg config) (ciPlan, error) {
	plan := ciPlan{Protocol: ciProtocol, Flags: cfg.Flags, Timeout: cfg.Timeout.String(), Selector: cfg.CISelector, Isolate: cfg.CIIsolate, Owners: cfg.Shards}
	scope, err := captureCIScope(ctx, cfg, filepath.Join(cfg.Out, "before"))
	if err != nil {
		return plan, err
	}
	plan.Scope = scope
	listing := func(stem, selector string) (string, []string, []string, error) {
		args := append([]string{"test"}, cfg.Flags...)
		args = append(args, "-count=1", "-timeout="+cfg.Timeout.String(), "-list="+selector, cfg.Package)
		path := filepath.Join(cfg.Out, stem)
		if _, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, args, path); err != nil {
			return "", nil, nil, err
		}
		data, err := os.ReadFile(path + ".stdout")
		if err != nil {
			return "", nil, nil, err
		}
		return parseList(string(data))
	}
	plan.Package, plan.Inventory, plan.Benchmarks, err = listing("inventory", ".")
	if err != nil {
		return plan, err
	}
	selectedPackage, selected, _, err := listing("selected", cfg.CISelector)
	if err != nil {
		return plan, err
	}
	if selectedPackage != plan.Package {
		return plan, fmt.Errorf("actual full and selected package identities differ")
	}
	plan.Selected = selected
	plan.InventorySHA, plan.SelectedSHA = ciNamesSHA(plan.Inventory), ciNamesSHA(plan.Selected)
	_, err = ciAssignments(plan)
	return plan, err
}

func ciRootCommand(goBinary string, plan ciPlan, name string) ([]string, error) {
	pattern, err := runPattern([]string{name})
	if err != nil {
		return nil, err
	}
	command := append([]string{goBinary, "test"}, plan.Flags...)
	return append(command, "-count=1", "-timeout="+plan.Timeout, "-json", "-run="+pattern, plan.Package), nil
}

func runCI(ctx context.Context, cfg config) error {
	cfg, err := ciPrepare(cfg)
	if err != nil {
		return err
	}
	plan, err := captureCIPlan(ctx, cfg)
	if err != nil {
		return err
	}
	if cfg.CIVerify != "" {
		err = verifyCIArtifacts(plan, cfg.CIVerify)
		final, guardErr := captureCIScope(ctx, cfg, filepath.Join(cfg.Out, "after"))
		if guardErr == nil && !reflect.DeepEqual(plan.Scope, final) {
			guardErr = fmt.Errorf("aggregate source/SDK/tool/environment changed")
		}
		result := errors.Join(err, guardErr)
		status := "passed"
		if result != nil {
			status = "failed"
		}
		return errors.Join(result, ciWriteJSON(filepath.Join(cfg.Out, "aggregate.json"), struct {
			Plan   ciPlan `json:"plan"`
			Status string `json:"status"`
		}{plan, status}))
	}
	owners, _ := ciAssignments(plan)
	report := ciReport{Plan: plan, Go: cfg.Go, Owner: cfg.CIOwner, Status: "failed", Roots: []ciRootReceipt{}}
	publish := func() error { return ciWriteJSON(filepath.Join(cfg.Out, "report.json"), report) }
	if err := publish(); err != nil {
		return err
	}
	var failures []error
	for index, name := range owners[cfg.CIOwner] {
		command, err := ciRootCommand(cfg.Go, plan, name)
		if err != nil {
			return err
		}
		root := ciRootReceipt{Name: name, Command: command, Stem: fmt.Sprintf("root-%04d", index), Exit: -1, Status: "failed"}
		stem := filepath.Join(cfg.Out, root.Stem)
		_, executionErr := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, command[1:], stem)
		if executionErr == nil {
			root.Exit = 0
		} else {
			var exit *exec.ExitError
			if errors.As(executionErr, &exit) {
				root.Exit = exit.ExitCode()
			}
			root.Error = executionErr.Error()
		}
		root.Output, err = ciFileSHA(stem + ".stdout")
		if err == nil {
			root.Stderr, err = ciFileSHA(stem + ".stderr")
		}
		validationErr := validateCIRoot(cfg.Out, plan, root)
		if err = errors.Join(executionErr, err, validationErr); err != nil {
			root.Error = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		} else {
			root.Status = "passed"
		}
		report.Roots = append(report.Roots, root)
		fmt.Printf("CI owner %d root %s: %s\n", cfg.CIOwner, name, root.Status)
		if err := publish(); err != nil {
			return err
		}
	}
	final, err := captureCIScope(ctx, cfg, filepath.Join(cfg.Out, "after"))
	if err == nil && !reflect.DeepEqual(plan.Scope, final) {
		err = fmt.Errorf("worker source/SDK/tool/environment changed")
	}
	if err != nil {
		failures = append(failures, err)
	} else {
		report.Final = &final
	}
	if len(failures) == 0 {
		report.Status = "passed"
	} else {
		report.Error = errors.Join(failures...).Error()
	}
	return errors.Join(errors.Join(failures...), publish())
}

func validateCIRoot(directory string, plan ciPlan, root ciRootReceipt) error {
	if root.Exit != 0 || root.Error != "" {
		return fmt.Errorf("root actual execution failed (exit %d): %s", root.Exit, root.Error)
	}
	if filepath.Base(root.Stem) != root.Stem || !strings.HasPrefix(root.Stem, "root-") {
		return fmt.Errorf("root artifact must be local")
	}
	var bytes int64
	for suffix, expected := range map[string]string{".stdout": root.Output, ".stderr": root.Stderr} {
		info, err := os.Lstat(filepath.Join(directory, root.Stem+suffix))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("actual output must be a regular owned artifact: %v", err)
		}
		bytes += info.Size()
		if bytes > 64<<20 {
			return fmt.Errorf("actual root output exceeds original capture bound")
		}
		hash, err := ciFileSHA(filepath.Join(directory, root.Stem+suffix))
		if err != nil || expected == "" || hash != expected {
			return fmt.Errorf("actual root %s identity differs: %v", suffix, err)
		}
	}
	file, err := os.Open(filepath.Join(directory, root.Stem+".stdout"))
	if err != nil {
		return err
	}
	outcomes, err := validateEvents(file, plan.Package, []string{root.Name})
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	for name, outcome := range outcomes {
		if outcome != "pass" {
			return fmt.Errorf("required root/subtest/seed %s did not pass: %s", name, outcome)
		}
	}
	return nil
}

func verifyCIArtifacts(expected ciPlan, directory string) error {
	owners, err := ciAssignments(expected)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != len(owners) {
		return fmt.Errorf("found %d owners, require exactly %d", len(entries), len(owners))
	}
	var failures []error
	for index, names := range owners {
		path := filepath.Join(directory, fmt.Sprintf("cross-runtime-owner-%d", index))
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			failures = append(failures, fmt.Errorf("owner %d directory missing or aliased", index))
			continue
		}
		var report ciReport
		if err := ciReadJSON(filepath.Join(path, "report.json"), &report); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := verifyCIScopeArtifacts(path, report); err != nil {
			failures = append(failures, fmt.Errorf("owner %d observation: %w", index, err))
			continue
		}
		if !reflect.DeepEqual(report.Plan, expected) || report.Owner != index || report.Go == "" || report.Final == nil || !reflect.DeepEqual(*report.Final, expected.Scope) || report.Status != "passed" || report.Error != "" || len(report.Roots) != len(names) {
			failures = append(failures, fmt.Errorf("owner %d incomplete or foreign source/SDK/config/plan", index))
			continue
		}
		for position, name := range names {
			root := report.Roots[position]
			command, err := ciRootCommand(report.Go, expected, name)
			if err != nil || root.Name != name || root.Stem != fmt.Sprintf("root-%04d", position) || !reflect.DeepEqual(root.Command, command) || root.Status != "passed" {
				failures = append(failures, fmt.Errorf("owner %d root %s missing/duplicated/foreign command", index, name))
				continue
			}
			if err := validateCIRoot(path, expected, root); err != nil {
				failures = append(failures, fmt.Errorf("owner %d root %s: %w", index, name, err))
			}
		}
	}
	return errors.Join(failures...)
}
