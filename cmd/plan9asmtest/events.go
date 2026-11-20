package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type testEvent struct {
	Action     string
	Package    string
	ImportPath string
	Test       string
}

func validateEvents(reader io.Reader, pkg string, names []string) (map[string]string, error) {
	return validateSuiteEvents(reader, pkg, names, false, false)
}

func validateSuiteEvents(reader io.Reader, pkg string, names []string, allowEmpty, noTestFiles bool) (map[string]string, error) {
	states := make(map[string]string)
	planned := make(map[string]bool)
	for _, name := range names {
		if !validName(name) || planned[name] {
			return states, fmt.Errorf("invalid/duplicate JSON plan %q", name)
		}
		planned[name] = true
	}
	if len(planned) == 0 && !allowEmpty {
		return states, fmt.Errorf("empty JSON plan")
	}
	started, finished, failed := false, false, false
	scanner := largeScanner(reader)
	for scanner.Scan() {
		var event testEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return states, fmt.Errorf("invalid Go JSON: %w", err)
		}
		// Go 1.24+ emits dependency compiler output separately from test2json.
		if event.Action == "build-output" && event.ImportPath != "" && event.Test == "" {
			continue
		}
		if event.Package != pkg || finished {
			return states, fmt.Errorf("unexpected package or post-terminal event: %+v", event)
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				if started {
					return states, fmt.Errorf("duplicate package start")
				}
				started = true
			case "output":
				if !started {
					return states, fmt.Errorf("package output before start")
				}
			case "pass", "fail":
				if !started {
					return states, fmt.Errorf("package terminal before start")
				}
				finished = true
				failed = failed || event.Action == "fail"
			case "skip":
				// Go's package-level no-test-files terminal is not a skipped
				// selected test. This is only allowed by actual go list metadata.
				if !started || !noTestFiles || len(planned) != 0 {
					return states, fmt.Errorf("unexpected package skip")
				}
				finished = true
			default:
				return states, fmt.Errorf("unexpected package action %q", event.Action)
			}
			continue
		}
		root, _, child := strings.Cut(event.Test, "/")
		if !started || !planned[root] || child && states[root] != "run" {
			return states, fmt.Errorf("unplanned/out-of-order test event: %+v", event)
		}
		switch event.Action {
		case "run":
			if states[event.Test] != "" {
				return states, fmt.Errorf("duplicate test run: %s", event.Test)
			}
			states[event.Test] = "run"
		case "pass", "fail", "skip":
			if states[event.Test] != "run" {
				return states, fmt.Errorf("test terminal without unique run: %s", event.Test)
			}
			states[event.Test] = event.Action
			failed = failed || event.Action == "fail"
		case "output", "pause", "cont", "attr", "artifacts":
			// Terminal output can occur before the corresponding terminal event,
			// but cannot serve as a substitute for an actual run/terminal pair.
			if states[event.Test] != "run" {
				return states, fmt.Errorf("test action outside run: %+v", event)
			}
		default:
			return states, fmt.Errorf("unexpected test action %q", event.Action)
		}
	}
	if err := scanner.Err(); err != nil {
		return states, err
	}
	for name := range planned {
		if states[name] != "pass" && states[name] != "skip" && states[name] != "fail" {
			return states, fmt.Errorf("missing planned test terminal: %s", name)
		}
	}
	for name, state := range states {
		if state == "run" {
			return states, fmt.Errorf("missing subtest/seed terminal: %s", name)
		}
	}
	if !finished || failed {
		return states, fmt.Errorf("missing package pass or actual test/package failure")
	}
	return states, nil
}
