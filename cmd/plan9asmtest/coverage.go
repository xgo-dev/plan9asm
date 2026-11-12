package main

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type coverageBlock struct {
	Statements uint64
	Count      uint64
}

var coverageLocation = regexp.MustCompile(`^.+:[1-9][0-9]*\.[1-9][0-9]*,[1-9][0-9]*\.[1-9][0-9]*$`)

func mergeCoverage(inputs []string) ([]byte, error) {
	return mergeCoverageInventory(inputs, true)
}

func mergeModuleCoverage(inputs []string) ([]byte, error) {
	return mergeCoverageInventory(inputs, false)
}

func mergeCoverageInventory(inputs []string, identical bool) ([]byte, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no coverage inputs")
	}
	var mode string
	var total map[string]coverageBlock
	for _, path := range inputs {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		currentMode, blocks, readErr := readCoverage(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("coverage %s: read=%v close=%v", path, readErr, closeErr)
		}
		if total == nil {
			mode, total = currentMode, blocks
			continue
		}
		if currentMode != mode || identical && len(blocks) != len(total) {
			return nil, fmt.Errorf("coverage mode/block inventory changed in %s", path)
		}
		for key, block := range blocks {
			old, exists := total[key]
			if !exists && !identical {
				total[key] = block
				continue
			}
			if !exists || old.Statements != block.Statements || math.MaxUint64-old.Count < block.Count {
				return nil, fmt.Errorf("coverage block changed/counter overflow: %s", key)
			}
			if mode == "set" {
				old.Count |= block.Count
			} else {
				old.Count += block.Count
			}
			total[key] = old
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "mode: %s\n", mode)
	keys := make([]string, 0, len(total))
	for key := range total {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		block := total[key]
		fmt.Fprintf(&out, "%s %d %d\n", key, block.Statements, block.Count)
	}
	return []byte(out.String()), nil
}

func readCoverage(file *os.File) (string, map[string]coverageBlock, error) {
	scanner := largeScanner(file)
	if !scanner.Scan() {
		return "", nil, fmt.Errorf("missing coverage mode: %v", scanner.Err())
	}
	mode := strings.TrimPrefix(scanner.Text(), "mode: ")
	if scanner.Text() != "mode: "+mode || mode != "set" && mode != "count" && mode != "atomic" {
		return "", nil, fmt.Errorf("invalid coverage mode")
	}
	blocks := make(map[string]coverageBlock)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !coverageLocation.MatchString(fields[0]) {
			return "", nil, fmt.Errorf("invalid coverage block %q", scanner.Text())
		}
		statements, err1 := strconv.ParseUint(fields[1], 10, 64)
		count, err2 := strconv.ParseUint(fields[2], 10, 64)
		if _, duplicate := blocks[fields[0]]; duplicate || err1 != nil || err2 != nil || mode == "set" && count > 1 {
			return "", nil, fmt.Errorf("invalid/duplicate coverage counters %q", scanner.Text())
		}
		blocks[fields[0]] = coverageBlock{statements, count}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, err
	}
	return mode, blocks, nil
}
