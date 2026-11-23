package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

type wasmDirectEncoderObservation struct {
	Opcode  string                    `json:"opcode"`
	Outcome string                    `json:"outcome"`
	Samples []wasmDirectEncoderSample `json:"samples"`
}

type wasmDirectEncoderSample struct {
	Source       string `json:"source"`
	ExitCode     int    `json:"exit_code"`
	BodyHex      string `json:"body_hex,omitempty"`
	ObjectSHA256 string `json:"object_sha256,omitempty"`
	Diagnostic   string `json:"diagnostic,omitempty"`
}

// These witnesses exercise the direct Plan 9 spellings. Go generates some of
// the same opcodes with proper operands from other source forms, notably
// BrTable through resume dispatch and local/global operations through Get.
var wasmDirectEncoderCases = []struct {
	spelling, opcodeHex string
	indexes             int
}{
	{"BrTable", "", 1},
	{"DataDrop", "fc09", 1},
	{"ElemDrop", "fc0d", 1},
	{"GlobalGet", "23", 1},
	{"GlobalSet", "24", 1},
	{"LocalGet", "20", 1},
	{"LocalSet", "21", 1},
	{"LocalTee", "22", 1},
	{"MemoryInit", "fc08", 2},
	{"TableCopy", "fc0e", 2},
	{"TableFill", "fc11", 1},
	{"TableGrow", "fc0f", 1},
	{"TableInit", "fc0c", 2},
	{"TableSize", "fc10", 1},
}

const (
	wasmDirectProbeHeader = "TEXT ·probe(SB),4,$0-0\n"
	wasmDirectProbeTail   = "\tI32Const $37\n\tDrop\n\tI32Const $0\n\tReturn\n"
	wasmDirectPanic       = "panic: interface conversion: interface {} is nil, not []uint64"
	wasmDirectPanicFrame  = "cmd/internal/obj/wasm.assemble("
)

func observeWasmDirectEncoder(goroot, goos string) (_ []wasmDirectEncoderObservation, result error) {
	goroot, err := filepath.Abs(goroot)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "plan9asm-wasm-encoder-")
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := append(os.Environ(), "GOROOT="+goroot, "GOOS="+goos, "GOARCH=wasm", "GOTOOLCHAIN=local",
		"GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")
	goBinary := filepath.Join(goroot, "bin", gotoolchain.HostExecutable("go"))
	tools, err := goasmcmd.Run(ctx, dir, env, goBinary, "env", "GOTOOLDIR")
	if err != nil {
		return nil, err
	}
	toolDir := strings.TrimSpace(string(tools))
	relative, err := filepath.Rel(filepath.Join(goroot, "pkg", "tool"), toolDir)
	if err != nil || !filepath.IsLocal(relative) {
		return nil, fmt.Errorf("assembler directory is outside the selected Go toolchain")
	}
	assembler := filepath.Join(toolDir, gotoolchain.HostExecutable("asm"))

	control, err := observeWasmDirectSample(ctx, env, dir, assembler, "control", "", false)
	if err != nil {
		return nil, fmt.Errorf("Wasm assembler control: %w", err)
	}
	// i32.const 37, drop, i32.const 0, return, unreachable, end.
	const tail = "41251a41000f000b"
	if !strings.HasSuffix(control.BodyHex, tail) {
		return nil, fmt.Errorf("Wasm assembler control lost the complete witness tail: %s", control.BodyHex)
	}
	prefix := strings.TrimSuffix(control.BodyHex, tail)
	observations := make([]wasmDirectEncoderObservation, 0, len(wasmDirectEncoderCases))
	for _, witness := range wasmDirectEncoderCases {
		observation := wasmDirectEncoderObservation{Opcode: strings.ToUpper(witness.spelling), Outcome: "indexes_omitted"}
		panicExpected := witness.opcodeHex == ""
		if panicExpected {
			observation.Outcome = "assembler_panic"
		}
		for index := 0; index < 2; index++ {
			operand := fmt.Sprintf("$%d", index)
			operands := strings.TrimSuffix(strings.Repeat(operand+", ", witness.indexes), ", ")
			line := "\t" + witness.spelling + " " + operands + "\n"
			name := fmt.Sprintf("%s-%d", witness.spelling, index)
			sample, err := observeWasmDirectSample(ctx, env, dir, assembler, name, line, panicExpected)
			if err != nil {
				return nil, fmt.Errorf("Wasm direct encoder %s %s: %w", witness.spelling, operands, err)
			}
			if !panicExpected && sample.BodyHex != prefix+witness.opcodeHex+tail {
				return nil, fmt.Errorf("Wasm direct encoder %s %s changed body bytes: %s", witness.spelling, operands, sample.BodyHex)
			}
			observation.Samples = append(observation.Samples, sample)
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func observeWasmDirectSample(ctx context.Context, env []string, dir, assembler, name, line string, panicExpected bool) (wasmDirectEncoderSample, error) {
	sample := wasmDirectEncoderSample{Source: wasmDirectProbeHeader + line + wasmDirectProbeTail}
	source, object := filepath.Join(dir, name+".s"), filepath.Join(dir, name+".o")
	if err := os.WriteFile(source, []byte(sample.Source), 0600); err != nil {
		return sample, err
	}
	observed, err := goasmcmd.Observe(ctx, dir, env, assembler, "-S", "-o", object, source)
	sample.ExitCode = observed.ExitCode
	if !observed.Waited || observed.PID <= 0 || ctx.Err() != nil {
		return sample, fmt.Errorf("no complete assembler process observation: %v", err)
	}
	if panicExpected {
		diagnostic := string(observed.Stderr)
		exit, exited := err.(*exec.ExitError)
		if !exited || exit.ExitCode() != 2 || observed.ExitCode != 2 ||
			!strings.HasPrefix(diagnostic, wasmDirectPanic+"\n") || !strings.Contains(diagnostic, "\n"+wasmDirectPanicFrame) {
			return sample, fmt.Errorf("unexpected assembler panic observation: %v\n%s", err, diagnostic)
		}
		sample.Diagnostic = wasmDirectPanic + "\n" + wasmDirectPanicFrame
		return sample, nil
	}
	if err != nil || observed.ExitCode != 0 || len(observed.Stderr) != 0 {
		return sample, fmt.Errorf("assembler did not emit a clean object and listing: %v\n%s", err, observed.Stderr)
	}
	body, err := wasmListedFunctionBody(string(observed.Stdout))
	if err != nil {
		return sample, err
	}
	data, err := os.ReadFile(object)
	if err != nil {
		return sample, err
	}
	if len(body) == 0 || bytes.Count(data, body) != 1 {
		return sample, fmt.Errorf("listed Wasm body does not occur once in the actual Go object")
	}
	sample.BodyHex = hex.EncodeToString(body)
	sample.ObjectSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	return sample, nil
}

// The -S byte rows have a hex offset and byte columns, followed by two
// spaces and the ASCII view. The separate instruction rows use decimal PCs.
func wasmListedFunctionBody(listing string) ([]byte, error) {
	var body []byte
	for _, line := range strings.Split(listing, "\n") {
		columns, _, _ := strings.Cut(strings.TrimSpace(line), "  ")
		fields := strings.Fields(columns)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseUint(fields[0], 0, 32)
		if err != nil || offset != uint64(len(body)) {
			return nil, fmt.Errorf("noncontiguous Wasm assembly listing: %q", columns)
		}
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil || len(field) != 2 {
				return nil, fmt.Errorf("invalid byte in Wasm assembly listing: %q", field)
			}
			body = append(body, byte(value))
		}
	}
	return body, nil
}
