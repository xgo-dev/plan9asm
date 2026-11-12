package plan9asm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go/format"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestX86Reciprocal14NativeFiniteRowsAndFactoredCases(t *testing.T) {
	rows := x86Reciprocal14NativeRows()
	if len(rows) != 236 {
		t.Fatal("132 canonical + 96 alias + 8 dynamic rows changed", len(rows))
	}
	var members [8]int
	profiles := make(map[int]int)
	seen := make(map[string]bool)
	for index, row := range rows {
		key := fmt.Sprint(row.member, "/", row.width, "/", row.source, "/", row.mode, "/", row.low, "/", row.upper, "/", row.dynamic)
		if row.id != index || seen[key] {
			t.Fatal("duplicate or unstable row identity", row)
		}
		seen[key] = true
		members[row.member]++
		profiles[row.profile()]++
		if index < 132 && (row.low != 16 || row.upper != 17 || row.dynamic) {
			t.Fatal("canonical row replaced by alias", row)
		}
	}
	if profiles[5] != 140 || profiles[6] != 96 || len(profiles) != 2 {
		t.Fatal("F / FVL profile denominator", profiles)
	}
	if members != [8]int{37, 37, 22, 22, 37, 37, 22, 22} {
		t.Fatal("missing complete eight-member shape", members)
	}
	for _, profile := range []int{5, 6} {
		var selected []x86Reciprocal14NativeRow
		for _, row := range rows {
			if row.profile() == profile {
				selected = append(selected, row)
			}
		}
		cases := x86Reciprocal14NativeCases(selected)
		if len(cases) < 2000 || len(cases) > 18000 {
			t.Fatal("factored cases unexpectedly Cartesian or empty", profile, len(cases))
		}
		source, declarations, _ := x86Reciprocal14NativeSource(selected, false)
		for _, forbidden := range []string{"KMOVQ", "VMOVUPS (AX),X", "VMOVUPS (BX),X", "VMOVUPS (CX),X", "KeepFunc", "Crop"} {
			if strings.Contains(source, forbidden) {
				t.Fatal("native source lost minimum profile or full-source boundary", forbidden)
			}
		}
		if strings.Count(source, "TEXT ·") != len(selected) || strings.Count(declarations, "func ") != len(selected) ||
			strings.Count(source, "LDMXCSR 128(DI)") != len(selected) {
			t.Fatal("incomplete initialized native program")
		}
	}
}

func TestX86Reciprocal14NativeTraceRejectsForeignAndIncompleteRecords(t *testing.T) {
	cases := []x86Reciprocal14NativeCase{{3, 6, 0x1234, 0x1f80, 0x1fc0}, {7, 16, 0xffff, 0x1f80, 0x9f80}}
	data := make([]byte, 16+184*len(cases))
	copy(data, "R14TRACE")
	binary.LittleEndian.PutUint32(data[8:], 1)
	binary.LittleEndian.PutUint32(data[12:], uint32(len(cases)))
	for index, c := range cases {
		r := data[16+184*index:]
		binary.LittleEndian.PutUint32(r, uint32(c.row))
		binary.LittleEndian.PutUint32(r[4:], uint32(c.sample))
		binary.LittleEndian.PutUint64(r[8:], c.mask)
		binary.LittleEndian.PutUint32(r[16:], c.first)
		binary.LittleEndian.PutUint32(r[20:], c.second)
	}
	if err := x86Reciprocal14NativeTrace(data, cases); err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{0, 7, 15, len(data) - 1, len(data) + 1} {
		changed := append(append([]byte(nil), data...), 0)
		if err := x86Reciprocal14NativeTrace(changed[:length], cases); err == nil {
			t.Fatal("incomplete trace accepted", length)
		}
	}
	for _, offset := range []int{0, 8, 12, 16, 20, 24, 28, 32, 36, 200} {
		changed := append([]byte(nil), data...)
		changed[offset] ^= 1
		if err := x86Reciprocal14NativeTrace(changed, cases); err == nil {
			t.Fatal("foreign trace identity accepted", offset)
		}
	}
	duplicate := append([]byte(nil), data...)
	copy(duplicate[200:], duplicate[16:200])
	if err := x86Reciprocal14NativeTrace(duplicate, cases); err == nil {
		t.Fatal("duplicate trace record replaced an actual case")
	}
}

func TestX86Reciprocal14NativeGoListingBoundaryControls(t *testing.T) {
	original := "literal.R140 STEXT nosplit asm size=1 args=0x0 locals=0x0\n" +
		"  0x0000 00000 (fixture.s:2) RET\n" + fmt.Sprintf("  0x0000%-48s  .\n", " c3")
	mutations := map[string][2]string{
		"foreign package":  {"literal.R140", "foreign.R140"},
		"wrong TEXT":       {"STEXT ", "SRODATA "},
		"wrong PC":         {"0x0000 00000", "0x0001 00001"},
		"wrong decimal PC": {"0x0000 00000", "0x0000 00001"},
		"wrong source row": {"fixture.s:2", "fixture.s:3"},
		"truncated extent": {"size=1", "size=2"},
	}
	inspect := func(owner string, line int, code []byte) {
		if owner != "R140" || line != 2 || !bytes.Equal(code, []byte{0xc3}) {
			t.Fatal("foreign original source instruction", owner, line, code)
		}
	}
	rows := []x86Reciprocal14NativeRow{{id: 0, width: 64, low: 16, upper: 17}}
	if fixture := os.Getenv("PLAN9ASM_RECIPROCAL14_LISTING_FIXTURE"); fixture != "" {
		mutation, exists := mutations[fixture]
		if !exists {
			t.Fatal("unknown boundary-control fixture")
		}
		listing := strings.Replace(original, mutation[0], mutation[1], 1)
		x86Reciprocal14NativeGoBytesIR(t, listing, rows, inspect)
		return // Accepted corruption is a successful child, rejected by parent.
	}
	for _, prefix := range []string{"literal.", `"".`} {
		x86Reciprocal14NativeGoBytesIR(t, strings.Replace(original, "literal.", prefix, 1), rows, inspect)
	}
	for name := range mutations {
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestX86Reciprocal14NativeGoListingBoundaryControls$", "-test.count=1")
		command.Env = append(os.Environ(), "PLAN9ASM_RECIPROCAL14_LISTING_FIXTURE="+name)
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		var status *exec.ExitError
		if !errors.As(err, &status) || status != err || status.ExitCode() != 1 ||
			!strings.Contains(string(output), "--- FAIL: TestX86Reciprocal14NativeGoListingBoundaryControls") ||
			!strings.Contains(string(output), "original") {
			t.Fatalf("corrupt Go listing was accepted or failed without its source-bound rejection: %s: %v\n%s", name, err, output)
		}
	}
	t.Logf("two actual producer prefixes accepted; %d foreign package/TEXT/PC/source/extent controls rejected", len(mutations))
}

func TestX86Reciprocal14NativeExplicitOwnerPolicy(t *testing.T) {
	data, err := os.ReadFile("x86_reciprocal14_native_linux_amd64_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("//go:build linux && amd64 && plan9asm_native_avx512\n")) ||
		strings.Count(string(data), "func TestX86Reciprocal14Native") != 2 ||
		strings.Contains(string(data), "TestCrossLinuxRuntimeMatrix") || strings.Contains(string(data), ".Skip") {
		t.Fatal("native execution owners escaped explicit hardware qualification")
	}
	_, file, _ := x86OriginalFloatingPolicyFile(t, "x86_reciprocal14_native_runtime_test.go")
	owner := x86OriginalFloatingPolicyFunction(t, file, "x86RunReciprocal14Native")
	var calls bytes.Buffer
	if err := format.Node(&calls, token.NewFileSet(), owner); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"x86RunOriginalGoNativeSource", "x86NativeFixtureASMDecl", "x86ScalarFPBitViewAPI", "x86OriginalFloatingRuntimeRequireCPU", "x86DwordProductIROptimize", "x86Reciprocal14NativeTrace", "os.Chmod"} {
		if !strings.Contains(calls.String(), required) {
			t.Fatal("native owner lost an independent stage", required)
		}
	}
}

func TestX86Reciprocal14NativeOriginalGoProgramCompiles(t *testing.T) {
	var rows []x86Reciprocal14NativeRow
	for _, row := range x86Reciprocal14NativeRows() {
		if row.dynamic || row.source == 0 && row.mode == 0 && row.low == 16 && row.upper == 17 &&
			(row.width == 64 || x86Reciprocal14TestMembers[row.member].scalar) {
			rows = append(rows, row)
		}
	}
	source, declarations, _ := x86Reciprocal14NativeSource(rows, false)
	x86NativeFixtureASMDecl(t, "amd64", declarations, source, "")
	var cases strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&cases, "{%d,6,65535,8064,8128},\n", row.id)
	}
	directory := t.TempDir()
	original := strings.NewReplacer("@ROWS@", x86Reciprocal14NativeMetadata(rows, true),
		"@CASES@", cases.String(), "@TRACE@", strconv.Quote(filepath.Join(directory, "unexecuted.trace"))).Replace(x86Reciprocal14NativeOriginalGo)
	for name, data := range map[string]string{
		"go.mod":        "module oracle\n\ngo 1.20\n",
		"value.go":      "package oracle\n" + declarations + "func MXCSR(value uint32) uint32\n",
		"value_amd64.s": source + x86OriginalNativeMXCSRSource("amd64"),
		"value_test.go": original,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	driver, _ := x86LEAActualSDKDriver(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "test", "-p=1", "-c", "-o", filepath.Join(directory, "original.test"), ".")
	command.Dir, command.Env = directory, x86OriginalGoNativeEnvironment("amd64", os.Environ())
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original-Go trace program did not compile (not executed): %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(directory, "unexecuted.trace")); !os.IsNotExist(err) {
		t.Fatal("object-only fixture unexpectedly executed", err)
	}
}

func TestX86Reciprocal14NativeSourceThreeAPIsActualProfileObjects(t *testing.T) {
	for _, profile := range []int{5, 6} {
		var rows []x86Reciprocal14NativeRow
		for _, row := range x86Reciprocal14NativeRows() {
			if row.profile() == profile {
				rows = append(rows, row)
			}
		}
		name := map[int]string{5: "estimate14-F", 6: "estimate14-FVL"}[profile]
		for start := 0; start < len(rows); start += 32 {
			end := start + 32
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("profile%d/batch%d", profile, start/32), func(t *testing.T) {
				batch := rows[start:end]
				source, declarations, _ := x86Reciprocal14NativeSource(batch, false)
				listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
				if err != nil {
					t.Fatal(err)
				}
				x86NativeFixtureASMDecl(t, "amd64", declarations, source, "")
				// Disassemble exact original Go text bytes, including its transport.
				// This is object inspection, not raw-source translator permission.
				original := x86Reciprocal14NativeGoBytesIR(t, listing, batch)
				x86OriginalFloatingOpcodeListing(t, name, "x86_64-unknown-linux-gnu", "-O0", original, true, 0)
				masked := false
				for _, row := range batch {
					masked = masked || row.mode != 0
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil {
							t.Fatal("full initialized native source rejected", err)
						}
						x86OriginalFloatingRuntimeObjectPipelines(t, name, "x86_64-unknown-linux-gnu", ir, masked, 0)
					})
				}
			})
		}
	}
}

func TestX86Reciprocal14NativeDeadSourceOriginalBytesAndThreeAPIs(t *testing.T) {
	for _, profile := range []int{5, 6} {
		var rows []x86Reciprocal14NativeRow
		for _, row := range x86Reciprocal14NativeRows() {
			if row.id < 132 && row.source != 0 && row.profile() == profile {
				rows = append(rows, row)
			}
		}
		for start := 0; start < len(rows); start += 32 {
			end := start + 32
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("profile%d/batch%d", profile, start/32), func(t *testing.T) {
				source, declarations, fixture := x86Reciprocal14NativeFaultProgram(t, rows[start:end], profile)
				if strings.Count(fixture, ".byte ") != end-start || strings.Contains(fixture, "vrcp14") || strings.Contains(fixture, "vrsqrt14") {
					t.Fatal("fault reference must use complete actual Go bytes, not reconstructed mnemonics")
				}
				if root := os.Getenv("PLAN9ASM_RUNTIME_ARTIFACT_DIR"); root != "" {
					path := filepath.Join(root, t.Name(), "fault.c")
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
						t.Fatal(err)
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil {
							t.Fatal("dead native memory source rejected", err)
						}
						x86OriginalFloatingRuntimeObjectPipelines(t, map[int]string{5: "estimate14-F", 6: "estimate14-FVL"}[profile],
							"x86_64-unknown-linux-gnu", ir, true, 0)
					})
				}
			})
		}
	}
}

// The existing Go byte-column parser owns byte extraction. No instruction is
// decoded, shortened or given numerical/address permission here; LLVM objdump
// independently disassembles every copied byte for the finite ISA-profile audit.
func x86Reciprocal14NativeGoBytesIR(t *testing.T, listing string, rows []x86Reciprocal14NativeRow,
	inspect ...func(string, int, []byte)) string {
	t.Helper()
	var ir strings.Builder
	ir.WriteString("target triple = \"x86_64-unknown-linux-gnu\"\n")
	seen, owner, size, expected := make(map[string]bool), "", 0, 0
	last := byte(0)
	var body []byte
	var instructions [][2]int
	wanted := make(map[string]bool)
	for _, row := range rows {
		wanted[row.name()] = true
	}
	finish := func() {
		if owner == "" {
			return
		}
		if owner != "" && (size == 0 || size != expected || last != 0xc3) {
			t.Fatal("original Go TEXT has no complete RET/size byte boundary", owner, size, expected)
		}
		for index, instruction := range instructions {
			end := len(body)
			if index+1 < len(instructions) {
				end = instructions[index+1][0]
			}
			if instruction[0] < 0 || instruction[0] >= end || end > len(body) {
				t.Fatal("original Go instruction has incomplete PC boundaries", owner, instruction, end)
			}
			for _, observer := range inspect {
				observer(owner, instruction[1], append([]byte(nil), body[instruction[0]:end]...))
			}
		}
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[1] == "STEXT" || fields[1] == "STEXTFIPS") {
			finish()
			// Match the existing official-row binder: historical Go emits
			// an empty package even with -p. No foreign package is accepted.
			owner = strings.TrimPrefix(fields[0], "literal.")
			if owner == fields[0] {
				owner = strings.TrimPrefix(fields[0], `"".`)
			}
			if owner == fields[0] {
				t.Fatal("foreign original Go package", fields[0])
			}
			size, expected = 0, 0
			body, instructions = nil, nil
			for _, field := range fields {
				if strings.HasPrefix(field, "size=") {
					n, err := strconv.Atoi(strings.TrimPrefix(field, "size="))
					if err != nil || n <= 0 {
						t.Fatal("invalid original Go TEXT extent", line)
					}
					expected = n
				}
			}
			if !wanted[owner] || seen[owner] {
				t.Fatal("foreign or duplicate original Go TEXT", owner)
			}
			seen[owner] = true
			fmt.Fprintf(&ir, "module asm \".globl OriginalGo%d\"\nmodule asm \"OriginalGo%d:\"\n", len(seen), len(seen))
			continue
		}
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "S") && !strings.HasPrefix(fields[0], "0x") {
			finish()
			owner = ""
		}
		if owner == "" {
			continue
		}
		if match := x86OfficialPackedListingInstruction.FindStringSubmatch(line); match != nil &&
			match[4] != "TEXT" && match[4] != "PCDATA" && match[4] != "FUNCDATA" {
			pc, pcErr := strconv.ParseUint(match[1], 16, 32)
			decimal, decimalErr := strconv.ParseUint(match[2], 10, 32)
			line, lineErr := strconv.Atoi(match[3])
			if pcErr != nil || decimalErr != nil || lineErr != nil || pc != decimal ||
				len(instructions) != 0 && int(pc) <= instructions[len(instructions)-1][0] {
				t.Fatal("invalid original Go instruction position", match)
			}
			instructions = append(instructions, [2]int{int(pc), line})
		}
		code := x86InsertExtractListedBytes(line)
		if len(code) == 0 {
			continue
		}
		pc, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 32)
		if owner == "" || err != nil || int(pc) != size {
			t.Fatal("noncontiguous original Go byte ownership", line)
		}
		ir.WriteString("module asm \".byte ")
		for index, b := range code {
			if index != 0 {
				ir.WriteByte(',')
			}
			fmt.Fprintf(&ir, "0x%02x", b)
		}
		ir.WriteString("\"\n")
		size += len(code)
		body = append(body, code...)
		last = code[len(code)-1]
	}
	finish()
	if len(seen) != len(rows) {
		t.Fatal("original Go byte directory incomplete", len(seen), len(rows))
	}
	return ir.String()
}
