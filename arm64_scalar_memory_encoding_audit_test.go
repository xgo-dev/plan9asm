package plan9asm

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
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func arm64MemoryAuditGoCommand(t *testing.T, goos string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if ctx.Err() != nil {
		t.Fatalf("actual Go command deadline: %v", ctx.Err())
	}
	var unavailable *exec.Error
	if errors.As(err, &unavailable) {
		t.Fatalf("actual Go tool unavailable: %v", err)
	}
	if err != nil && len(args) >= 2 && args[0] == "tool" && args[1] == "asm" && !bytes.Contains(output, []byte("asm:")) {
		t.Fatalf("Go command failed without an assembler source diagnostic: %v\n%s", err, output)
	}
	return output, err
}

func TestARM64ScalarMemoryAuditCompleteGoOptabs(t *testing.T) {
	root, err := arm64MemoryAuditGoCommand(t, "linux", "env", "GOROOT")
	if err != nil {
		t.Fatalf("actual Go GOROOT: %v\n%s", err, root)
	}
	path := filepath.Join(strings.TrimSpace(string(root)), "src", "cmd", "internal", "obj", "arm64", "asm7.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	count, err := arm64ScalarMemoryLegacyGoRows(string(source))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual Go asm7 SHA256 %x; four base mnemonics × %d memory rows, unsigned aliases expand to seven × %d", sha256.Sum256(source), count, count)
}

// This exposes the original count-only audit unchanged in scope, so its
// attribute blind spots can be tested against the same source bytes.
func arm64ScalarMemoryLegacyGoRows(source string) (int, error) {
	expected := map[int]int{20: 4, 21: 4, 30: 4, 31: 4, 22: 2, 23: 2, 98: 1, 99: 1, 64: 1, 65: 1}
	// This is an audit of the actual Go table, not a production encoder guess.
	// Go 1.20 has no separate LAUTOPOOL/LOREGPOOL rows. Its case body
	// chooses the literal pool after selecting the two ordinary long rows.
	if !strings.Contains(source, "C_LAUTOPOOL") {
		expected[30], expected[31] = 2, 2
	}
	rows := make(map[string]map[int]int)
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if end := strings.IndexByte(line, '}'); end >= 0 {
			line = line[:end+1]
		}
		if !strings.HasPrefix(line, "{AMOV") {
			continue
		}
		fields := strings.Split(strings.TrimSuffix(strings.TrimSuffix(line, ","), "}"), ",")
		name := strings.TrimPrefix(fields[0], "{")
		if name != "AMOVB" && name != "AMOVH" && name != "AMOVW" && name != "AMOVD" {
			continue
		}
		if len(fields) != 10 && len(fields) != 11 {
			return 0, fmt.Errorf("unknown actual Go optab shape: %s", line)
		}
		kind, err := strconv.Atoi(strings.TrimSpace(fields[len(fields)-5]))
		if err != nil {
			return 0, err
		}
		if _, memory := expected[kind]; !memory {
			continue
		}
		if rows[name] == nil {
			rows[name] = make(map[int]int)
		}
		rows[name][kind]++
	}
	var failures []error
	for _, name := range []string{"AMOVB", "AMOVH", "AMOVW", "AMOVD"} {
		for kind, count := range expected {
			if got := rows[name][kind]; got != count {
				failures = append(failures, fmt.Errorf("actual %s case %d has %d rows, want %d", name, kind, got, count))
			}
		}
	}
	for _, alias := range []string{"AMOVBU", "AMOVHU", "AMOVWU"} {
		if !strings.Contains(source, "oprangeset("+alias+", t)") {
			failures = append(failures, fmt.Errorf("missing actual Go unsigned MOV alias: %s", alias))
		}
	}
	count := 0
	for _, rows := range expected {
		count += rows
	}
	return count, errors.Join(failures...)
}

type arm64MemoryAuditForm struct {
	instruction string
	width       int // Known operation width only. Zero means pool/source-variant audit.
}

func arm64MemoryAuditForms() []arm64MemoryAuditForm {
	var forms []arm64MemoryAuditForm
	for index, op := range arm64MemoryScratchAuditMoves {
		width := 1 << (index / 2)
		if op == "MOVD" {
			width = 8
		}
		for _, memory := range []string{
			"-256(R0)", "-1(R0)", "0(R0)", "255(R0)",
			fmt.Sprintf("%d(R0)", 4095*width),
			"-8192(R0)", "-257(R0)", "65536(R0)",
			"65536(RSP)", "65536(ZR)", "slot+65536(FP)", "local+65536(SP)",
		} {
			operationWidth := 4
			if strings.Contains(memory, "65536") || memory == "-257(R0)" {
				operationWidth = 8
			}
			if memory == "-8192(R0)" {
				operationWidth = 0
			}
			forms = append(forms,
				arm64MemoryAuditForm{op + " " + memory + ",R1", operationWidth},
				arm64MemoryAuditForm{op + " R1," + memory, operationWidth})
		}
		for _, memory := range []string{"32768(R0)", "65537(R0)", "-4095(R0)", "-4096(R0)"} {
			forms = append(forms,
				arm64MemoryAuditForm{op + " " + memory + ",R1", 0},
				arm64MemoryAuditForm{op + " R1," + memory, 0})
		}
		for _, suffix := range []string{".P", ".W"} {
			for _, offset := range []int{-256, 0, 255} {
				memory := fmt.Sprintf("%d(R0)", offset)
				forms = append(forms,
					arm64MemoryAuditForm{op + suffix + " " + memory + ",R1", 4},
					arm64MemoryAuditForm{op + suffix + " R1," + memory, 4})
			}
		}
		indices := []string{"R2"}
		for _, extension := range []string{".UXTW", ".SXTW", ".SXTX", ""} {
			indices = append(indices, "R2"+extension+"<<0")
			if width != 1 {
				indices = append(indices, fmt.Sprintf("R2%s<<%d", extension, index/2))
			}
		}
		for _, indexed := range indices {
			memory := "(R0)(" + indexed + ")"
			forms = append(forms,
				arm64MemoryAuditForm{op + " " + memory + ",R1", 4},
				arm64MemoryAuditForm{op + " R1," + memory, 4})
		}
		for _, instruction := range []string{
			op + " (R0)(R27),R1", op + " R27,(R0)(R2)",
			op + " (R27),R1", op + " R27,(R0)",
			op + " (R0),ZR", op + " ZR,(R0)",
			op + " $0,(R0)", op + ".P $0,255(R0)",
		} {
			forms = append(forms, arm64MemoryAuditForm{instruction, 4})
		}
		forms = append(forms, arm64MemoryAuditForm{op + " $0,65536(R0)", 8})
		for _, memory := range []string{"payload+0(SB)", "payload+1(SB)"} {
			operationWidth := 8
			if width != 1 && memory == "payload+1(SB)" {
				operationWidth = 12
			}
			forms = append(forms,
				arm64MemoryAuditForm{op + " " + memory + ",R1", operationWidth},
				arm64MemoryAuditForm{op + " R1," + memory, operationWidth})
		}
		// Non-pool aliasing is accepted: data/base R27 are reread after ADD.
		for _, instruction := range []string{
			op + " 65536(R27),R1", op + " 65536(R0),R27",
			op + " R27,65536(R0)", op + " R1,65536(R27)",
		} {
			forms = append(forms, arm64MemoryAuditForm{instruction, 8})
		}
	}
	return forms
}

func arm64MemoryAuditRejectedForms() []string {
	var rejected []string
	for _, op := range arm64MemoryScratchAuditMoves {
		rejected = append(rejected, []string{
			op + " -8192(R27),R1",
			op + " R27,-8192(R0)", op + " R1,-8192(R27)",
			op + ".P 256(R0),R1", op + ".W R1,-257(R0)",
			op + ".P (R0),R0", op + ".W R0,(R0)",
			op + ".P slot+0(FP),R1", op + ".W R1,local+0(SP)",
			op + " (R0),RSP", op + " RSP,(R0)",
			op + " (R0),(R1)", op + " $1,(R0)",
			op + " (R0)(R2.UXTX),R1", op + " R1,(R0)(R2.SXTB)",
			op + " 1(R0)(R2),R1", op + " $0.0,(R0)",
			op + " (R31),R1", op + " (R0),W1",
			op + " R27,payload(SB)", op + " (F0),R1",
			op + " (R0),F1", op + ".P.W (R0),R1",
		}...)
	}
	return rejected
}

func TestARM64ScalarMemoryAuditRejectedGoFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rejected.s")
	rejected := arm64MemoryAuditRejectedForms()
	for _, instruction := range rejected {
		source := "TEXT rejected(SB),4,$0-0\n" + instruction + "\nRET\n"
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-o", filepath.Join(dir, "rejected.o"), path)
		if err == nil {
			t.Errorf("actual Go accepted expected rejected format: %s", instruction)
		}
		t.Logf("Go rejected %s: %s", instruction, strings.TrimSpace(string(output)))
	}
	t.Logf("actual Go %d rejected scalar GP memory formats", len(rejected))
}

func TestARM64ScalarMemoryAuditPoolDestinationR27VersionBoundary(t *testing.T) {
	// The current source diagnoses this alias; the old source does not.
	// Record the actual acceptance boundary without making the old accepted
	// source look like a current Go rejection or numerical execution proof.
	dir := t.TempDir()
	path := filepath.Join(dir, "pool-destination.s")
	for _, op := range arm64MemoryScratchAuditMoves {
		source := "TEXT poolDestination(SB),4,$0-0\n" + op + " -8192(R0),R27\nRET\n"
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-o", filepath.Join(dir, "pool-destination.o"), path)
		t.Logf("actual Go %s pool destination R27 accepted=%v diagnostics/listing:\n%s", op, err == nil, output)
	}
}

func TestARM64ScalarMemoryAuditWideOffsetGoEncodingBoundary(t *testing.T) {
	// Object-only audit: do not allocate or execute any huge-offset access.
	dir := t.TempDir()
	path := filepath.Join(dir, "wide.s")
	for _, offset := range []string{"2147483647", "2147483648", "4294959104", "4294967295", "4295032832", "-2147483648", "-2147483649"} {
		source := "TEXT wide(SB),4,$0-0\nMOVD " + offset + "(R0),R1\nRET\n"
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-o", filepath.Join(dir, "wide.o"), path)
		t.Logf("actual Go offset=%s accepted=%v diagnostics/listing:\n%s", offset, err == nil, output)
	}
	// Go's writeback encoder also explicitly narrows the source displacement
	// to int32 before testing its signed-nine-bit range. Keep this genuine
	// accepted/rejected source distinction separate from literal-pool offsets.
	for _, offset := range []string{"4294967296", "4294967551", "4294967552", "-4294967296", "-4294967552", "-4294967553"} {
		source := "TEXT wide(SB),4,$0-0\nMOVD.P " + offset + "(R0),R1\nRET\n"
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-o", filepath.Join(dir, "wide.o"), path)
		t.Logf("actual Go post-index offset=%s accepted=%v diagnostics/listing:\n%s", offset, err == nil, output)
	}
}

func TestARM64ScalarMemoryAuditOriginalGoObjects(t *testing.T) {
	forms := arm64MemoryAuditForms()
	var source strings.Builder
	for index, form := range forms {
		fmt.Fprintf(&source, "TEXT audit%d(SB),4,$0-0\n%s\nRET\n", index, form.instruction)
	}
	source.WriteString("GLOBL payload(SB),8,$16\nDATA payload+0(SB)/8,$0x10203040aa80feff\nDATA payload+8(SB)/8,$0xfedcba9876543210\n")
	dir := t.TempDir()
	path := filepath.Join(dir, "original.s")
	if err := os.WriteFile(path, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	functionHeader := regexp.MustCompile(`^audit([0-9]+) STEXT `)
	bytesRow := regexp.MustCompile(`^\s*0x[0-9a-f]+((?: [0-9a-f]{2}){4,16})(?:\s|$)`)
	returnRow := regexp.MustCompile(`^\s*0x([0-9a-f]+) [0-9]+ .*\)\s+RET(?:\s|$)`)
	for _, goos := range []string{"linux", "darwin"} {
		listing, err := arm64MemoryAuditGoCommand(t, goos, "tool", "asm", "-S", "-o", filepath.Join(dir, goos+".o"), path)
		if err != nil {
			t.Fatalf("actual Go %s memory object family: %v\n%s", goos, err, listing)
		}
		data := make([][]byte, len(forms))
		returnPC := make([]int, len(forms))
		current := -1
		for _, line := range strings.Split(string(listing), "\n") {
			if match := functionHeader.FindStringSubmatch(line); match != nil {
				current, err = strconv.Atoi(match[1])
				if err != nil || current >= len(forms) {
					t.Fatal("invalid original Go listing function identity")
				}
			}
			if current < 0 {
				continue
			}
			if strings.HasPrefix(line, "payload ") {
				current = -1
				continue
			}
			if match := bytesRow.FindStringSubmatch(line); match != nil {
				row, err := hex.DecodeString(strings.ReplaceAll(match[1], " ", ""))
				if err != nil {
					t.Fatal(err)
				}
				data[current] = append(data[current], row...)
			}
			if match := returnRow.FindStringSubmatch(line); match != nil {
				pc, parseErr := strconv.ParseInt(match[1], 16, 32)
				err = parseErr
				if err != nil {
					t.Fatal(err)
				}
				returnPC[current] = int(pc)
			}
		}
		for index, form := range forms {
			if len(data[index]) < 12 || returnPC[index] == 0 {
				t.Fatalf("missing actual Go %s case %d bytes/RET: %s", goos, index, form.instruction)
			}
			if form.width != 0 && returnPC[index] != form.width {
				t.Errorf("actual Go %s %s width %d want %d", goos, form.instruction, returnPC[index], form.width)
			}
			t.Logf("%s %03d %-31s RET-PC=%d bytes=%x", goos, index, form.instruction, returnPC[index], data[index])
		}
		t.Logf("actual Go %s original source SHA256 %x object listing SHA256 %x; %d accepted memory formats", goos, sha256.Sum256([]byte(source.String())), sha256.Sum256(listing), len(forms))
	}
}
