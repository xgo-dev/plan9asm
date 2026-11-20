package plan9asm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type x86CMPXCHGActualObservation struct {
	output [16]uint64
	csr    uint32
	bytes  [96]byte
}

type x86CMPXCHGActualPacket struct {
	rows       [576]x86CMPXCHGActualObservation
	deviations int
}

// This is transport/opcode equivalence, not a pass of the mathematical ISA
// model. The separate original-Go/C strict roots still reject every deviation.
func TestX86CMPXCHGOriginalGoAndCCompleteObservationEquivalence(t *testing.T) {
	x86CMPXCHGActualEquivalence(t, x86FloatCompareExecutionTools(t))
}

func x86CMPXCHGActualEquivalence(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	declarations, assembly, names := x86CMPXCHGNumericalFixture()
	x86CMPXCHGCSRControlObject(t)
	declarations += "func resetCSR()\nfunc restoreCSR(value uint32)\n"
	assembly += x86CMPXCHGCSRControlAssembly
	goDriver := strings.Replace(x86CMPXCHGGoNumerical, "KERNEL_NAMES", names, 1)
	goDriver = x86CMPXCHGObserveGoDriver(t, goDriver)
	t.Logf("actual diagnostic declaration/assembly/Go-driver SHA256 %x/%x/%x", sha256.Sum256([]byte(declarations)), sha256.Sum256([]byte(assembly)), sha256.Sum256([]byte(goDriver)))
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), runtime.GOOS, "amd64", declarations, assembly, goDriver)
	goOutput := execution.run(t, original)
	t.Logf("actual original Go complete observer stdout:\n%s", goOutput)
	goPacket, err := x86CMPXCHGParseActualPacket(goOutput)
	if err != nil {
		t.Fatalf("actual original Go complete observation: %v", err)
	}
	cDriver := x86CMPXCHGObserveCDriver(t, x86CMPXCHGOriginalCSource())
	t.Logf("actual diagnostic independent C-driver SHA256 %x", sha256.Sum256([]byte(cDriver)))
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			cOutput := x86CMPXCHGCompileOriginalC(t, execution, cDriver, level)
			t.Logf("actual independent C complete observer stdout:\n%s", cOutput)
			cPacket, err := x86CMPXCHGParseActualPacket(cOutput)
			if err != nil {
				t.Fatalf("actual independent C opcode complete observation: %v", err)
			}
			if goPacket.deviations != cPacket.deviations {
				t.Errorf("independent mathematical deviation counts differ: Go=%d C=%d", goPacket.deviations, cPacket.deviations)
			}
			mismatches := 0
			for ordinal, goRow := range goPacket.rows {
				if goRow != cPacket.rows[ordinal] {
					if mismatches < 2 {
						t.Logf("actual observation %d differs: Go=%+v C=%+v", ordinal, goRow, cPacket.rows[ordinal])
					}
					mismatches++
				}
			}
			if mismatches != 0 {
				t.Errorf("complete actual Go/C observations differ: %d/576", mismatches)
			}
			t.Logf("actual Go/C complete observations=576 equal; mathematical/ISA deviations=%d; equivalence only, not native ISA numerical P", goPacket.deviations)
		})
	}
}

const x86CMPXCHGCSRControlAssembly = `
DATA cmpxchgCSRseed<>+0(SB)/4,$0x1f80
GLOBL cmpxchgCSRseed<>(SB),8,$4
TEXT ·resetCSR(SB),4,$0-0
LDMXCSR cmpxchgCSRseed<>(SB)
RET
TEXT ·restoreCSR(SB),4,$0-4
LDMXCSR value+0(FP)
RET
`

func x86CMPXCHGCSRControlObject(t *testing.T) {
	t.Helper()
	directory := t.TempDir()
	source, object := filepath.Join(directory, "control.s"), filepath.Join(directory, "control.o")
	if err := os.WriteFile(source, []byte(x86CMPXCHGCSRControlAssembly), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "tool", "asm", "-S",
		"-p", "ordering", "-o", object, source)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=", "GOENV=off", "GOWORK=off")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(source, object, output, err, ctx.Err(), true, "amd64"); failure != nil {
		t.Fatalf("actual CSR control object: %v\n%s", failure, output)
	}
	if !strings.Contains(string(output), "0f ae 15 00 00 00 00 c3") ||
		!strings.Contains(string(output), "0f ae 54 24 08 c3") ||
		!strings.Contains(string(output), "80 1f 00 00") || strings.Count(string(output), "LDMXCSR") != 2 {
		t.Fatalf("actual DATA source/load/restore bytes changed:\n%s", output)
	}
	bytes, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual source/Go CSR object SHA256 %x/%x; complete listing:\n%s", sha256.Sum256([]byte(x86CMPXCHGCSRControlAssembly)), sha256.Sum256(bytes), output)
}

func x86CMPXCHGObserverReplace(t *testing.T, source, from, to string) string {
	t.Helper()
	if strings.Count(source, from) != 1 {
		t.Fatalf("independent observer seam disappeared or became ambiguous: %q", from)
	}
	return strings.Replace(source, from, to, 1)
}

// The exact assembly and strict mathematical drivers are not changed. These
// diagnostic drivers only emit every actual observation and separate canary/
// CSR transport failure from the already-preserved mathematical deviation.
func x86CMPXCHGObserveGoDriver(t *testing.T, source string) string {
	t.Helper()
	source = x86CMPXCHGObserverReplace(t, source, "observations, failures := 0, 0", "observations, failures, transportFailures := 0, 0, 0")
	source = x86CMPXCHGObserverReplace(t, source, "if failures < 24 {", "if false && failures < 24 {")
	source = x86CMPXCHGObserverReplace(t, source, "if kernelFailures != 0 {", "if false && kernelFailures != 0 {")
	source = x86CMPXCHGObserverReplace(t, source, "                    before := csr()", "                    originalCSR := csr()\n                    resetCSR()\n                    before := csr()")
	source = x86CMPXCHGObserverReplace(t, source, "                    after := csr()", "                    after := csr()\n                    restoreCSR(originalCSR)\n                    restoredCSR := csr()")
	source = x86CMPXCHGObserverReplace(t, source, "                    observations++", `                    transportBad := out[6]>>32 != canary>>32 || csr != before || after != before || restoredCSR != originalCSR || raw != expectedRaw
                    for i := 7; i < len(out); i++ { transportBad = transportBad || out[i] != canary }
                    if transportBad { transportFailures++ }
                    fmt.Printf("OBS %d %d %d %d", index, observations%48/4, map[bool]int{false:0, true:1}[equal], observations%2)
                    for i, value := range out {
                        if i == 4 { value &= 0x8d5 }
                        fmt.Printf(" %x", value)
                    }
                    fmt.Printf(" %x %x %x %x %x\n", before, after, originalCSR, restoredCSR, raw)
                    observations++`)
	source = x86CMPXCHGObserverReplace(t, source,
		`    fmt.Printf("original CMPXCHG numerical observations %d failures %d\n", observations, failures)
    if failures != 0 { os.Exit(1) }`,
		`    fmt.Printf("END %d %d %d\n", observations, failures, transportFailures)
    if transportFailures != 0 { os.Exit(1) }`)
	return source
}

func x86CMPXCHGObserveCDriver(t *testing.T, source string) string {
	t.Helper()
	source = x86CMPXCHGObserverReplace(t, source, "unsigned observations = 0, failures = 0;", "unsigned observations = 0, failures = 0, transport_failures = 0;")
	source = x86CMPXCHGObserverReplace(t, source, "if (kernel_failures <= 2) {", "if (0 && kernel_failures <= 2) {")
	source = x86CMPXCHGObserverReplace(t, source, "if (kernel_failures) {", "if (0 && kernel_failures) {")
	source = x86CMPXCHGObserverReplace(t, source, `                    __asm__ volatile("stmxcsr %0" : "=m"(before));`,
		`                    unsigned original_csr, controlled_csr = 0x1f80;
                    __asm__ volatile("stmxcsr %0" : "=m"(original_csr));
                    __asm__ volatile("ldmxcsr %0" : : "m"(controlled_csr));
                    __asm__ volatile("stmxcsr %0" : "=m"(before));`)
	source = x86CMPXCHGObserverReplace(t, source, `                    __asm__ volatile("stmxcsr %0" : "=m"(after));`,
		`                    __asm__ volatile("stmxcsr %0" : "=m"(after));
                    __asm__ volatile("ldmxcsr %0" : : "m"(original_csr));
                    unsigned restored_csr;
                    __asm__ volatile("stmxcsr %0" : "=m"(restored_csr));`)
	source = x86CMPXCHGObserverReplace(t, source, "                    observations++;", `                    int transport_bad = (out[6]>>32) != (canary>>32) ||
                        (uint32_t)out[6] != before || after != before || restored_csr != original_csr || memcmp(raw, expected, sizeof(raw));
                    for (unsigned i = 7; i < 16; i++) transport_bad |= out[i] != canary;
                    transport_failures += transport_bad != 0;
                    printf("OBS %u %u %u %u", index, edge, equal, seed);
                    for (unsigned i = 0; i < 16; i++) {
                        uint64_t value = i == 4 ? out[i]&0x8d5 : out[i];
                        printf(" %llx", (unsigned long long)value);
                    }
                    printf(" %x %x %x %x ", before, after, original_csr, restored_csr);
                    for (unsigned i = 0; i < sizeof(raw); i++) printf("%02x", raw[i]);
                    printf("\n");
                    observations++;`)
	source = x86CMPXCHGObserverReplace(t, source,
		`    printf("actual C opcode CMPXCHG numerical observations %u failures %u\n", observations, failures);
    return failures ? 1 : 0;`,
		`    printf("END %u %u %u\n", observations, failures, transport_failures);
    return transport_failures ? 1 : 0;`)
	return source
}

func x86CMPXCHGParseActualPacket(output []byte) (x86CMPXCHGActualPacket, error) {
	var packet x86CMPXCHGActualPacket
	lines := strings.Split(string(output), "\n")
	if len(output) > 1<<20 || len(lines) != 578 || lines[577] != "" {
		return packet, fmt.Errorf("incomplete, extra or over-bound actual observation output")
	}
	// Windows C stdio emits CRLF. Accept that text transport without
	// trimming field whitespace or discarding malformed embedded CR bytes.
	for index := range lines {
		lines[index] = strings.TrimSuffix(lines[index], "\r")
	}
	parse := func(text string, base, bits int) (uint64, error) {
		value, err := strconv.ParseUint(text, base, bits)
		if err != nil || strconv.FormatUint(value, base) != text {
			return 0, fmt.Errorf("noncanonical actual value %q", text)
		}
		return value, nil
	}
	for ordinal, line := range lines[:576] {
		fields := strings.Split(line, " ")
		if len(fields) != 26 || fields[0] != "OBS" {
			return packet, fmt.Errorf("actual observation %d has incomplete/unknown fields", ordinal)
		}
		want := []int{ordinal / 48, ordinal % 48 / 4, ordinal % 4 / 2, ordinal % 2}
		for index, value := range want {
			if fields[index+1] != strconv.Itoa(value) {
				return packet, fmt.Errorf("duplicate, missing or reordered actual observation %d", ordinal)
			}
		}
		row := &packet.rows[ordinal]
		for index := range row.output {
			value, err := parse(fields[index+5], 16, 64)
			if err != nil {
				return packet, err
			}
			row.output[index] = value
		}
		before, err := parse(fields[21], 16, 32)
		if err != nil {
			return packet, err
		}
		after, err := parse(fields[22], 16, 32)
		if err != nil || before != 0x1f80 || before != after || uint32(row.output[6]) != uint32(before) {
			return packet, fmt.Errorf("actual MXCSR transport changed at observation %d", ordinal)
		}
		row.csr = uint32(before)
		// Ambient input differs between independent Go/C processes. Preserve
		// both complete values in the raw trace and require exact restoration;
		// opcode equality concerns the identical controlled MXCSR input.
		originalCSR, err := parse(fields[23], 16, 32)
		if err != nil {
			return packet, err
		}
		restoredCSR, err := parse(fields[24], 16, 32)
		if err != nil || originalCSR != restoredCSR {
			return packet, fmt.Errorf("actual ambient MXCSR restoration failed at observation %d", ordinal)
		}
		if row.output[4]&^uint64(0x8d5) != 0 || row.output[5] != row.output[4]&0xd5|2 || row.output[6]>>32 != 0xa7a7a7a7 {
			return packet, fmt.Errorf("actual status/LAHF or output canary was incomplete at observation %d", ordinal)
		}
		for index := 7; index < 16; index++ {
			if row.output[index] != 0xa7a7a7a7a7a7a7a7 {
				return packet, fmt.Errorf("actual output canary changed at observation %d", ordinal)
			}
		}
		if len(fields[25]) != 192 || strings.ToLower(fields[25]) != fields[25] {
			return packet, fmt.Errorf("actual complete byte observation missing at %d", ordinal)
		}
		bytes, err := hex.DecodeString(fields[25])
		if err != nil {
			return packet, err
		}
		copy(row.bytes[:], bytes)
		family := ordinal / 96
		start := 17
		if family == 5 {
			start = 16
		}
		width := []int{1, 2, 4, 8, 8, 16}[family]
		for index, value := range row.bytes {
			if (index < start || index >= start+width) && value != 0xa7 {
				return packet, fmt.Errorf("actual input canary changed at observation %d", ordinal)
			}
		}
	}
	footer := strings.Split(lines[576], " ")
	if len(footer) != 4 || footer[0] != "END" || footer[1] != "576" || footer[3] != "0" {
		return packet, fmt.Errorf("actual observer has missing/unknown/nonzero transport terminal")
	}
	deviations, err := parse(footer[2], 10, 16)
	if err != nil || deviations > 576 {
		return packet, fmt.Errorf("actual observer has invalid mathematical deviation count")
	}
	packet.deviations = int(deviations)
	return packet, nil
}

func TestX86CMPXCHGActualObservationPacketRejectsIncompleteTransport(t *testing.T) {
	// Synthetic output-protocol tripwires, not actual opcode execution evidence.
	var source strings.Builder
	for ordinal := 0; ordinal < 576; ordinal++ {
		fmt.Fprintf(&source, "OBS %d %d %d %d", ordinal/48, ordinal%48/4, ordinal%4/2, ordinal%2)
		for index := 0; index < 16; index++ {
			value := uint64(0xa7a7a7a7a7a7a7a7)
			switch index {
			case 4:
				value = 64
			case 5:
				value = 66
			case 6:
				value = 0xa7a7a7a700001f80
			}
			fmt.Fprintf(&source, " %x", value)
		}
		fmt.Fprintf(&source, " 1f80 1f80 1f80 1f80 %s\n", strings.Repeat("a7", 96))
	}
	source.WriteString("END 576 0 0\n")
	valid := source.String()
	packet, err := x86CMPXCHGParseActualPacket([]byte(valid))
	if err != nil || packet.deviations != 0 {
		t.Fatalf("complete synthetic protocol control: %v", err)
	}
	for name, output := range map[string]string{
		"CRLF":  strings.ReplaceAll(valid, "\n", "\r\n"),
		"mixed": strings.Replace(valid, "\n", "\r\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			actual, err := x86CMPXCHGParseActualPacket([]byte(output))
			if err != nil || actual != packet {
				t.Fatalf("text-mode line endings changed the complete observation: %v", err)
			}
		})
	}
	for name, mutation := range map[string]string{
		"bare-CR":         strings.Replace(valid, "\n", "\r", 1),
		"double-CR":       strings.Replace(valid, "\n", "\r\r\n", 1),
		"embedded-CR":     strings.Replace(valid, "OBS 0", "OBS\r 0", 1),
		"missing":         strings.TrimSuffix(valid, "END 576 0 0\n"),
		"unknown":         valid + "unknown\n",
		"duplicate":       strings.Replace(valid, "OBS 0 0 0 1", "OBS 0 0 0 0", 1),
		"truncated":       strings.Replace(valid, strings.Repeat("a7", 96), "a7", 1),
		"canary":          strings.Replace(valid, strings.Repeat("a7", 96), "a6"+strings.Repeat("a7", 95), 1),
		"changed-CSR":     strings.Replace(valid, "1f80 1f80", "1f80 1f81", 1),
		"uncontrolled":    strings.Replace(valid, "1f80 1f80", "1fa0 1fa0", 1),
		"unrestored":      strings.Replace(valid, "1f80 1f80 1f80 1f80", "1f80 1f80 1fa0 1f80", 1),
		"unknown-LAHF":    strings.Replace(valid, " 40 42 ", " 40 43 ", 1),
		"transport-exit":  strings.Replace(valid, "END 576 0 0", "END 576 0 1", 1),
		"wrong-count":     strings.Replace(valid, "END 576", "END 575", 1),
		"overflow":        strings.Replace(valid, "END 576 0 0", "END 576 65536 0", 1),
		"diagnostic-only": "END 576 240 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := x86CMPXCHGParseActualPacket([]byte(mutation)); err == nil {
				t.Fatal("incomplete/unknown actual transport got equivalence credit")
			}
		})
	}
	mutated := packet
	mutated.rows[575].output[0] ^= 1
	if reflect.DeepEqual(packet, mutated) {
		t.Fatal("full observation comparison did not retain a late register byte")
	}
}
