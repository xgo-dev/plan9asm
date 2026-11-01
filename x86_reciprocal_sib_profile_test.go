package plan9asm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The selected encoder already observes the complete SDK producer schema,
// register enum and actual tools. This missing scoped consumer must bind the
// original source/file as well, without weakening the ordinary diagnostic API.
type x86ReciprocalSIBDiagnosticConsumer interface {
	acceptsReciprocalSIBDiagnostic(string, string, []byte, []byte, string, string) bool
}

func x86ReciprocalSIBSource(op string) []byte {
	return []byte("TEXT f(SB),4,$0-0\n" + op + " 16(R9)(CX*2),X1,X2\nRET\n")
}

func x86ReciprocalSIBExpectedDiagnostic(t *testing.T, schema x86SegmentMOVEncoderSchema) string {
	t.Helper()
	index, hasIndex := schema.registers["REG_CX"]
	base, hasBase := schema.registers["REG_R9"]
	if !hasIndex || !hasBase || index == base {
		t.Fatal("actual selected register enum lost its distinct CX/R9 identities")
	}
	if schema.namedDiagnostic {
		return "asm: asmidx: bad address 2/CX/R9\nasm: assembly failed\n"
	}
	return fmt.Sprintf("asm: asmidx: bad address 2/%d/%d\nasm: assembly failed\n", index, base)
}

func TestX86ReciprocalSIBDiagnosticBindsActualSelectedProducer(t *testing.T) {
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	consumer, present := any(producer.schema).(x86ReciprocalSIBDiagnosticConsumer)
	if !present {
		t.Fatal("missing selected-SDK reciprocal SIB diagnostic consumer")
	}
	for _, op := range []string{"VRCPSS", "VRSQRTSS"} {
		t.Run(op, func(t *testing.T) {
			source := x86ReciprocalSIBSource(op)
			filename := filepath.Join(t.TempDir(), "bound.s")
			if err := os.WriteFile(filename, source, 0600); err != nil {
				t.Fatal(err)
			}
			expected := x86ReciprocalSIBExpectedDiagnostic(t, producer.schema)
			if !consumer.acceptsReciprocalSIBDiagnostic(filename, filename, source, source, "386", expected) {
				t.Fatal("exact source/selected-register diagnostic failed")
			}
			for _, mutation := range []string{"filename", "source", "expected-source", "opcode", "mode",
				"scale", "arbitrary-registers", "swapped-registers", "writer", "missing", "footer-only", "duplicate", "extra"} {
				t.Run(mutation, func(t *testing.T) {
					actualFile, actual, want, arch, diagnostic := filename, source, source, "386", expected
					switch mutation {
					case "filename":
						actualFile += ".foreign"
					case "source":
						actual = bytes.Replace(source, []byte("16(R9)"), []byte("17(R9)"), 1)
					case "expected-source":
						want = bytes.Replace(source, []byte(op), []byte("VADDSS"), 1)
					case "opcode":
						actual = bytes.Replace(source, []byte(op), []byte("VADDSS"), 1)
						want = actual
					case "mode":
						arch = "amd64"
					case "scale":
						diagnostic = strings.Replace(expected, "address 2/", "address 3/", 1)
					case "arbitrary-registers":
						diagnostic = "asm: asmidx: bad address 2/12345/67890\nasm: assembly failed\n"
					case "swapped-registers":
						diagnostic = fmt.Sprintf("asm: asmidx: bad address 2/%d/%d\nasm: assembly failed\n",
							producer.schema.registers["REG_R9"], producer.schema.registers["REG_CX"])
					case "writer":
						diagnostic = fmt.Sprintf("asm: asmidx: bad address 2/%d/%d\nasm: assembly failed\n",
							producer.schema.registers["REG_CX"], producer.schema.registers["REG_R9"])
						if !producer.schema.namedDiagnostic {
							diagnostic = "asm: asmidx: bad address 2/CX/R9\nasm: assembly failed\n"
						}
					case "missing":
						diagnostic = ""
					case "footer-only":
						diagnostic = "asm: assembly failed\n"
					case "duplicate":
						diagnostic += expected
					case "extra":
						diagnostic += "unobserved extra output\n"
					}
					if consumer.acceptsReciprocalSIBDiagnostic(actualFile, filename, actual, want, arch, diagnostic) {
						t.Fatal("foreign source/producer/tuple acquired a source rejection", mutation)
					}
				})
			}
		})
	}
	changed := make(map[string][]byte)
	for name, data := range producer.sources {
		changed[name] = append([]byte(nil), data...)
	}
	name := x86SegmentMOVProducerSources[0]
	changed[name] = bytes.Replace(changed[name], []byte("asmidx: bad address"), []byte("asmidx: foreign address"), 1)
	if bytes.Equal(changed[name], producer.sources[name]) {
		t.Fatal("foreign SDK producer control did not mutate its actual source")
	}
	if _, err := x86SegmentMOVInspectProducer(changed); err == nil {
		t.Fatal("foreign SDK diagnostic implementation acquired the selected producer profile")
	}
}

func TestX86ReciprocalSIBOriginalGoRejectionAndOwnedExit(t *testing.T) {
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	driver, _ := x86LEAActualSDKDriver(t)
	for _, op := range []string{"VRCPSS", "VRSQRTSS"} {
		t.Run(op, func(t *testing.T) {
			source := x86ReciprocalSIBSource(op)
			dir := t.TempDir()
			filename, object := filepath.Join(dir, "bound.s"), filepath.Join(dir, "bound.o")
			if err := os.WriteFile(filename, source, 0600); err != nil {
				t.Fatal(err)
			}
			stage, cancelStage := runtimeOracleStageContext(t)
			defer cancelStage()
			ctx, cancel := context.WithTimeout(stage, time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, driver, "tool", "asm", "-p", "example.com/forms", "-o", object, filename)
			command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386")
			output, processErr := runtimeOracleCombinedOutput(ctx, command)
			expected := x86ReciprocalSIBExpectedDiagnostic(t, producer.schema)
			if err := x86UnnamedAsmidxOutcome(output, processErr, ctx.Err(), expected); err != nil {
				t.Fatal("actual selected Go/complete source/exit prior", err)
			}
			for _, failure := range []error{nil, errors.New("launch failure"), errors.Join(processErr, errors.New("cleanup failure"))} {
				if x86UnnamedAsmidxOutcome(output, failure, nil, expected) == nil {
					t.Fatal("non-owned process outcome became a Go source rejection")
				}
			}
			if x86UnnamedAsmidxOutcome(output, processErr, context.DeadlineExceeded, expected) == nil {
				t.Fatal("expired command became a Go source rejection")
			}
			if current, err := os.ReadFile(filename); err != nil || !bytes.Equal(current, source) {
				t.Fatal("actual command lost its original source identity", err)
			}
			consumer, present := any(producer.schema).(x86ReciprocalSIBDiagnosticConsumer)
			if !present || !consumer.acceptsReciprocalSIBDiagnostic(filename, filename, source, source, "386", string(output)) {
				t.Fatal("real Go refusal has no exact selected-source consumer")
			}
		})
	}
}

func x86ReciprocalSIBOriginalOwnerWiring(source []byte) error {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "owner.go", source, 0)
	if err != nil {
		return err
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestX86ScalarReciprocalMode32FrontendAddressHasNoPhysicalPermission" {
			continue
		}
		var output bytes.Buffer
		if err := format.Node(&output, set, function.Body); err != nil {
			return err
		}
		text := output.String()
		for _, required := range []string{
			`[]string{"VRCPSS", "VRSQRTSS"}`,
			`[]string{"R8", "R9", "R10", "R11", "R13", "R14", "R15"}`,
			`goAssemblerOracleOutput(t, "386", source, "", true)`,
			`[]string{"16(AX)(R9*2)", "16(R9)(CX*2)", "16(R12)"}`,
			`x86ReciprocalSIBOriginalGoRejection(t, "386", "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n")`,
			`unbound diagnostic, no source-rejection claim`,
			`not the non-SIB frontend compatibility class`,
		} {
			if strings.Count(text, required) != 1 {
				return fmt.Errorf("missing unique original reciprocal source/observation scope: %s", required)
			}
		}
		return nil
	}
	return fmt.Errorf("missing original complete reciprocal mode32 owner")
}

func TestX86ReciprocalSIBOriginalOwnerUsesSelectedDiagnostic(t *testing.T) {
	source, err := os.ReadFile("x86_scalar_reciprocal_mode32_test.go")
	if err != nil {
		t.Fatal(err)
	}
	old := `goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n", "", false)`
	bound := `x86ReciprocalSIBOriginalGoRejection(t, "386", "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n")`
	unwired := string(source)
	oldCount, boundCount := strings.Count(unwired, old), strings.Count(unwired, bound)
	if oldCount+boundCount != 1 {
		t.Fatal("original owner has an unknown, duplicated or missing diagnostic route")
	}
	if boundCount == 1 {
		unwired = strings.Replace(unwired, bound, old, 1)
	}
	if strings.Count(unwired, old) != 1 || strings.Count(unwired, bound) != 0 {
		t.Fatal("independent unwired baseline lost its exact original source route")
	}
	complete := strings.Replace(unwired, old, bound, 1)
	if complete == unwired || x86ReciprocalSIBOriginalOwnerWiring([]byte(complete)) != nil {
		t.Fatal("independent complete source/diagnostic routing control")
	}
	for _, change := range [][2]string{
		{bound, old}, {bound, `x86ReciprocalSIBOriginalGoRejection(t, "amd64", "foreign")`},
		{`goAssemblerOracleOutput(t, "386", source, "", true)`, "NOP()"},
		{`"R8", "R9", "R10", "R11", "R13", "R14", "R15"`, `"R8", "R9"`},
		{`"16(AX)(R9*2)", "16(R9)(CX*2)", "16(R12)"`, `"16(R9)(CX*2)"`},
		{`unbound diagnostic, no source-rejection claim`, `accepted rejection`},
	} {
		changed := strings.Replace(complete, change[0], change[1], 1)
		if changed == complete || x86ReciprocalSIBOriginalOwnerWiring([]byte(changed)) == nil {
			t.Fatal("reduced or unbound original fixture passed routing policy", change)
		}
	}
	if err := x86ReciprocalSIBOriginalOwnerWiring(source); err != nil {
		t.Fatal("actual owner still uses an unobserved generic positionless diagnostic", err)
	}
}
