//go:build go1.27

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationMetadataPrettyJSONLayoutAgreesWithFreshActualSource(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(producer.Metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	reported, err := gotoolprofile.DecodeInstrumentationMetadata(bytes.NewReader(data), input, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(proof *gotoolprofile.InstrumentationMetadataProof) gotoolprofile.InstrumentationMetadataProof {
		copy := *proof
		copy.Headers = append([]gotoolprofile.InstrumentationGeneratedHeader(nil), proof.Headers...)
		for index := range copy.Headers {
			copy.Headers[index].Header.HeaderSHA256, copy.Headers[index].Header.ObjectSHA256 = "", ""
		}
		copy.Declarations = append([]gotoolprofile.InstrumentationDeclarationProof(nil), proof.Declarations...)
		for index := range copy.Declarations {
			var compact bytes.Buffer
			if err := json.Compact(&compact, copy.Declarations[index].Layout); err != nil {
				t.Fatal(err)
			}
			copy.Declarations[index].Layout = compact.Bytes()
		}
		return copy
	}
	if !reflect.DeepEqual(normalize(reported), normalize(actual.Metadata)) {
		t.Fatal("actual metadata differs in more than report layout whitespace and the separately bound native header object hashes")
	}
	if bytes.Equal(reported.Declarations[0].Layout, actual.Metadata.Declarations[0].Layout) {
		t.Fatal("fixture did not reproduce pretty-printed RawMessage versus actual compact layout")
	}
	t.Log("exact difference: Declaration.Layout JSON whitespace; all other mode/source/selection/export/header/type/ABI fields unchanged")
	if err := gotoolprofile.ValidateInstrumentationMetadataAgreement(input, reported, actual.Metadata, ".", nil); err != nil {
		t.Fatalf("strictly decoded pretty layout rejected independently recaptured actual source: %v", err)
	}
}

func TestInstrumentationCLIActualMetadataAndObjectInvocation(t *testing.T) {
	for _, config := range []struct {
		target string
		mode   gotoolprofile.InstrumentationMode
		cgo    string
	}{
		{"darwin/arm64", gotoolprofile.InstrumentationRace, "0"},
		{"darwin/arm64", gotoolprofile.InstrumentationRace, "1"},
		{"linux/arm64", gotoolprofile.InstrumentationMSan, "1"},
		{"linux/arm64", gotoolprofile.InstrumentationASan, "1"},
	} {
		t.Run(config.target+"/"+string(config.mode)+"/cgo"+config.cgo, func(t *testing.T) {
			testInstrumentationCLIActualInvocation(t, config.target, config.mode, config.cgo)
		})
	}
}

func testInstrumentationCLIActualInvocation(t *testing.T, target string, mode gotoolprofile.InstrumentationMode, cgo string) {
	t.Helper()
	input, ctx := instrumentationMetadataFixture(t, target, mode, cgo)
	output := instrumentationObjectFixtureOutput(t, input)
	profile := filepath.Join(output, "input.json")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, data, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(output, gotoolchain.HostExecutable("plan9asmll"))
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, ".", os.Environ(), goBinary, "build", "-p=1", "-o", binary, ".")
	if err != nil {
		t.Fatalf("build actual current CLI: %v\n%s\n%s", err, stdout, stderr)
	}
	goos, goarch, _ := strings.Cut(target, "/")
	args := []string{
		"-instrumentation-profile=" + profile,
		"-instrumentation-package-dir=.",
		"-goos=" + goos, "-goarch=" + goarch,
		"-patterns=" + input.Plan.PackagePath,
		"-module-path=" + input.Original.Module,
		"-asm-files=" + strings.Join(input.Plan.SFiles, ","),
		"-strict-load=true", "-keep-going=false",
		"-out=" + filepath.Join(output, "metadata"),
		"-report=" + filepath.Join(output, "metadata.json"),
		"-metadata-only",
	}
	stdout, stderr, err = gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, os.Environ(), binary, args...)
	if err != nil {
		t.Fatalf("actual mode metadata CLI: %v\n%s\n%s", err, stdout, stderr)
	}
	file, err := os.Open(filepath.Join(output, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	producer, decodeErr := gotoolprofile.DecodeInstrumentationInvocation(file, input, gotoolprofile.InstrumentationMetadataQuery, nil, nil)
	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil {
		t.Fatalf("independent metadata reader: %v (close: %v)", decodeErr, closeErr)
	}
	args = args[:len(args)-3]
	args = append(args,
		"-out="+filepath.Join(output, "objects"),
		"-report="+filepath.Join(output, "objects.json"),
		"-instrumentation-metadata="+filepath.Join(output, "metadata.json"),
		"-compile", "-keep-obj", "-llc-opt-level=0")
	stdout, stderr, err = gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, os.Environ(), binary, args...)
	if err != nil {
		t.Fatalf("actual mode CPP/LLVM CLI: %v\n%s\n%s", err, stdout, stderr)
	}
	file, err = os.Open(filepath.Join(output, "objects.json"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	version, stderr, err := gotoolprofile.RunBounded(ctx, ".", os.Environ(), config.LLC, "--version")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("independent actual LLVM22 version: %v; %s", err, stderr)
	}
	toolSHA, err := gotoolprofile.FileSHA256(config.LLC)
	if err != nil {
		t.Fatal(err)
	}
	tools := &gotoolprofile.InstrumentationLLVMTool{Version: string(version), SHA256: toolSHA, Triple: targetTriple(goos, goarch)}
	encoded, err := os.ReadFile(filepath.Join(output, "objects.json"))
	if err != nil {
		t.Fatal(err)
	}
	var serialized gotoolprofile.InstrumentationInvocationProof
	if err := json.Unmarshal(encoded, &serialized); err != nil {
		t.Fatal(err)
	}
	for _, item := range serialized.Consumption.Files {
		for _, declaration := range item.Declarations {
			for _, expected := range serialized.Consumption.Metadata.Declarations {
				if expected.Symbol != declaration.Symbol {
					continue
				}
				compact := func(value gotoolprofile.InstrumentationDeclarationProof) gotoolprofile.InstrumentationDeclarationProof {
					var layout bytes.Buffer
					if err := json.Compact(&layout, value.Layout); err != nil {
						t.Fatal(err)
					}
					value.Layout = layout.Bytes()
					return value
				}
				if !reflect.DeepEqual(compact(expected), compact(declaration)) {
					t.Fatal("serialized LLVM declaration differs from actual source metadata in more than layout whitespace")
				}
				if bytes.Equal(expected.Layout, declaration.Layout) {
					t.Fatal("fixture lacks nested declaration RawMessage indentation difference")
				}
				t.Log("exact nested declaration difference: Layout JSON whitespace; symbol/file/AST/type/full ABI tokens unchanged")
			}
		}
	}
	invocation, decodeErr := gotoolprofile.DecodeInstrumentationInvocation(file, input, gotoolprofile.InstrumentationObjectCompile, producer.Metadata, tools)
	closeErr = file.Close()
	if decodeErr != nil || closeErr != nil {
		t.Fatalf("independent actual object reader: %v (close: %v)", decodeErr, closeErr)
	}
	proof := invocation.Consumption
	if proof.Status != "llvm_objects_only" || len(proof.Files) != 1 || producer.ObjectCount != 0 || invocation.ObjectCount != 1 {
		t.Fatal("CLI omitted its actual original selected assembly or claimed runtime")
	}
	for _, indent := range []string{"    ", "\t"} {
		var reformatted bytes.Buffer
		if err := json.Indent(&reformatted, encoded, "", indent); err != nil {
			t.Fatal(err)
		}
		if _, err := gotoolprofile.DecodeInstrumentationInvocation(&reformatted, input, gotoolprofile.InstrumentationObjectCompile, producer.Metadata, tools); err != nil {
			t.Fatalf("valid whole-report formatting rejected independent source/ABI identity: %v", err)
		}
		queryJSON, err := json.MarshalIndent(producer, "", indent)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gotoolprofile.DecodeInstrumentationInvocation(bytes.NewReader(queryJSON), input, gotoolprofile.InstrumentationMetadataQuery, producer.Metadata, nil); err != nil {
			t.Fatalf("valid query formatting rejected independent source/ABI identity: %v", err)
		}
	}
	for _, item := range proof.Files {
		physical := filepath.Join(output, "objects", item.Output.Part)
		irSHA, err := gotoolprofile.FileSHA256(physical)
		if err != nil || irSHA != item.Output.IR {
			t.Fatalf("actual CLI IR changed or is absent: %v", err)
		}
		objectSHA, err := gotoolprofile.FileSHA256(strings.TrimSuffix(physical, ".ll") + ".o")
		if err != nil || objectSHA != item.Output.Object {
			t.Fatalf("actual CLI LLVM object changed or is absent: %v", err)
		}
	}
	testInstrumentationInvocationMutations(t, input, producer.Metadata, tools, encoded)
	for name, change := range map[string]func([]string) []string{
		"ordinary and mode paired": func(args []string) []string { return append(args, "-feature-profile="+profile) },
		"ordinary query paired":    func(args []string) []string { return append(args, "-signature-source-query") },
		"mode context deleted":     func(args []string) []string { return args[1:] },
		"both context and metadata deleted": func(args []string) []string {
			var result []string
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-instrumentation-profile=") && !strings.HasPrefix(arg, "-instrumentation-metadata=") {
					result = append(result, arg)
				}
			}
			return result
		},
		"producer metadata deleted": func(args []string) []string {
			var result []string
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-instrumentation-metadata=") {
					result = append(result, arg)
				}
			}
			return result
		},
		"changed actual target": func(args []string) []string { return append(args, "-goos=windows") },
		"changed package path":  func(args []string) []string { return append(args, "-patterns=example.invalid/foreign") },
		"unknown file":          func(args []string) []string { return append(args, "-asm-files=unknown_arm64.s") },
		"invented mode tags":    func(args []string) []string { return append(args, "-tags=race") },
		"borrow baseline CGO":   func(args []string) []string { return append(args, "-tags=cgo") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := change(append([]string(nil), args...))
			// Never permit a failed child to leave the valid previous report
			// or object directory available as apparent negative-run evidence.
			changed = append(changed, "-report="+filepath.Join(t.TempDir(), "rejected.json"), "-out="+t.TempDir())
			stdout, stderr, err := gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, os.Environ(), binary, changed...)
			if err == nil {
				t.Fatalf("mode CLI accepted changed/deleted/ordinary scope: %s\n%s", stdout, stderr)
			}
		})
	}
}

func testInstrumentationInvocationMutations(t *testing.T, input *gotoolprofile.InstrumentationConsumerInput, producer *gotoolprofile.InstrumentationMetadataProof, tools *gotoolprofile.InstrumentationLLVMTool, original []byte) {
	t.Helper()
	for name, change := range map[string]func(*gotoolprofile.InstrumentationInvocationProof){
		"ordinary wrapper": func(p *gotoolprofile.InstrumentationInvocationProof) { p.Protocol = gotoolprofile.ConsumerProtocol },
		"missing wrapper":  func(p *gotoolprofile.InstrumentationInvocationProof) { p.Protocol = "" },
		"borrow query": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.Phase = gotoolprofile.InstrumentationMetadataQuery
		},
		"paired mode deletion": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.ModeProfileID = ""
			p.Consumption.ModeProfileID = ""
		},
		"paired metadata deletion": func(p *gotoolprofile.InstrumentationInvocationProof) { p.Metadata = nil; p.Consumption.Metadata = nil },
		"paired source deletion": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.InputSHA256 = ""
			p.Consumption.InputSHA256 = ""
		},
		"missing complete files": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.AsmFiles = nil
			p.Consumption.Files = nil
			p.ObjectCount = 0
		},
		"changed exact package":  func(p *gotoolprofile.InstrumentationInvocationProof) { p.PackagePath += "/foreign" },
		"changed exact target":   func(p *gotoolprofile.InstrumentationInvocationProof) { p.Target = "windows/arm64" },
		"invented mode tag":      func(p *gotoolprofile.InstrumentationInvocationProof) { p.CustomTags = []string{"race"} },
		"erased compiler":        func(p *gotoolprofile.InstrumentationInvocationProof) { p.LLVM = nil; p.Consumption.LLVM = nil },
		"missing physical count": func(p *gotoolprofile.InstrumentationInvocationProof) { p.ObjectCount = 0 },
		"paired layout deletion": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.Metadata.Declarations[0].Layout = nil
			p.Consumption.Metadata.Declarations[0].Layout = nil
			p.Consumption.Files[0].Declarations[0].Layout = nil
		},
		"nested layout unknown": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.Consumption.Files[0].Declarations[0].Layout = json.RawMessage(`{"unexpected":true}`)
		},
		"nested layout trailing": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.Consumption.Files[0].Declarations[0].Layout = append(p.Consumption.Files[0].Declarations[0].Layout, []byte(` {}`)...)
		},
		"nested layout raw null": func(p *gotoolprofile.InstrumentationInvocationProof) {
			p.Consumption.Files[0].Declarations[0].Layout = json.RawMessage(`null`)
		},
		"paired multi-field layout": func(p *gotoolprofile.InstrumentationInvocationProof) {
			var layout plan9asm.FuncSig
			if err := json.Unmarshal(p.Metadata.Declarations[0].Layout, &layout); err != nil {
				t.Fatal(err)
			}
			layout.Ret, layout.Frame.Results[0].Type, layout.Frame.Results[0].Offset = plan9asm.I8, plan9asm.I8, 8
			encoded, err := json.Marshal(layout)
			if err != nil {
				t.Fatal(err)
			}
			p.Metadata.Declarations[0].Layout = encoded
			p.Consumption.Metadata.Declarations[0].Layout = encoded
			p.Consumption.Files[0].Declarations[0].Layout = encoded
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.InstrumentationInvocationProof
			if err := json.Unmarshal(original, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			independent := producer
			if name == "paired multi-field layout" {
				independent = changed.Metadata
				changed.Consumption.MetadataSHA256 = gotoolprofile.InstrumentationMetadataSHA256(independent)
			}
			if err := gotoolprofile.ValidateInstrumentationInvocation(input, gotoolprofile.InstrumentationObjectCompile, independent, tools, &changed); err == nil {
				t.Fatal("mode invocation reader accepted an erased/relabelled/paired-forged proof")
			}
		})
	}
	for _, data := range [][]byte{
		append(append([]byte(nil), original...), []byte(` {}`)...),
		append([]byte(`{"unexpected":true,`), bytes.TrimSpace(original)[1:]...),
	} {
		if _, err := gotoolprofile.DecodeInstrumentationInvocation(bytes.NewReader(data), input, gotoolprofile.InstrumentationObjectCompile, producer, tools); err == nil {
			t.Fatal("invocation reader accepted unknown or trailing JSON")
		}
	}
}
