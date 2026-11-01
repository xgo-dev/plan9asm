package gotoolprofile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGeneratedHeaderSourceRuleRegistrationBindsActualSDKAndCompleteSourceSet(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filepath.Dir(goBinary))
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, stderr, err := RunBounded(ctx, t.TempDir(), os.Environ(), goBinary, "env", "GOVERSION")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual native-header rule SDK version: %v\n%s\n%s", err, output, stderr)
	}
	version := strings.TrimSpace(string(output))
	proof, err := CaptureNativeHeaderSourceRules(root, version)
	if nativeHeaderSourceHashes(version) == nil {
		if !NativeHeaderSourceDomainUnsupported(err) || proof != nil {
			t.Fatalf("unknown actual SDK acquired registered omission authority: %v", err)
		}
		return
	}
	if err != nil || RecheckNativeHeaderSourceRules(root, proof) != nil {
		t.Fatalf("actual audited native SDK rule capture/recheck: %v", err)
	}
	for _, mutate := range []func(*NativeHeaderSourceRules){
		func(copy *NativeHeaderSourceRules) { copy.Protocol = "legacy" },
		func(copy *NativeHeaderSourceRules) { copy.GoVersion = "go1.99" },
		func(copy *NativeHeaderSourceRules) {
			delete(copy.SourceSHA256, "src/cmd/compile/internal/types/size.go")
		},
		func(copy *NativeHeaderSourceRules) {
			copy.SourceSHA256["src/cmd/compile/internal/types/size.go"] = strings.Repeat("1", 64)
		},
		func(copy *NativeHeaderSourceRules) { copy.SourceSHA256["extra"] = strings.Repeat("1", 64) },
	} {
		copy := *proof
		copy.SourceSHA256 = make(map[string]string)
		for name, digest := range proof.SourceSHA256 {
			copy.SourceSHA256[name] = digest
		}
		mutate(&copy)
		if ValidateNativeHeaderSourceRules(&copy, version) == nil {
			t.Fatal("changed/deleted/extra rule registration acquired header replay authority")
		}
	}
}

func TestGeneratedHeaderSourceUnsupportedDomainCannotSwallowFailures(t *testing.T) {
	_, unsupported := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", map[string]string{"header.go": "package header\nimport \"time\"\nconst Value = time.Second\n"})
	if !NativeHeaderSourceDomainUnsupported(unsupported) || !NativeHeaderSourceDomainUnsupported(fmt.Errorf("property query: %w", unsupported)) {
		t.Fatal("unclosed imported property model lacks its precise typed domain")
	}
	for _, failure := range []error{
		fmt.Errorf("source parse failure"), errors.Join(unsupported, fmt.Errorf("source changed")),
		fmt.Errorf("native header source query has unclosed imports"),
	} {
		if NativeHeaderSourceDomainUnsupported(failure) {
			t.Fatal("an unrelated or joined failure became a conservative successful query")
		}
	}
	for _, packagePath := range []string{"sync/atomic", "internal/runtime/atomic", "simd/archsimd"} {
		definitions, err := ReplayNativeGeneratedHeader(packagePath, "linux/386", "go1.20", map[string]string{"header.go": "package header\ntype Record struct { Value uint64 }\n"})
		if definitions != nil || !NativeHeaderSourceDomainUnsupported(err) {
			t.Fatal("compiler-special layout acquired ordinary native alignment")
		}
	}
	if _, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/386", "go1.20", map[string]string{"header.go": "package header\ntype Record struct { Value [1<<31]byte }\n"}); err == nil || NativeHeaderSourceDomainUnsupported(err) {
		t.Fatal("overflow must fail, not suspend a supposedly successful source query")
	}
}

func TestGeneratedHeaderSourceReplayMatchesOriginalNativeObjects(t *testing.T) {
	source := nativeHeaderRulesSource
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRules(t, target, source)
			replayed, err := ReplayNativeGeneratedHeader("example.invalid/header", target, "go1.20", map[string]string{"header.go": source})
			if err != nil || !reflect.DeepEqual(actual, replayed) {
				t.Fatalf("complete native compiler header differs from independent original source replay:\nactual=%v\nreplayed=%v\nerror=%v", actual, replayed, err)
			}
		})
	}
}

func TestGeneratedHeaderSourceReplayRejectsUnclosedInputs(t *testing.T) {
	for _, source := range []string{
		"package header\ntype Record struct { Value [1<<62]uint64 }\n",
		"package header\ntype Record struct { Self Record }\n",
		"package header\ntype A struct { B__size byte }\ntype A_B struct {}\n",
	} {
		if definitions, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", map[string]string{"header.go": source}); err == nil || definitions != nil {
			t.Fatalf("unclosed source acquired header definitions: %q %v %v", source, definitions, err)
		}
	}
}

func TestGeneratedHeaderSourceReplayRetainsBlankZeroTailAndMultifileIdentity(t *testing.T) {
	sources := map[string]string{
		"first.go":  "package header\nconst First = 7\ntype Record struct { First uint64; _ byte; Tail [0]byte }\n",
		"second.go": "package header\nconst Second = First + 1\ntype Alias = Record\n",
	}
	wanted := map[string]string{"const_First": "7", "const_Second": "8", "Record__size": "16", "Record_First": "0", "Record_Tail": "9", "Alias__size": "16", "Alias_First": "0", "Alias_Tail": "9"}
	actual, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", sources)
	if err != nil || !reflect.DeepEqual(actual, wanted) {
		t.Fatalf("multifile/blank/zero-tail native source replay: %v %v", actual, err)
	}
	for _, mutate := range []func(map[string]string){
		func(copy map[string]string) { delete(copy, "first.go") },
		func(copy map[string]string) { copy["second.go"] = "package different\nconst Second = 8\n" },
		func(copy map[string]string) { copy["second_test.go"] = copy["second.go"]; delete(copy, "second.go") },
	} {
		copy := make(map[string]string)
		for name, text := range sources {
			copy[name] = text
		}
		mutate(copy)
		if definitions, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", copy); err == nil || definitions != nil {
			t.Fatalf("changed original source acquired a complete header: %v %v", definitions, err)
		}
	}
}
