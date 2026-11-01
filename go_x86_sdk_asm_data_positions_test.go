//go:build go1.27

package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// Explicit -std flags here exercise the offline decoder only. This owned
// first-party fixture is never passed off as a live authenticated SDK source.
func TestGoX86SDKASMDataCPPPositionFirstParty(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			sdkASMDataPositionFirstParty(t, arch, nil, nil)
		})
	}
}

func sdkASMDataPositionFirstParty(t *testing.T, arch string, replacement, headerSource []byte) {
	t.Helper()
	pkg, profile, _, _ := numericalSBFixture(t, arch)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	raw := []byte(`#include "textflag.h"
#include "go_asm.h"
#include "position.h"

// Discarding this line changes compiler debug metadata, not just diagnostics.
TEXT ·Feature(SB),NOSPLIT,$0-1
INNER(const_Value)
#line 73 "logical-one.s"
MOVB AX,ret+0(FP)
#ifdef ABSENT
#line 137 "logical-inactive.s"
#endif
RET
DATA table<>(SB)/4,$const_Value
GLOBL table<>(SB),RODATA,$4
`)
	if replacement != nil {
		raw = replacement
	}
	if headerSource == nil {
		headerSource = []byte("#define INNER(v) MOVL $v,AX\n")
	}
	goSource := []byte("package numericalfixture\nconst Value=7\nfunc Feature() byte\n")
	for name, data := range map[string][]byte{"value.go": goSource, profile.AssemblyFile: raw,
		"position.h": headerSource} {
		if err := os.WriteFile(filepath.Join(profile.Directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := goasmcmd.Run(ctx, profile.Directory, profile.Environment, profile.GoBinary,
		"list", "-compiled", "-export", "-json", "-gcflags=-std", "-asmflags=-std", ".")
	if err != nil {
		t.Fatal("actual complete first-party Go/ASM", err)
	}
	var selected goAMD64FrameSelection
	if json.Unmarshal(selection, &selected) != nil || selected.Standard || len(selected.SFiles) != 1 {
		t.Fatal("test -std flags changed source identity or complete member selection")
	}
	read := func(file string) []byte {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	root := filepath.Dir(filepath.Dir(profile.GoBinary))
	header := filepath.Join(profile.Directory, "go_asm.h")
	if _, err := goasmcmd.Run(ctx, profile.Directory, profile.Environment, profile.GoBinary,
		"tool", "compile", "-std", "-p", pkg.Path, "-asmhdr", header,
		"-o", filepath.Join(profile.Directory, "header.o"), filepath.Join(profile.Directory, "value.go")); err != nil {
		t.Fatal(err)
	}
	cpp, positions, err := observeSDKAssemblyCPP(string(raw), AssemblyPreprocessOptions{
		FileName: filepath.Join(profile.Directory, profile.AssemblyFile),
		Defines:  GoAssemblerDefinesWithEnv("linux", arch, map[string]string{"GO386": "sse2", "GOAMD64": "v1"}),
		ReadInclude: func(parent, name string) (string, []byte, error) {
			file := filepath.Join(profile.Directory, name)
			if _, err := os.Stat(file); os.IsNotExist(err) {
				file = filepath.Join(root, "pkg", "include", name)
			}
			return file, read(file), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	expanded := filepath.Join(profile.Directory, "expanded.asm")
	if err := os.WriteFile(expanded, []byte(positions.Mapped), 0600); err != nil {
		t.Fatal(err)
	}
	input := gostaticstorage.SDKASMDataSource{Name: profile.AssemblyFile, Original: raw, Expanded: []byte(cpp.Output)}
	for _, role := range []string{"original", "expanded"} {
		file := filepath.Join(profile.Directory, profile.AssemblyFile)
		if role == "expanded" {
			file = expanded
		}
		object := filepath.Join(profile.Directory, role+".o")
		args := []string{"tool", "asm", "-std", "-p", pkg.Path, "-I", profile.Directory,
			"-I", filepath.Join(root, "pkg", "include"), "-o", object, file}
		if _, err := goasmcmd.Run(ctx, profile.Directory, profile.Environment, profile.GoBinary, args...); err != nil {
			t.Fatal(err)
		}
		if role == "original" {
			input.OriginalObject = read(object)
		} else {
			input.ExpandedObject = read(object)
		}
	}
	request := gostaticstorage.SDKASMDataObservationRequest{PackagePath: pkg.Path, Target: profile.Target,
		Archive: read(selected.Export), BuiltinSource: read(filepath.Join(root, "src", "cmd", "internal", "goobj", "builtinlist.go")),
		Sources: []gostaticstorage.SDKASMDataSource{input}}
	scratch := &GoX86SDKASMDataSource{observation: sdkASMDataLiveObservation{Request: GoX86SDKASMDataCaptureRequest{
		GoBinary: profile.GoBinary, Directory: profile.Directory, PackagePath: pkg.Path,
		Target: profile.Target, Environment: profile.Environment}, ObjectInputs: request,
		CPP: []AssemblyCPPObservation{cpp}, Positions: []sdkCPPPositionObservation{positions},
		Header: sdkASMDataHeaderObservation{Actual: read(header), CompilerObject: read(filepath.Join(profile.Directory, "header.o"))}}}
	sdkASMDataDiagnosticRetain(t, scratch)
	if folder := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); folder != "" {
		// Actual first-party physical inputs outlive t.TempDir only as query
		// evidence. They do not construct or impersonate a live SDK source.
		inputs := map[string][]byte{filepath.Join(profile.Directory, "value.go"): goSource}
		for _, source := range cpp.Sources {
			inputs[source.File] = read(source.File)
		}
		raw, err := json.Marshal(inputs)
		if err != nil {
			t.Fatal(err)
		}
		name := "sdk-data-first-party-inputs-" + strings.ReplaceAll(t.Name(), "/", "-") + ".json"
		if err := os.WriteFile(filepath.Join(folder, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := gostaticstorage.ObserveX86SDKCPPASMData(request); err != nil {
		t.Fatal("complete first-party source/header/macro/lineage object join is not closed", err)
	}
	if replacement == nil {
		for _, mutation := range []string{"filename", "line"} {
			mapped := positions.Mapped
			if mutation == "filename" {
				// Logical metadata must remain part of complete object equality,
				// even when the emitted machine grammar is byte-identical.
				mapped = strings.ReplaceAll(mapped, profile.AssemblyFile, "foreign-logical.s")
			} else {
				var changed strings.Builder
				for _, line := range strings.Split(mapped, "\n") {
					if strings.HasPrefix(line, "#line ") {
						var value uint
						if _, err := fmt.Sscanf(line, "#line %d", &value); err != nil {
							t.Fatal(err)
						}
						line = strings.Replace(line, fmt.Sprint(value), fmt.Sprint(value+1), 1)
					}
					changed.WriteString(line)
					changed.WriteByte('\n')
				}
				mapped = changed.String()
			}
			replay, err := preprocessGoAssembly(mapped, AssemblyPreprocessOptions{})
			if err != nil || replay != cpp.Output {
				t.Fatal("metadata-only mutation changed machine grammar", mutation, err)
			}
			file := filepath.Join(profile.Directory, "changed-"+mutation+".asm")
			if err := os.WriteFile(file, []byte(mapped), 0600); err != nil {
				t.Fatal(err)
			}
			object := filepath.Join(profile.Directory, "changed-"+mutation+".o")
			if _, err := goasmcmd.Run(ctx, profile.Directory, profile.Environment, profile.GoBinary,
				"tool", "asm", "-std", "-p", pkg.Path, "-o", object, file); err != nil {
				t.Fatal(err)
			}
			changed := request
			changed.Sources = append([]gostaticstorage.SDKASMDataSource(nil), request.Sources...)
			changed.Sources[0].ExpandedObject = read(object)
			changedObservation := scratch.observation
			changedObservation.ObjectInputs = changed
			changedObservation.Positions = []sdkCPPPositionObservation{{Mapped: mapped}}
			sdkASMDataDiagnosticRetainNamed(t, "-mutation-"+mutation,
				&GoX86SDKASMDataSource{observation: changedObservation})
			if _, err := gostaticstorage.ObserveX86SDKCPPASMData(changed); !errors.Is(err, gostaticstorage.ErrContext) {
				t.Fatal("anonymous DATA/TEXT metadata mutation was normalized away", mutation, err)
			}
		}
	}
}

func TestGoX86SDKASMDataCPPPositionObjectFamilies(t *testing.T) {
	cases := []struct {
		name, raw, header string
	}{
		{"labels and semicolons", `#include "textflag.h"
TEXT ·Feature(SB),NOSPLIT,$0-1
start: NOP; MOVL $7,AX
MOVB AX,ret+0(FP)
RET
`, ""},
		{"included body and parent final base", `#include "textflag.h"
#include "position.h"

`, "TEXT ·Feature(SB),NOSPLIT,$0-1\nMOVL $7,AX\nMOVB AX,ret+0(FP)\nRET"},
		{"nested macro invocation", `#include "textflag.h"
#include "position.h"
/* multi-line
   physical comment */
TEXT ·Feature(SB),NOSPLIT,$0-1
OUTER(7)
MOVB AX,ret+0(FP)
RET
`, "#define INNER(v) MOVL $v,AX\n#define OUTER(v) INNER(v)\n"},
		{"active and inactive filename line", `#include "textflag.h"
#line 17 "active-logical.s"
TEXT ·Feature(SB),NOSPLIT,$0-1
MOVL $7,AX
#ifdef ABSENT
#line 131 "inactive-logical.s"
#endif
MOVB AX,ret+0(FP)
RET
`, ""},
		{"zero statements", "#include \"textflag.h\"\n// no machine statements\n", ""},
		{"empty TEXT body", "#include \"textflag.h\"\nTEXT ·Feature(SB),NOSPLIT,$0-1\n", ""},
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					sdkASMDataPositionFirstParty(t, arch, []byte(test.raw), []byte(test.header))
				})
			}
		})
	}
}
