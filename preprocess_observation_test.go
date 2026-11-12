package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"text/scanner"
)

func TestPreprocessAssemblyCPPObservationGoObjects(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			for _, fixture := range ppMacroControlFixtures() {
				t.Run(fixture.name, func(t *testing.T) {
					for _, style := range []string{"object", "alias", "function"} {
						t.Run(style, func(t *testing.T) {
							source := ppMacroControlSource(fixture, style)
							headers := map[string]string{"choice.h": "#define VALUE 42\n"}
							original := ppMacroControlGoObject(t, target, source, headers, "observation-original")
							if !strings.Contains(string(original), "2a 00 00 00") {
								t.Fatal("actual original Go object lacks its marker")
							}
							options := AssemblyPreprocessOptions{
								FileName: "entry.s",
								ReadInclude: func(parent, name string) (string, []byte, error) {
									body, ok := headers[name]
									if !ok || parent != "entry.s" {
										return "", nil, fmt.Errorf("unbound include %s:%s", parent, name)
									}
									return name, []byte(body), nil
								},
							}
							plain, err := PreprocessAssemblySource(source, options)
							if err != nil {
								t.Fatal(err)
							}
							observed, err := ObserveAssemblyCPP(source, options)
							if err != nil {
								t.Fatal(err)
							}
							if observed.Output != plain {
								t.Fatalf("observation changed strict CPP output: %q != %q", observed.Output, plain)
							}
							ppCheckObservation(t, observed)
							if len(observed.Events) == 0 || len(observed.Sources) == 0 {
								t.Fatal("accepted source has no actual execution/source observation")
							}
							ppCheckObservedSource(t, observed, "entry.s", source)
							if fixture.name == "include" {
								ppCheckObservedSource(t, observed, "choice.h", headers["choice.h"])
							}
							normalized := ppMacroControlGoObject(t, target, observed.Output, nil, "observation-normalized")
							if !strings.Contains(string(normalized), "2a 00 00 00") {
								t.Fatal("observed CPP changed the actual Go object's marker")
							}
						})
					}
				})
			}
		})
	}
}

func TestPreprocessAssemblyCPPObservationTransitions(t *testing.T) {
	const source = "#define F(x) \\\n#define VALUE x \\\n\n#ifdef ABSENT\nF(13)\n#define DISABLED 1\n#include \"missing.h\"\n#else\nF(42)\n#endif\nDATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n"
	observed, err := ObserveAssemblyCPP(source, AssemblyPreprocessOptions{FileName: "entry.s"})
	if err != nil {
		t.Fatal(err)
	}
	ppCheckObservation(t, observed)
	var inactiveInvocation, activeInvocation, generatedDefinition, skippedInclude bool
	for _, event := range observed.Events {
		if event.Kind == "invoke" && event.Name == "F" {
			inactiveInvocation = inactiveInvocation || !event.EnabledBefore
			activeInvocation = activeInvocation || event.EnabledBefore
			if !event.Function || event.Definition == 0 {
				t.Fatalf("lost actual function-macro definition: %+v", event)
			}
		}
		if event.Kind == "control" && event.Directive == "define" && event.Name == "VALUE" {
			generatedDefinition = generatedDefinition || event.Expansion != 0
		}
		if event.Kind == "control" && event.Directive == "include" && !event.EnabledBefore {
			skippedInclude = true
			if event.Included != "" {
				t.Fatal("inactive include invented actual consumption")
			}
		}
	}
	if !inactiveInvocation || !activeInvocation || !generatedDefinition || !skippedInclude {
		t.Fatalf("incomplete actual execution transitions: %+v", observed.Events)
	}
}

func TestPreprocessAssemblyCPPObservationPredefines(t *testing.T) {
	defines := []string{"VALUE=13", "VALUE=42"}
	const source = "DATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n"
	observed, err := ObserveAssemblyCPP(source, AssemblyPreprocessOptions{FileName: "entry.s", Defines: defines})
	if err != nil {
		t.Fatal(err)
	}
	ppCheckObservation(t, observed)
	if !reflect.DeepEqual(observed.Defines, defines) || len(observed.Events) != 3 ||
		observed.Events[0].Kind != "predefine" || observed.Events[1].Kind != "predefine" ||
		observed.Events[2].Definition != 2 {
		t.Fatalf("predefined overwrite/actual macro binding lost: %+v", observed)
	}
	defines[0] = "VALUE=99"
	if observed.Defines[0] != "VALUE=13" {
		t.Fatal("observation borrowed mutable caller options")
	}
}

func TestPreprocessAssemblyCPPObservationIncludes(t *testing.T) {
	const source = "#include \"guard.h\"\nTEXT ·Probe(SB),$0-0\nRET\n"
	const header = "#ifndef GUARD\n#define GUARD 1\n#include \"guard.h\"\n#endif\n"
	options := AssemblyPreprocessOptions{FileName: "entry.s", ReadInclude: func(parent, name string) (string, []byte, error) {
		if name != "guard.h" || parent != "entry.s" && parent != "guard.h" {
			return "", nil, fmt.Errorf("unbound include")
		}
		return "guard.h", []byte(header), nil
	}}
	observed, err := ObserveAssemblyCPP(source, options)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := PreprocessAssemblySource(source, options)
	if err != nil || plain != observed.Output || len(observed.Sources) != 2 {
		t.Fatalf("guarded include cycle changed: %+v / %v", observed, err)
	}
	ppCheckObservedSource(t, observed, "guard.h", header)
	var active int
	for _, event := range observed.Events {
		if event.Directive == "include" && event.EnabledBefore {
			active++
			if event.Included != "guard.h" {
				t.Fatal("actual include identity missing")
			}
		}
	}
	if active != 2 {
		t.Fatalf("lost actual repeated include use: %d", active)
	}
}

func TestPreprocessAssemblyCPPObservationFailureIdentity(t *testing.T) {
	for _, source := range []string{
		"#define RET(x) x\nTEXT ·Probe(SB),$0-0\nRET\n",
		"#define F(x) x\n#ifdef ABSENT\nF +\n#endif\nTEXT ·Probe(SB),$0-0\nRET\n",
		"#include \"missing.h\"\n",
		"TEXT ·Probe(SB),$0-0\nRET",
	} {
		t.Run(fmt.Sprintf("%x", sha256.Sum256([]byte(source))), func(t *testing.T) {
			options := AssemblyPreprocessOptions{FileName: "entry.s"}
			_, plainErr := PreprocessAssemblySource(source, options)
			observed, observedErr := ObserveAssemblyCPP(source, options)
			if plainErr == nil {
				// Some parser failures remain invalid normalized machine source;
				// the query must still return exactly the normal engine's output.
				plain, err := PreprocessAssemblySource(source, options)
				if err != nil || observedErr != nil || observed.Output != plain {
					t.Fatalf("observation changed successful CPP: %v / %v", err, observedErr)
				}
				return
			}
			if observedErr == nil || observedErr.Error() != plainErr.Error() ||
				!reflect.DeepEqual(observed, AssemblyCPPObservation{}) {
				t.Fatalf("observation changed failure or returned a positive trace: %v / %v / %+v", plainErr, observedErr, observed)
			}
		})
	}
}

func TestPreprocessAssemblyCPPObservationCachedLookahead(t *testing.T) {
	const source = "#define F(x) x\n#ifdef ABSENT\nF\n\n#endif\nTEXT ·Probe(SB),$0-0\nRET\n"
	original := ppSemanticGoObject(t, "observation-original-lookahead", source, nil, nil)
	if !original.accepted {
		t.Fatalf("original Go did not accept the cached-newline control: %s", original.output)
	}
	observed, err := ObserveAssemblyCPP(source, AssemblyPreprocessOptions{FileName: "entry.s"})
	if err != nil {
		t.Fatal(err)
	}
	ppCheckObservation(t, observed)
	var reference int
	var peek bool
	for _, event := range observed.Events {
		if event.Kind == "invoke" && event.Name == "F" {
			reference = event.Ordinal
			if event.Invoked || event.EnabledBefore || !event.Function {
				t.Fatalf("bare inactive function macro was turned into an invocation: %+v", event)
			}
		}
		if event.Kind == "peek" {
			peek = true
			if reference == 0 || event.Expansion != reference || len(event.Tokens) != 1 ||
				event.Tokens[0].Kind != '\n' || event.Tokens[0].Text != "#" {
				t.Fatalf("cached token's dispatch/text/lineage changed: %+v", event)
			}
		}
	}
	if !peek {
		t.Fatal("cached token consumption is absent from the execution trace")
	}
}

func TestPreprocessAssemblyCPPObservationCapturesConsumedDefines(t *testing.T) {
	defines := []string{"VALUE=42"}
	options := AssemblyPreprocessOptions{
		FileName: "entry.s", Defines: defines,
		ReadInclude: func(parent, name string) (string, []byte, error) {
			defines[0] = "VALUE=99"
			return "header.h", []byte("\n"), nil
		},
	}
	const source = "#include \"header.h\"\nDATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n"
	observed, err := ObserveAssemblyCPP(source, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed.Defines, []string{"VALUE=42"}) || !strings.Contains(observed.Output, "$42") {
		t.Fatalf("trace retained caller mutation rather than consumed -D input: %+v", observed)
	}
}

func TestPreprocessAssemblyCPPObservationBoundsAndChangedSource(t *testing.T) {
	t.Run("changed-include", func(t *testing.T) {
		calls := 0
		const source = "#include \"header.h\"\n#include \"header.h\"\n"
		observed, err := ObserveAssemblyCPP(source, AssemblyPreprocessOptions{
			FileName: "entry.s", ReadInclude: func(parent, name string) (string, []byte, error) {
				calls++
				return "header.h", []byte(fmt.Sprintf("// version %d\n", calls)), nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "changed during execution") ||
			!reflect.DeepEqual(observed, AssemblyCPPObservation{}) {
			t.Fatalf("changed source received a successful observation: %v / %+v", err, observed)
		}
	})
	t.Run("events", func(t *testing.T) {
		observer := newPPGoObservation()
		observer.eventLimit = 2
		output, err := preprocessGoAssemblyObserved("#define X 1\nX\nX\n", AssemblyPreprocessOptions{}, observer)
		if err == nil || !strings.Contains(err.Error(), "2-event bound") || output != "" || len(observer.result.Events) != 2 {
			t.Fatalf("event exhaustion was truncated or accepted: output=%q err=%v", output, err)
		}
	})
	for _, bound := range []string{"tokens", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			observer := newPPGoObservation()
			observer.result.Events = []AssemblyCPPEvent{{Ordinal: 1}}
			observer.active = 0
			if bound == "tokens" {
				observer.tokens = ppGoObservationTokens
			} else {
				observer.tokenBytes = ppGoObservationBytes
			}
			if err := observer.capture(ppGoToken{kind: scanner.Ident, text: "X", value: "X"}); err == nil ||
				len(observer.result.Events[0].Tokens) != 0 {
				t.Fatal("exhausted capture silently appended or accepted a token")
			}
		})
	}
}

func ppCheckObservation(t *testing.T, observation AssemblyCPPObservation) {
	t.Helper()
	for index, event := range observation.Events {
		if event.Ordinal != index+1 || event.Expansion < 0 || event.Expansion >= event.Ordinal ||
			event.Definition < 0 || event.Definition >= event.Ordinal || event.Include < 0 || event.Include >= event.Ordinal {
			t.Fatalf("noncanonical event order/lineage: %+v", event)
		}
	}
}

func ppCheckObservedSource(t *testing.T, observation AssemblyCPPObservation, file, source string) {
	t.Helper()
	for _, observed := range observation.Sources {
		if observed.File == file {
			if observed.Bytes != len(source) || observed.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(source))) {
				t.Fatalf("source identity mismatch: %+v", observed)
			}
			return
		}
	}
	t.Fatalf("missing actual source identity %q", file)
}
