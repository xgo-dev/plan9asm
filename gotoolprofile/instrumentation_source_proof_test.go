package gotoolprofile

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func actualInstrumentationSourceProof(t *testing.T) *InstrumentationSourceProof {
	t.Helper()
	proof, err := CaptureInstrumentationSourceProof(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func cloneInstrumentationSourceProof(t *testing.T, proof *InstrumentationSourceProof) *InstrumentationSourceProof {
	t.Helper()
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var result InstrumentationSourceProof
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

func TestInstrumentationSourceProofActualCaptureAndOfflineRoundtrip(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeInstrumentationSourceProof(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ReplayInstrumentationSourceProof(restored)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []InstrumentationMode{InstrumentationRace, InstrumentationMSan, InstrumentationASan} {
		if _, err := rules.TargetSupported("linux/arm64", mode); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(string(data), runtime.GOROOT()) {
		t.Fatal("portable source proof leaked its physical tool root")
	}
	if rules.root != "" {
		t.Fatal("offline replay acquired an actual source-tree identity")
	}
	if err := rules.Recheck(); err == nil {
		t.Fatal("offline source replay impersonated a production source recheck")
	}
}

func TestInstrumentationSourceProofRejectsForgedRegistrationAndBounds(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	for name, mutate := range map[string]func(*testing.T, *InstrumentationSourceProof){
		"missing protocol": func(t *testing.T, p *InstrumentationSourceProof) { p.Protocol = "" },
		"downgrade":        func(t *testing.T, p *InstrumentationSourceProof) { p.Protocol = "go_driver_builtin_features_v2" },
		"wrong version":    func(t *testing.T, p *InstrumentationSourceProof) { p.GoVersion = "go1.19.13" },
		"missing source": func(t *testing.T, p *InstrumentationSourceProof) {
			delete(p.SourceText, "src/cmd/go/internal/work/init.go")
		},
		"missing hash": func(t *testing.T, p *InstrumentationSourceProof) { delete(p.SourceSHA256, "VERSION") },
		"missing AST":  func(t *testing.T, p *InstrumentationSourceProof) { delete(p.RegistrationSHA256, "MSanSupported") },
		"foreign source": func(t *testing.T, p *InstrumentationSourceProof) {
			p.SourceText["unregistered.go"] = "package unknown\n"
		},
		"changed bytes": func(t *testing.T, p *InstrumentationSourceProof) { p.SourceText["VERSION"] += "changed" },
		"changed AST": func(t *testing.T, p *InstrumentationSourceProof) {
			p.RegistrationSHA256["instrumentInit"] = strings.Repeat("0", 64)
		},
		"source bound": func(t *testing.T, p *InstrumentationSourceProof) {
			p.SourceText["VERSION"] = strings.Repeat("x", instrumentationRegistrationByteLimit+1)
		},
		"self-consistent platform forgery": func(t *testing.T, p *InstrumentationSourceProof) {
			key := "src/internal/platform/supported.go"
			original := p.SourceText[key]
			p.SourceText[key] = strings.Replace(original, `case "linux":`, `case "plan9":`, 1)
			if p.SourceText[key] == original {
				t.Fatal("actual platform fixture did not contain the expected complete grammar")
			}
			p.SourceSHA256[key] = bytesSHA256([]byte(p.SourceText[key]))
			contents := make(map[string][]byte)
			for name, text := range p.SourceText {
				contents[name] = []byte(text)
			}
			rules, err := replayInstrumentationRuleSources("", p.GoVersion, contents)
			if err != nil {
				t.Fatal(err)
			}
			p.RegistrationSHA256 = rules.RegistrationHashes()
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneInstrumentationSourceProof(t, proof)
			mutate(t, mutated)
			if _, err := ReplayInstrumentationSourceProof(mutated); err == nil {
				t.Fatal("accepted incomplete or forged source-rule evidence")
			}
		})
	}
}

func TestInstrumentationSourceProofDecoderRejectsUnknownTrailingAndOversizedJSON(t *testing.T) {
	data, err := json.Marshal(actualInstrumentationSourceProof(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		string(data) + "{}", `{"protocol":"x","supported":true}`,
		strings.Repeat(" ", instrumentationSourceProofJSONLimit+1),
	} {
		if _, err := DecodeInstrumentationSourceProof(strings.NewReader(input)); err == nil {
			t.Fatal("accepted unknown, trailing or over-bound source-proof JSON")
		}
	}
}
