package gotoolprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestInstrumentationEmissionPortableRoleGrammar(t *testing.T) {
	// Explicit unit records exercise the finite role validator only. They are
	// not actual Go captures and cannot satisfy ValidateInstrumentationMetadata
	// or the complete consumption/report/ledger entry points.
	for _, name := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(name, func(t *testing.T) {
			arch, err := instrumentationConsumptionArch("linux/" + name)
			if err != nil {
				t.Fatal(err)
			}
			const pkgPath = "example.invalid/unit.v2"
			pkg := PackageProof{PackagePath: pkgPath, Macros: &AssemblerMacros{}}
			for _, source := range []string{"", "// nonzero comment\n", "DATA local<>+0(SB)/8,$41\nGLOBL local<>(SB),0,$8\n"} {
				file := InstrumentationAssemblyFile{TypedSource: source, CPP: CPPProof{File: "source.s", Emission: "symbol_free"}}
				input := &InstrumentationConsumerInput{ID: strings.Repeat("b", 64),
					Original: &ConsumerInput{SignatureSourceProtocol: SignatureSourceProtocol, Sources: map[string]string{"source.s": bytesSHA256([]byte(source))}},
					Observation: &InstrumentationExportObservation{Early: &InstrumentationEarlyObservation{
						BaselineFeatures: &Observation{Target: "linux/" + string(arch), GoVersion: "go1.27.1"},
						ModeTools:        &InstrumentationToolState{BinarySHA256: map[string]string{"asm": strings.Repeat("a", 64)}},
					}},
				}
				native := EmptyAssemblyProof{Protocol: EmptyAssemblyProtocol, ProfileID: input.ID, File: "source.s",
					PackagePath: pkgPath, SourceSHA256: input.Original.Sources["source.s"], Target: "linux/" + string(arch),
					GoVersion: "go1.27.1", AsmToolSHA256: strings.Repeat("a", 64), ObjectSHA256: strings.Repeat("c", 64), ListingSHA256: bytesSHA256(nil)}
				if strings.HasPrefix(source, "DATA") {
					file.CPP.Emission = "data_only"
					native.Protocol, native.ListingSHA256 = DataOnlyAssemblyProtocol, strings.Repeat("d", 64)
					file.CPP.DataOnlyAssembly = &DataOnlyAssemblyProof{Native: native, Symbols: []DataOnlySymbol{{Name: "local", Static: true, Kind: "SDATA", Size: 8}}}
				} else {
					file.CPP.EmptyAssembly = &native
				}
				if _, err := validateInstrumentationAssemblyEmission(input, pkg, file, arch); err != nil {
					t.Fatal(err)
				}
				body, err := json.Marshal(file)
				if err != nil {
					t.Fatal(err)
				}
				for name, change := range map[string]func(*InstrumentationAssemblyFile){
					"known empty object": func(f *InstrumentationAssemblyFile) {
						if f.CPP.EmptyAssembly != nil {
							f.CPP.EmptyAssembly.ObjectSHA256 = bytesSHA256(nil)
						} else {
							f.CPP.DataOnlyAssembly.Native.ObjectSHA256 = bytesSHA256(nil)
						}
					},
					"missing role": func(f *InstrumentationAssemblyFile) { f.CPP.Emission = "" },
					"paired missing native": func(f *InstrumentationAssemblyFile) {
						f.CPP.Emission = "assembly"
						f.CPP.EmptyAssembly = nil
						f.CPP.DataOnlyAssembly = nil
					},
					"both native roles": func(f *InstrumentationAssemblyFile) {
						f.CPP.EmptyAssembly = &native
						f.CPP.DataOnlyAssembly = &DataOnlyAssemblyProof{Native: native}
					},
					"unconsumed decl": func(f *InstrumentationAssemblyFile) {
						f.Declarations = []InstrumentationDeclarationProof{{Symbol: "unconsumed"}}
					},
					"malformed TEXT":      func(f *InstrumentationAssemblyFile) { f.TypedSource = "TEXT\n" },
					"different TEXT role": func(f *InstrumentationAssemblyFile) { f.TypedSource = "TEXT ·Unexpected(SB),$0-0\nRET\n" },
					"missing DATA":        func(f *InstrumentationAssemblyFile) { f.TypedSource = "// symbol-free\n"; f.CPP.Emission = "data_only" },
				} {
					t.Run(file.CPP.Emission+"/"+name, func(t *testing.T) {
						var changed InstrumentationAssemblyFile
						if err := json.Unmarshal(body, &changed); err != nil {
							t.Fatal(err)
						}
						change(&changed)
						if _, err := validateInstrumentationAssemblyEmission(input, pkg, changed, arch); err == nil {
							t.Fatal("contradictory role acquired a native source permission")
						}
					})
				}
			}
			if _, err := validateInstrumentationAssemblyEmission(nil, pkg, InstrumentationAssemblyFile{}, arch); err == nil {
				t.Fatal("nil scope accepted")
			}
		})
	}
}

func TestDataOnlySourceCompleteSymbolIdentity(t *testing.T) {
	const pkg = "example.invalid/data.v2"
	const source = "DATA ·A+0(SB)/8,$1\nGLOBL ·A(SB),0,$8\nGLOBL local<>(SB),0,$16\nGLOBL foreign·B(SB),0,$4\n"
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	symbols := []DataOnlySymbol{{Name: "example.invalid/data%2ev2.A", Kind: "SDATA", Size: 8}, {Name: "foreign.B", Kind: "SBSS", Size: 4}, {Name: "local", Static: true, Kind: "SBSS", Size: 16}}
	if err := ValidateDataOnlySourceSymbols(file, pkg, symbols); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{
		strings.Replace(source, "·A", "·Other", -1),
		strings.Replace(source, "$16", "$17", 1),
		strings.Replace(source, "local<>", "local", -1),
		source + "GLOBL extra(SB),0,$1\n",
		source + "TEXT ·Fn(SB),$0-0\nRET\n",
	} {
		parsed, err := plan9asm.Parse(plan9asm.ArchAMD64, changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDataOnlySourceSymbols(parsed, pkg, symbols); err == nil {
			t.Fatal("changed native symbols were accepted")
		}
	}
}
