//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestGoX86SDKNumericalReadLiteralMappedRepeatedPositions(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg, profile, _, _ := numericalSBFixture(t, arch)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			filename := filepath.Join(profile.Directory, "positions.s")
			original := fmt.Sprintf(`#define READ CMPB ·Flag(SB), $1
#define PAIR READ; READ
DATA table<>+0(SB)/8, $1
GLOBL table<>(SB), 8, $8
TEXT ·positions(SB), 4, $0-0
READ; READ
PAIR
#line 50 %q
READ
#line 50 %q
READ
RET
`, filename, filename)
			observed, tape, err := observeSDKAssemblyCPP(original, AssemblyPreprocessOptions{FileName: filename})
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, observed.Output)
			if err != nil {
				t.Fatal(err)
			}
			positions, err := numericalSDKLiteralSourcePositions(file, observed.Output, tape)
			if err != nil || len(positions) != 1 || len(positions[0]) != 8 {
				t.Fatal("complete original source position tape", err, positions)
			}
			for _, mutation := range []string{"token text", "token position", "mapped stream", "CPP program", "parsed ordinal"} {
				t.Run(mutation, func(t *testing.T) {
					changed := tape
					changed.Tokens = append([]sdkCPPPositionToken(nil), tape.Tokens...)
					program := observed.Output
					parsed := *file
					parsed.Funcs = append([]Func(nil), file.Funcs...)
					switch mutation {
					case "token text":
						changed.Tokens[0].Text += "foreign"
					case "token position":
						changed.Tokens[0].Position.Line++
					case "mapped stream":
						changed.Mapped += "RET\n"
					case "CPP program":
						program += "RET\n"
					case "parsed ordinal":
						parsed.Funcs[0].Instrs = append([]Instr(nil), file.Funcs[0].Instrs[1:]...)
					}
					if _, err := numericalSDKLiteralSourcePositions(&parsed, program, changed); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed complete source/tape/ordinal was accepted", err)
					}
				})
			}
			for _, route := range []string{"original", "mapped"} {
				t.Run(route, func(t *testing.T) {
					path, program := filename, original
					if route == "mapped" {
						path, program = filepath.Join(profile.Directory, "mapped.asm"), tape.Mapped
					}
					if err := os.WriteFile(path, []byte(program), 0600); err != nil {
						t.Fatal(err)
					}
					listing, err := goasmcmd.Run(ctx, profile.Directory, profile.Environment, profile.GoBinary,
						"tool", "asm", "-S", "-p", pkg.Path, "-o", filepath.Join(profile.Directory, route+".o"), path)
					if err != nil {
						t.Fatal("actual original/mapped Go assembler", err)
					}
					all, err := numericalListingRows(listing)
					if err != nil {
						t.Fatal(err)
					}
					rows := all[pkg.Path+".positions"]
					for ordinal := 1; ordinal <= 6; ordinal++ {
						matches := 0
						for pc, candidates := range rows {
							for _, row := range candidates {
								if !numericalSDKLiteralReadOrdinal(file.Funcs[0], ordinal, positions[0], pc, row, rows, pkg.Path, arch) {
									continue
								}
								matches++
								changed := row
								changed.position += ".foreign"
								if numericalSDKLiteralReadOrdinal(file.Funcs[0], ordinal, positions[0], pc, changed, rows, pkg.Path, arch) {
									t.Fatal("foreign source position borrowed a read ordinal")
								}
								for other := 1; other <= 6; other++ {
									if other != ordinal && numericalSDKLiteralReadOrdinal(file.Funcs[0], other, positions[0], pc, row, rows, pkg.Path, arch) {
										t.Fatal("repeated macro/source line borrowed another native PC")
									}
								}
							}
						}
						if matches != 1 {
							t.Fatalf("source ordinal %d has %d native matches, expected %s; actual listing:\n%s", ordinal, matches, positions[0][ordinal], listing)
						}
					}
				})
			}
		})
	}
}

func TestGoX86SDKNumericalReadLiteralPositionDisplayGrammar(t *testing.T) {
	for _, input := range []string{"source.s:0", "source.s:12", "source.s:12[source.s:20]", "source.s:12[generated.s:20]"} {
		if _, valid := numericalSDKListingLogicalPosition(input); !valid {
			t.Fatal("valid Go position display rejected", input)
		}
	}
	for _, input := range []string{"", ":1", "source.s", "source.s:-1", "source.s:+1", "source.s:1x",
		"source.s:4294967296", "source.s:1[", "source.s:1[]", "source.s:1[other.s:x]",
		"source.s:1[other.s:2]tail", "source.s:1[other.s:2[third.s:3]]", "source.s:1]", "source.s:1\n"} {
		if _, valid := numericalSDKListingLogicalPosition(input); valid {
			t.Fatal("unknown/malformed Go position display accepted", input)
		}
	}
}

func TestGoX86SDKNumericalReadLiteralObjectSourceNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sdk")
	assembly := filepath.Join(root, "src", "sample", "input.s")
	goSource := filepath.Join(root, "src", "sample", "input.go")
	digest := sha256.Sum256([]byte("captured source"))
	newSource := func() *GoX86NumericalReadSource {
		return &GoX86NumericalReadSource{
			literals: &numericalSDKLiteralJoin{},
			guard: &GoAMD64FrameSource{
				env: map[string]string{"GOROOT": root},
				inputs: map[string][32]byte{
					assembly: digest,
					goSource: digest,
				},
			},
			cpp: AssemblyCPPObservation{Sources: []AssemblyCPPObservedSource{
				{File: assembly, SHA256: fmt.Sprintf("%x", digest)},
			}},
		}
	}
	for _, name := range []string{assembly, filepath.ToSlash(assembly), "$GOROOT/src/sample/input.s"} {
		if actual, valid := newSource().sdkLiteralObjectSource(name); !valid || actual != assembly {
			t.Fatal("exact captured SDK/CPP source spelling rejected", name, actual, valid)
		}
	}
	for _, name := range []string{
		"", "input.s", "src/sample/input.s", "$GOROOT", "$GOROOT/../input.s",
		"$GOROOT/src/../src/sample/input.s", "$GOROOT//src/sample/input.s",
		"$GOROOT/src/sample/./input.s", "$GOROOT/src/sample/missing.s",
		"$GOROOT/src/sample/input.go", goSource, assembly + ".foreign",
	} {
		if actual, valid := newSource().sdkLiteralObjectSource(name); valid {
			t.Fatal("unbound source spelling supplied a native PC identity", name, actual)
		}
	}
	for _, mutation := range []string{"ordinary source", "missing captured input", "missing CPP input", "stale captured hash", "stale CPP hash", "different SDK root"} {
		t.Run(mutation, func(t *testing.T) {
			source := newSource()
			switch mutation {
			case "ordinary source":
				source.literals = nil
			case "missing captured input":
				delete(source.guard.inputs, assembly)
			case "missing CPP input":
				source.cpp.Sources = nil
			case "stale captured hash":
				source.guard.inputs[assembly] = sha256.Sum256([]byte("changed source"))
			case "stale CPP hash":
				source.cpp.Sources[0].SHA256 = "changed"
			case "different SDK root":
				source.guard.env["GOROOT"] = filepath.Join(root, "other")
			}
			if actual, valid := source.sdkLiteralObjectSource("$GOROOT/src/sample/input.s"); valid {
				t.Fatal("changed captured SDK/CPP identity supplied a native PC", actual)
			}
		})
	}
}
