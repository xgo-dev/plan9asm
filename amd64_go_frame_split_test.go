//go:build go1.27

package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64FrameAutomaticSplitLayout(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		// Go's ADJSP encoder flips ADD/SUB at the signed-byte boundary.
		// Exercise both sides, with and without generated stack checks.
		for _, frame := range []int{64, 120, 128, 160, 256} {
			for _, nosplit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/frame%d/nosplit%t", target.name, frame, nosplit), func(t *testing.T) {
					pkg, request := goAMD64FrameSourceFixture(t)
					request.Target = target.name
					flags := ""
					if nosplit {
						flags = "4,"
					}
					assembly := fmt.Sprintf("TEXT ·Value(SB),%s$%d-16\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nMOVQ 16(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n", flags, frame)
					if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
						t.Fatal(err)
					}
					// The original assembler decides whether a source-level split
					// flag actually generates a stack check (small leaves do not).
					listing := x86InsertExtractGoListing(t, "amd64", assembly)
					wantSplit := !nosplit && frame+8 >= 128
					if strings.Contains(string(listing), "CALL\truntime.morestack_noctxt") != wantSplit {
						t.Fatal("independent Go prologue did not match the frame/flag case", listing)
					}
					name := pkg.Path + ".Value"
					sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: "amd64", TargetTriple: target.triple,
						Sigs: map[string]FuncSig{name: sig}, ResolveSym: func(string) string { return name }}
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate"}, func(t *testing.T, ir string, err error) {
						if err != nil || !strings.Contains(ir, "%fixed_local_native = alloca") || strings.Contains(ir, "morestack") {
							t.Fatal("ordinary source frame did not use the LLVM function frame", err)
						}
						compileLLVMToObject(t, llc, options.TargetTriple, "split.ll", "split.o", ir)
						compileLLVMToObject(t, llc, options.TargetTriple, "split-opt.ll", "split-opt.o", x86MulDivRoundOptimize(t, ir))
					})
				})
			}
		}
	}
}

func TestGoAMD64FrameAutomaticSplitRejectsChangedObservation(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	pkg, request := goAMD64FrameSourceFixture(t)
	name := filepath.Join(request.Directory, request.AssemblyFile)
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), ",NOSPLIT,", ",", 1))
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := requireGoAMD64FrameCapture(t, pkg, request)
	expanded, err := source.preprocess(request.AssemblyFile, raw)
	if err != nil {
		t.Fatal(err)
	}
	object, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := source.frameDataObject(expanded, object)
	if err != nil || len(observed.Member.Texts) != 1 {
		t.Fatal("missing complete original split TEXT", err)
	}
	fn := source.functions[pkg.Path+".Value"]
	text := observed.Member.Texts[0]
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := goAMD64FrameSplitProjection(fn, text, 160, request.Target, request.Directory, "", nil)
	if err != nil || projection.prologue <= 0 || len(projection.code) >= len(fn.code) {
		t.Fatal("missing generated layout projection", err)
	}
	listing, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	for _, mismatch := range []string{"FIPS header", "FIPS object", "missing kind"} {
		t.Run(mismatch, func(t *testing.T) {
			changed, header := text, listing
			switch mismatch {
			case "FIPS header":
				header = []byte(strings.Replace(string(listing), " STEXT ", " STEXTFIPS ", 1))
			case "FIPS object":
				changed.Kind = 2
			case "missing kind":
				changed.Kind = 0
			}
			_, err := goAMD64FrameListingWithSplitObject(header, file, pkg, source.origins,
				[]gostaticstorage.TextRecord{changed}, nil, request.Target, request.Directory, "")
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("listing silently changed the complete object TEXT kind", err)
			}
		})
	}
	for _, mutation := range []string{
		"TLS offset", "TLS type", "TLS target", "call offset", "call target", "call ABI", "extra relocation",
		"prefix bytes", "branch destination", "retry destination", "generated source line", "empty positions", "position gap", "object bytes", "body branch to entry", "NOSPLIT flag", "extra flag",
	} {
		t.Run(mutation, func(t *testing.T) {
			var changed gostaticstorage.TextRecord
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "TLS offset":
				changed.Relocations[0].Offset++
			case "TLS type":
				changed.Relocations[0].Type = 16
			case "TLS target":
				changed.Relocations[0].Target.Name = "runtime.tls_g"
			case "call offset":
				changed.Relocations[1].Offset++
			case "call target":
				changed.Relocations[1].Target.Name = "runtime.morestack"
			case "call ABI":
				changed.Relocations[1].Target.ABI = 1
			case "extra relocation":
				changed.Relocations = append(changed.Relocations, changed.Relocations[1])
			case "prefix bytes":
				changed.Code[0] = 0x65
			case "branch destination":
				changed.Code[projection.prologue-1]++
			case "retry destination":
				changed.Code[len(changed.Code)-1]++
			case "generated source line":
				changed.Positions[0].Line++
			case "empty positions":
				changed.Positions = nil
			case "position gap":
				changed.Positions[0].Start++
			case "object bytes":
				changed.Code = changed.Code[:len(changed.Code)-1]
			case "NOSPLIT flag":
				changed.Flags = 16
			case "extra flag":
				changed.Flags = 1
			case "body branch to entry":
				pc := int(changed.Positions[1].Start)
				changed.Code[pc], changed.Code[pc+1] = 0x74, byte(-pc-2)
			}
			changedFn := fn
			if mutation != "object bytes" {
				changedFn.code = changed.Code
			}
			shape, err := goAMD64FrameSplitProjection(changedFn, changed, 160, request.Target, request.Directory, "", nil)
			if err == nil {
				err = goAMD64FrameMachineShape(shape, 160)
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed complete split observation accepted", err)
			}
		})
	}
}

func TestGoAMD64FrameAutomaticSplitDoesNotAuthorizeSourceRuntime(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, instruction := range []string{"CALL runtime·morestack_noctxt(SB)", "MOVQ (TLS),R14", "MOVQ 168(SP),AX"} {
		t.Run(instruction, func(t *testing.T) {
			pkg, request, _, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			name := filepath.Join(request.Directory, request.AssemblyFile)
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			assembly := strings.Replace(string(raw), "TEXT ·Value(SB),4,$160-40", "TEXT ·Value(SB),$160-40\n"+instruction, 1)
			if err := os.WriteFile(name, []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			x86InsertExtractGoListing(t, "amd64", assembly)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil {
				defer func() {
					if err := source.Close(); err != nil {
						t.Error(err)
					}
				}()
				expanded, readErr := source.preprocess(request.AssemblyFile, []byte(assembly))
				if readErr != nil {
					t.Fatal(readErr)
				}
				file, parseErr := Parse(ArchAMD64, expanded)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				_, err = source.BindFixedLocal(ctx, pkg, file, options)
			}
			if !errors.Is(err, ErrProbeNeedsContext) || strings.Contains(err.Error(), "producer") {
				t.Fatal("automatic split check authorized a source runtime or return-slot effect", err)
			}
		})
	}
}
