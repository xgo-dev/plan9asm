//go:build go1.27

package plan9asm

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"golang.org/x/arch/x86/x86asm"
)

func fixedLocalSplitDataFixture(t *testing.T, target, triple string, frame int) (GoPackage, GoAMD64FrameCaptureRequest, Options, string) {
	t.Helper()
	pkg, request, _, options, original := fixedLocalDataFixture(t,
		"MOVOU literal<>(SB),X0\nPADDQ 16(SP),X0", fixedLocalLiteralData)
	assembly := strings.Replace(original, "TEXT ·Value(SB),4,$160-40", fmt.Sprintf("TEXT ·Value(SB),$%d-40", frame), 1)
	if assembly == original {
		t.Fatal("fixture did not remove the source NOSPLIT flag")
	}
	if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	request.Target, options.TargetTriple = target, triple
	return pkg, request, options, assembly
}

func TestGoAMD64FrameAutomaticSplitWithDataObjects(t *testing.T) {
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
		t.Run(target.name, func(t *testing.T) {
			for _, frame := range []int{160, 536} {
				t.Run(fmt.Sprintf("frame%d", frame), func(t *testing.T) {
					pkg, request, options, assembly := fixedLocalSplitDataFixture(t, target.name, target.triple, frame)
					x86LEAActualTargetGoObject(t, "amd64", target.triple, assembly)
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
						if err != nil || !strings.Contains(ir, "internal constant [32 x i8]") ||
							!strings.Contains(ir, "fixed_local_native") || strings.Contains(ir, "morestack") {
							t.Fatal("complete DATA/split source lost its ordinary LLVM frame or private literal", err)
						}
						compileLLVMToObject(t, llc, target.triple, "split-data.ll", "split-data.o", ir)
						compileLLVMToObject(t, llc, target.triple, "split-data-opt.ll", "split-data-opt.o", x86MulDivRoundOptimize(t, ir))
					})
				})
			}
		})
	}
}

func TestGoAMD64FrameAutomaticSplitWithSDKDataObservation(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/internal/fips140/sha256")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	pkg := sdkAMD64FrameActualPackage(t, observed.source)
	source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: "sha256block_amd64.s",
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		for ordinal, object := range observed.source.observation.Objects.Sources {
			for _, text := range object.Original.Texts {
				if text.Name != request.PackagePath+".blockAVX2" || len(text.Code) < 64 || len(text.Positions) == 0 {
					continue
				}
				t.Logf("original prefix=%x tail=%x relocations=%+v firstPC=%+v lastPC=%+v", text.Code[:64],
					text.Code[len(text.Code)-16:], text.Relocations, text.Positions[0], text.Positions[len(text.Positions)-1])
				rows := strings.SplitN(string(observed.source.observation.Frames[ordinal].OriginalListing), "\n", 4)
				if len(rows) > 3 {
					rows = rows[:3]
				}
				t.Log(strings.Join(rows, "\n"))
			}
		}
		t.Fatal("complete original SDK split/DATA observation", err)
	}
	defer source.Close()
	fn, found := source.functions[request.PackagePath+".blockAVX2"]
	if !found || !fn.split || fn.prologue <= 0 || len(source.functions) != 2 {
		t.Fatal("complete SDK source lost its split frame or ordinary sibling")
	}
	expanded := source.sdkFrame.owner.source.observation.CPP[0].Output
	data, err := source.fixedLocalDataObservation(source.request.AssemblyFile, expanded)
	if err != nil {
		t.Fatal(err)
	}
	var text gostaticstorage.TextRecord
	for _, candidate := range data.Member.Texts {
		if candidate.Name == request.PackagePath+".blockAVX2" {
			text = candidate
		}
	}
	if len(text.Positions) == 0 || !strings.HasPrefix(text.Positions[0].File, "$GOROOT/") {
		t.Fatal("actual SDK object did not exercise captured-root source metadata")
	}
	tls, err := x86asm.Decode(text.Code, 64)
	if err != nil {
		t.Fatal(err)
	}
	lea, err := x86asm.Decode(text.Code[tls.Len:], 64)
	if err != nil || lea.Op != x86asm.LEA || lea.Len != 8 || lea.AddrSize != 64 {
		t.Fatal("actual SDK prologue lacks the original disp32 LEA", err)
	}
	for _, displacement := range []int32{-1 << 31, -417, -415, -129, -128, -1, 0, 127, 128, 1<<31 - 1} {
		t.Run(fmt.Sprintf("wrong displacement %d", displacement), func(t *testing.T) {
			changed := text
			changed.Code = append([]byte(nil), text.Code...)
			binary.LittleEndian.PutUint32(changed.Code[tls.Len+lea.Len-4:], uint32(displacement))
			changedFn := fn
			changedFn.code = changed.Code
			if _, err := goAMD64FrameSplitProjection(changedFn, changed, 536, request.Target, request.Directory, source.env["GOROOT"], data); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("wrong physical stack-check displacement was accepted", err)
			}
		})
	}
	for _, mutation := range []string{"empty root", "foreign root", "unclean metadata", "generated line"} {
		t.Run(mutation, func(t *testing.T) {
			changed, root := text, source.env["GOROOT"]
			changed.Positions = append([]gostaticstorage.TextPosition(nil), text.Positions...)
			switch mutation {
			case "empty root":
				root = ""
			case "foreign root":
				root = t.TempDir()
			case "unclean metadata":
				changed.Positions[0].File = strings.Replace(changed.Positions[0].File, "$GOROOT/", "$GOROOT/../", 1)
			case "generated line":
				changed.Positions[0].Line++
			}
			if _, err := goAMD64FrameSplitProjection(fn, changed, 536, request.Target, request.Directory, root, data); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("generated SDK region borrowed an unbound source position", err)
			}
		})
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("live complete SDK split/DATA observation", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("complete original SHA256 source observed; this is not a whole-file translation or execution result")
}

func TestGoAMD64FrameAutomaticSplitDataRelocationPartition(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			// Both private and ordinary references belong to this original body.
			// Capturing Global's address gives it no fixed-local read permission.
			assembly := fixedLocalLiteralData + `TEXT ·Value(SB),$160-16
MOVQ a+0(FP),AX
MOVQ AX,16(SP)
MOVQ $·Global(SB),BX
MOVQ literal<>(SB),CX
MOVQ 16(SP),AX
MOVQ AX,ret+8(FP)
RET
`
			pkg, request, _, _ := fixedLocalTransportFixture(t, assembly,
				"var Global uint64\nfunc Value(a uint64) uint64\n", target.name, target.triple)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			expanded, err := source.preprocess(request.AssemblyFile, []byte(assembly))
			if err != nil {
				t.Fatal(err)
			}
			data, err := source.fixedLocalDataObservation(request.AssemblyFile, expanded)
			if err != nil || len(data.Member.Texts) != 1 {
				t.Fatal("missing complete original object", err)
			}
			text, fn := data.Member.Texts[0], source.functions[pkg.Path+".Value"]
			if len(text.Relocations) != 4 || text.Relocations[1].Target.Name != pkg.Path+".Global" || text.Relocations[2].Target.ABI != 65535 {
				t.Fatal("actual Go object lacks both generated and body relocation roles")
			}
			shape, err := goAMD64FrameSplitProjection(fn, text, 160, request.Target, request.Directory, "", data)
			if err != nil {
				t.Fatal("complete unmodified generated/body relocation partition", err)
			}
			encoded, err := json.Marshal(text)
			if err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []string{
				"missing TLS", "missing morestack", "duplicate TLS", "duplicate morestack", "duplicate body", "reordered body",
				"DATA in prefix", "DATA in tail", "DATA crosses body end", "body call", "private index", "private ABI",
				"TLS ordinary fallback", "morestack ordinary fallback", "TLS field moved", "morestack field moved",
			} {
				t.Run(mutation, func(t *testing.T) {
					var changed gostaticstorage.TextRecord
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					relocations := changed.Relocations
					switch mutation {
					case "missing TLS":
						relocations = relocations[1:]
					case "missing morestack":
						relocations = relocations[:3]
					case "duplicate TLS":
						relocations = append([]gostaticstorage.TextRelocation{relocations[0]}, relocations...)
					case "duplicate morestack":
						relocations = append(relocations, relocations[3])
					case "duplicate body":
						relocations[2] = relocations[1]
					case "reordered body":
						relocations[1], relocations[2] = relocations[2], relocations[1]
					case "DATA in prefix":
						relocations[1].Offset = int64(shape.prologue - 4)
					case "DATA in tail":
						relocations[2].Offset = relocations[3].Offset + 4
					case "DATA crosses body end":
						relocations[2].Offset = int64(shape.prologue + len(shape.code) - 2)
					case "body call":
						relocations[1].Type, relocations[1].Target = relocations[3].Type, relocations[3].Target
					case "private index":
						relocations[2].Target.SymbolIndex++
					case "private ABI":
						relocations[2].Target.ABI = 0
					case "TLS ordinary fallback":
						relocations[0].Type, relocations[0].Target = relocations[1].Type, relocations[1].Target
						if goAMD64FrameDataRelocationLine(relocations[0], data) == "" {
							t.Fatal("mutation did not exercise ordinary R_PCREL fallback")
						}
					case "morestack ordinary fallback":
						relocations[3].Type, relocations[3].Target = relocations[1].Type, relocations[1].Target
					case "TLS field moved":
						relocations[0].Offset++
					case "morestack field moved":
						relocations[3].Offset++
					}
					changed.Relocations = relocations
					if _, err := goAMD64FrameSplitProjection(fn, changed, 160, request.Target, request.Directory, "", data); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed generated/body relocation roles were accepted", err)
					}
				})
			}
		})
	}
}
