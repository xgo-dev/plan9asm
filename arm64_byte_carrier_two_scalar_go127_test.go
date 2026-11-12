//go:build go1.27

package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The second parameter is a real declared uint32, not permission to access its
// following gap. The assembly caller initializes that separate gap explicitly.
func arm64ByteCarrierTwoScalarFixture(t *testing.T, widths []arm64NativeResultTailCase) (string, string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packagePath := "example.invalid/twoscalarcarrier"
	var declarations, assembly strings.Builder
	declarations.WriteString("package twoscalarcarrier\n\n")
	for _, width := range widths {
		name := strings.ToLower(width.name())
		fmt.Fprintf(&declarations, "func %s(input uint64, spare uint32) (result uint%d)\n", name, width.resultBits)
		fmt.Fprintf(&declarations, "func observe_%s(input uint64) (value,native,guard,paramgap uint64)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\nMOVD input+0(FP),R0\n%s R0,result+16(FP)\nRET\n",
			name, 16+width.resultBits/8, width.op)
		fmt.Fprintf(&assembly, `
TEXT ·observe_%s(SB),4,$48-40
    MOVD input+0(FP),R0
    MOVD R0,8(RSP)
    MOVD $0xabad1dea00123456,R1
    MOVD R1,16(RSP)
    MOVD $0xfeedfacecafebeef,R1
    MOVD R1,24(RSP)
    MOVD $0x7ac35ef012345678,R1
    MOVD R1,32(RSP)
    CALL ·%s(SB)
    MOVD 24(RSP),R0
    MOVD R0,native+16(FP)
    %s 24(RSP),R0
    MOVD R0,value+8(FP)
    MOVD 32(RSP),R0
    MOVD R0,guard+24(FP)
    MOVD 16(RSP),R0
    MOVD R0,paramgap+32(FP)
    RET
`, name, name, map[int]string{8: "MOVBU", 16: "MOVHU", 32: "MOVWU"}[width.resultBits])
	}
	for name, data := range map[string]string{
		"go.mod":  "module " + packagePath + "\ngo 1.20\n",
		"decl.go": declarations.String(), "original_arm64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, packagePath
}

func TestARM64ByteCarrierTwoScalarActualEntryFootprint(t *testing.T) {
	widths := arm64NativeResultTailCases()
	directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, widths)
	lease, release := runtimeOracleStageContext(t)
	defer release()
	source, err := CaptureGoARM64ByteCarrierSource(lease, arm64ByteCarrierRequest(t, directory, packagePath))
	if err != nil {
		t.Fatalf("producer precondition: %v", err)
	}
	defer source.Close()
	for _, width := range widths {
		name := strings.ToLower(width.name())
		found := false
		for _, text := range source.report.Archive[1].Texts {
			if text.Name != packagePath+"."+name || text.ABI != 1 {
				continue
			}
			found = true
			entry, err := arm64ByteCarrierTypedEntry(text, source.declarations[name])
			if err != nil {
				t.Fatalf("actual two-parameter entry is not closed: %v; code=%x", err, text.Code)
			}
			if entry.allocation != 48 || entry.dataStart != 8 || entry.dataBytes != 32 ||
				entry.callPC != 20 || entry.continuationPC != 24 || len(entry.parameterStores) != 2 ||
				entry.parameterStores[0].Offset != 8 || entry.parameterStores[0].Bytes != 8 ||
				entry.parameterStores[1].Offset != 16 || entry.parameterStores[1].Bytes != 4 ||
				len(entry.resultLoads) != 1 || entry.resultLoads[0].Offset != 24 ||
				entry.resultLoads[0].Bytes != int64(width.resultBits/8) {
				t.Fatalf("actual compiler allocation, exact fields or continuation differ: %+v", entry)
			}
			t.Logf("actual ABI1 entry %s code=%x allocation=%d callPC=%d continuationPC=%d", name,
				text.Code, entry.allocation, entry.callPC, entry.continuationPC)
		}
		if !found {
			t.Fatal("original compiler entry is missing")
		}
	}
}

func TestARM64ByteCarrierTwoScalarEntryRejectsFabricatedFields(t *testing.T) {
	width := arm64NativeResultTailCase{op: "MOVD", resultBits: 32, storeBits: 64}
	directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, []arm64NativeResultTailCase{width})
	lease, release := runtimeOracleStageContext(t)
	defer release()
	source, err := CaptureGoARM64ByteCarrierSource(lease, arm64ByteCarrierRequest(t, directory, packagePath))
	if err != nil {
		t.Fatalf("producer precondition: %v", err)
	}
	defer source.Close()
	name := strings.ToLower(width.name())
	var original gostaticstorage.TextRecord
	for _, text := range source.report.Archive[1].Texts {
		if text.Name == packagePath+"."+name && text.ABI == 1 {
			original = text
		}
	}
	if _, err := arm64ByteCarrierTypedEntry(original, source.declarations[name]); err != nil {
		t.Fatalf("unchanged actual entry positive control failed: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*gostaticstorage.TextRecord, *FuncSig)
	}{
		{"second-store-missing", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[16:], 0xd503201f)
		}},
		{"second-store-wrong-register", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[16:], 0xb90013e0)
		}},
		{"second-store-authorizes-gap", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[16:], 0xf9000be1)
		}},
		{"second-store-in-gap", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[16:], 0xb90017e1)
		}},
		{"result-load-from-gap", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code[24:], 0xb94017e0)
		}},
		{"result-aliases-saved-FP", func(text *gostaticstorage.TextRecord, _ *FuncSig) {
			binary.LittleEndian.PutUint32(text.Code, 0xf81e0ffe)
		}},
		{"call-at-old-continuation", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Offset = 16 }},
		{"callee-ABI-not-zero", func(text *gostaticstorage.TextRecord, _ *FuncSig) { text.Relocations[0].Target.ABI = 1 }},
		{"second-argument-is-pointer", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Args[1] = Ptr }},
		{"second-argument-is-wide", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Args[1] = I64 }},
		{"second-field-is-gap", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Frame.Params[1].Offset = 12 }},
		{"second-field-wrong-index", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Frame.Params[1].Index = 0 }},
		{"gap-is-result", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Frame.Results[0].Offset = 12 }},
		{"native-tail-is-field", func(_ *gostaticstorage.TextRecord, signature *FuncSig) { signature.Frame.Results[0].Type = I64 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := original
			text.Code = append([]byte(nil), original.Code...)
			text.Relocations = append([]gostaticstorage.TextRelocation(nil), original.Relocations...)
			declaration := source.declarations[name]
			declaration.Args = append([]LLVMType(nil), declaration.Args...)
			declaration.Frame.Params = append([]FrameSlot(nil), declaration.Frame.Params...)
			declaration.Frame.Results = append([]FrameSlot(nil), declaration.Frame.Results...)
			test.mutate(&text, &declaration)
			if _, err := arm64ByteCarrierTypedEntry(text, declaration); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("fabricated two-scalar carrier entry accepted: %v", err)
			}
		})
	}
}

func TestARM64ByteCarrierTwoScalarActualSourceTargetMatrix(t *testing.T) {
	widths := arm64NativeResultTailCases()
	if len(widths) != 9 {
		t.Fatal("native-width family is incomplete")
	}
	directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, widths)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	lease, release := runtimeOracleStageContext(t)
	defer release()
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd", "openbsd"} {
		t.Run(goos, func(t *testing.T) {
			request := request
			request.Target = goos + "/arm64"
			request.Environment = append([]string(nil), request.Environment...)
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + goos
				}
			}
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatalf("producer precondition: %v", err)
			}
			defer source.Close()
			if len(source.report.Calls) != 9 || len(source.report.Standalone) != 18 {
				t.Fatal("original complete call/body inventory differs")
			}
			for _, width := range widths {
				name := strings.ToLower(width.name())
				declaration := source.declarations[name]
				if len(declaration.Frame.Params) != 2 || declaration.Frame.Params[0].Offset != 0 ||
					declaration.Frame.Params[1].Offset != 8 || declaration.Frame.Params[1].Type != I32 ||
					len(declaration.Frame.Results) != 1 || declaration.Frame.Results[0].Offset != 16 {
					t.Fatalf("actual two-scalar fields differ: %+v", declaration.Frame)
				}
			}
			if err := source.Verify(lease); err != nil {
				t.Fatal(err)
			}
			t.Log("actual producer complete: nine callees, nine same-file CALLs, FP0/8 parameters and FP16 result")
		})
	}
}

func TestARM64ByteCarrierTwoScalarNativeWidthConsumers(t *testing.T) {
	// Reuse immutable compiler artifacts, never a revocable source owner or
	// a case's original files, temporary outputs or command environment.
	buildCache := t.TempDir()
	for _, width := range arm64NativeResultTailCases() {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(width.name()+"/"+api, func(t *testing.T) {
				// A failed binding revokes its owner. Every case therefore captures
				// its own actual source; no earlier failure is reused as a RED.
				directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, []arm64NativeResultTailCase{width})
				lease, release := runtimeOracleStageContext(t)
				defer release()
				request := arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, buildCache)
				source, err := CaptureGoARM64ByteCarrierSource(lease, request)
				if err != nil {
					t.Fatalf("producer precondition, not consumer RED: %v", err)
				}
				defer source.Close()
				if len(source.report.Calls) != 1 {
					t.Fatal("original same-file native CALL is missing")
				}
				t.Log("actual producer reached P before consumer")
				goSource, err := os.ReadFile(filepath.Join(directory, "decl.go"))
				if err != nil {
					t.Fatal(err)
				}
				assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
				if err != nil {
					t.Fatal(err)
				}
				pkg := mustGoPackage(t, packagePath, string(goSource))
				ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), "aarch64-unknown-linux-gnu", nil)
				if err != nil {
					t.Fatalf("observed two-scalar native-width consumer failed: %v", err)
				}
				if !strings.Contains(ir, "(i64 %arg0, i32 %arg1)") || !strings.Contains(ir, "store volatile i32") {
					t.Fatal("typed second-parameter transport was omitted")
				}
			})
		}
	}
}

func TestARM64ByteCarrierTwoScalarConsumersRejectUndefinedBytes(t *testing.T) {
	// Only immutable Go build artifacts are shared. Each case still captures
	// its own original source, temporary outputs and revocable observation.
	buildCache := t.TempDir()
	width := arm64NativeResultTailCase{op: "MOVH", resultBits: 8, storeBits: 16}
	for _, test := range []struct {
		name, before, after string
	}{
		{"parameter-gap-is-not-defined", "MOVD R1,16(RSP)", "MOVW R1,16(RSP)"},
		{"native-result-tail-is-not-defined", "MOVD R1,24(RSP)", "MOVW R1,24(RSP)"},
		{"outgoing-input-is-not-defined", "MOVD R0,8(RSP)", "MOVW R0,8(RSP)"},
		{"saved-LR-is-not-data", "MOVD R0,paramgap+32(FP)", "MOVD R0,paramgap+32(FP)\n    MOVD R0,0(RSP)"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(test.name+"/"+api, func(t *testing.T) {
				directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, []arm64NativeResultTailCase{width})
				filename := filepath.Join(directory, "original_arm64.s")
				original, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				assembly := strings.Replace(string(original), test.before, test.after, 1)
				if assembly == string(original) {
					t.Fatal("negative did not change the actual source")
				}
				if err := os.WriteFile(filename, []byte(assembly), 0600); err != nil {
					t.Fatal(err)
				}
				lease, release := runtimeOracleStageContext(t)
				defer release()
				request := arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, buildCache)
				source, err := CaptureGoARM64ByteCarrierSource(lease, request)
				if err != nil {
					t.Fatalf("original producer precondition: %v", err)
				}
				defer source.Close()
				declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
				if err != nil {
					t.Fatal(err)
				}
				pkg := mustGoPackage(t, packagePath, string(declarations))
				ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, assembly, "aarch64-unknown-linux-gnu", nil)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("undefined or protected bytes granted output: %v", err)
				}
				if !errors.Is(source.Verify(lease), ErrProbeNeedsContext) {
					t.Fatal("failed byte proof did not revoke its original owner")
				}
			})
		}
	}
}

func TestARM64ByteCarrierTwoScalarFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	widths := append(arm64NativeResultTailCases(), arm64NativeResultTailCase{op: "MOVW", resultBits: 32, storeBits: 32})
	directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, widths)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	base := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, target := range []struct{ goos, triple string }{
		{"darwin", "aarch64-apple-darwin"}, {"linux", "aarch64-unknown-linux-gnu"},
		{"windows", "aarch64-pc-windows-msvc"}, {"freebsd", "aarch64-unknown-freebsd"},
		{"openbsd", "aarch64-unknown-openbsd"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			request := base
			request.Target = target.goos + "/arm64"
			request.Environment = append([]string(nil), base.Environment...)
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + target.goos
				}
			}
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatalf("original producer precondition: %v", err)
			}
			defer source.Close()
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), target.triple, nil)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "two-scalar.ll", "two-scalar.o", ir)
				})
			}
		})
	}
}
