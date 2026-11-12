package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86BackendMantissaSource(arch string) string {
	move, bytes, offset := "MOVQ", 16, 8
	if arch == "386" {
		move, bytes, offset = "MOVL", 8, 4
	}
	return fmt.Sprintf(`TEXT ·Probe(SB),4,$0-%d
%s out+0(FP),DI
%s input+%d(FP),SI
VMOVUPS (SI),Z0
VMOVUPS (SI),Z1
VGETMANTPS $0,X1,X0
VMOVUPS Z0,(DI)
RET
`, bytes, move, move, offset)
}

func TestTargetBackendX86IntrinsicPublicAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source := x86BackendMantissaSource(arch)
		x86LEAActualTargetGoObject(t, arch, map[string]string{"amd64": "x86_64-unknown-linux-gnu", "386": "i386-unknown-linux-gnu"}[arch], source)
		for _, triple := range []string{"arm64-apple-macosx", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+triple+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Probe(out,input *[64]byte)", arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "intrinsic") {
						t.Fatal("complete initialized function escaped its actual x86 intrinsic backend", len(ir), err)
					}
				})
			}
		}
	}
}

func TestTargetBackendPackedStringInitializedPublicAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		matching := testTargetTriple("linux", arch)
		for _, row := range go127PackedStringCompareSpecs() {
			source := "TEXT ·Probe(SB),4,$0-0\nPXOR X0,X0\nPXOR X1,X1\nMOVL $16,AX\nMOVL $16,DX\n" +
				row.op + " $8,X0,X1\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, triple := range []string{matching, "", "aarch64-unknown-linux-gnu"} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+row.op+"/"+triple+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Probe()", arch, triple, api)
						if triple == matching {
							if err != nil || !strings.Contains(ir, "call ") || !strings.Contains(ir, "@llvm.x86.sse42.pcmp") {
								t.Fatal("initialized packed-string family lost its explicit native target", err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "intrinsic") {
							t.Fatal("missing or mismatched target published initialized native-intrinsic IR", len(ir), err)
						}
					})
				}
			}
		}
	}
}

func TestTargetBackendX86IntrinsicDefaultModeAndModuleCleanup(t *testing.T) {
	source := x86BackendMantissaSource("amd64")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "backend", "package backend\nfunc Probe(out,input *[64]byte)\n")
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "amd64"} {
		for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			t.Run(mode+"/"+triple, func(t *testing.T) {
				options := Options{Goarch: mode, TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
				native := strings.HasPrefix(triple, "x86_64-")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				for attempt := 0; attempt < 3; attempt++ {
					module, err := TranslateModuleInContext(ctx, file, options)
					published := !module.IsNil()
					if published {
						module.Dispose()
					}
					if native {
						if err != nil || !published {
							t.Fatal("default source mode lost its explicit matching target", err)
						}
					} else if published || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "intrinsic") {
						t.Fatal("rejected backend published a module or lost its error", err)
					}
				}
				text, err := Translate(file, options)
				if native && (text == "" || err != nil) || !native && (text != "" || !errors.Is(err, ErrProbeNeedsContext)) {
					t.Fatal("text and owned-module target boundaries disagree", len(text), err)
				}
			})
		}
	}
	// The public completion guard also wraps the direct-module early return.
	// An x86 source alone must not constrain a genuinely portable module.
	for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run("direct-portable/"+triple, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT portable(SB),4,$0-0\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			options := Options{TargetTriple: triple, Sigs: map[string]FuncSig{"portable": {Name: "portable", Ret: Void}}}
			for _, translate := range []func(llvm.Context, *File, Options) (llvm.Module, error){
				translateModuleDirectInContext, TranslateModuleInContext,
			} {
				module, err := translate(ctx, file, options)
				published := !module.IsNil()
				if published {
					module.Dispose()
				}
				if err != nil || !published {
					t.Fatal("portable early module return acquired a native backend restriction", err)
				}
			}
		})
	}
}

func TestTargetBackendX86IntrinsicNamespaceAndUses(t *testing.T) {
	for _, row := range []struct {
		name, declaration, call string
		x86Intrinsic            bool
	}{
		{"llvm.x86.sse.stmxcsr", "declare void @llvm.x86.sse.stmxcsr(ptr)", "call void @llvm.x86.sse.stmxcsr(ptr null)", true},
		{"llvm.x86.sse.ldmxcsr", "declare void @llvm.x86.sse.ldmxcsr(ptr)", "call void @llvm.x86.sse.ldmxcsr(ptr null)", true},
		{"llvm.x86.sse.rcp.ps", "declare <4 x float> @llvm.x86.sse.rcp.ps(<4 x float>)", "%v = call <4 x float> @llvm.x86.sse.rcp.ps(<4 x float> zeroinitializer)", true},
		{"llvm.x86.sha1msg1", "declare <4 x i32> @llvm.x86.sha1msg1(<4 x i32>,<4 x i32>)", "%v = call <4 x i32> @llvm.x86.sha1msg1(<4 x i32> zeroinitializer,<4 x i32> zeroinitializer)", true},
		{"llvm.x86.application.helper", "declare void @llvm.x86.application.helper()", "call void @llvm.x86.application.helper()", false},
		{"application.llvm.x86.sse.stmxcsr", "declare void @application.llvm.x86.sse.stmxcsr()", "call void @application.llvm.x86.sse.stmxcsr()", false},
		{"llvm.ctpop.i64", "declare i64 @llvm.ctpop.i64(i64)", "%v = call i64 @llvm.ctpop.i64(i64 7)", false},
	} {
		for _, used := range []bool{false, true} {
			for _, target := range []struct{ mode, triple string }{
				{"amd64", "x86_64-unknown-linux-gnu"}, {"386", "i386-unknown-linux-gnu"},
				{"386", "i686-pc-windows-msvc"}, {"amd64", "aarch64-unknown-linux-gnu"},
				{"amd64", "wasm32-unknown-unknown"}, {"amd64", ""}, {"386", "x86_64-unknown-linux-gnu"},
			} {
				t.Run(fmt.Sprintf("%s/used%t/%s/%s", row.name, used, target.mode, target.triple), func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					call := ""
					if used {
						call = row.call
					}
					module, err := parseIRModuleInContext(ctx, fmt.Sprintf("target triple = %q\n%s\ndefine void @caller() {\n%s\nret void\n}\n", target.triple, row.declaration, call))
					if err != nil {
						t.Fatal(err)
					}
					defer module.Dispose()
					function := module.NamedFunction(row.name)
					if function.IsNil() || row.x86Intrinsic && function.IntrinsicID() == 0 || strings.Contains(row.name, "application") && function.IntrinsicID() != 0 {
						t.Fatal("LLVM intrinsic identity assumption changed", row.name)
					}
					err = validateTranslatedBackend(&File{Arch: ArchAMD64}, Options{Goarch: target.mode}, module)
					wantReject := used && row.x86Intrinsic && !x86ScalarFloatIntegerNativeTarget(target.mode, target.triple)
					if (row.name == "llvm.x86.sse.ldmxcsr" || row.name == "llvm.x86.sse.stmxcsr") &&
						strings.HasPrefix(target.triple, "x86_64-") {
						wantReject = false // The i32 MXCSR memory operand is independent of source pointer width.
					}
					if wantReject != errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("intrinsic identity/use or source/backend mode classification changed", wantReject, err)
					}
				})
			}
		}
	}
}

func TestTargetBackendMXCSRWidthIndependentIntrinsicBoundary(t *testing.T) {
	for _, row := range []struct {
		name, declaration, call string
		widthIndependent        bool
	}{
		{"llvm.x86.sse.ldmxcsr", "declare void @llvm.x86.sse.ldmxcsr(ptr)", "call void @llvm.x86.sse.ldmxcsr(ptr null)", true},
		{"llvm.x86.sse.stmxcsr", "declare void @llvm.x86.sse.stmxcsr(ptr)", "call void @llvm.x86.sse.stmxcsr(ptr null)", true},
		{"llvm.x86.rdrand.64", "declare {i64,i32} @llvm.x86.rdrand.64()", "%random = call {i64,i32} @llvm.x86.rdrand.64()", false},
		{"llvm.x86.rdseed.64", "declare {i64,i32} @llvm.x86.rdseed.64()", "%random = call {i64,i32} @llvm.x86.rdseed.64()", false},
	} {
		for _, triple := range []string{
			"x86_64-unknown-linux-gnu", "i386-unknown-linux-gnu", "i686-pc-windows-msvc",
			"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", "",
		} {
			for _, used := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/used%t", row.name, triple, used), func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					body := ""
					if used {
						body = row.call
					}
					module, err := parseIRModuleInContext(ctx, fmt.Sprintf("target triple = %q\n%s\ndefine void @caller() {\n%s\nret void\n}\n", triple, row.declaration, body))
					if err != nil {
						t.Fatal(err)
					}
					defer module.Dispose()
					if module.NamedFunction(row.name).IntrinsicID() == 0 {
						t.Fatal("mode boundary fixture is not an actual LLVM intrinsic")
					}
					err = validateTranslatedBackend(&File{Arch: ArchAMD64}, Options{Goarch: "amd64"}, module)
					native := triple == "x86_64-unknown-linux-gnu" || row.widthIndependent &&
						(triple == "i386-unknown-linux-gnu" || triple == "i686-pc-windows-msvc")
					if wantReject := used && !native; wantReject != errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("MXCSR width independence changed another intrinsic's mode boundary", wantReject, err)
					}
				})
			}
		}
	}
}
