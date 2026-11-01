//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func x86TLSMoveSourceFixture(t *testing.T, target string, shared bool, declaration, body string) (GoPackage, *File, Options, []byte, GoX86TLSMoveCaptureRequest) {
	t.Helper()
	_, frame := goAMD64FrameSourceFixture(t)
	goos, arch, _ := strings.Cut(target, "/")
	pkg, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, body)
	if err := os.WriteFile(filepath.Join(frame.Directory, frame.AssemblyFile), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, entry := range frame.Environment {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	for key, value := range map[string]string{"GOOS": goos, "GOARCH": arch, "GOAMD64": "v1", "GO386": "sse2",
		"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": ""} {
		values[key] = value
	}
	temporary, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	values["TMPDIR"], values["GOTMPDIR"] = temporary, temporary
	var environment []string
	for key, value := range values {
		environment = append(environment, key+"="+value)
	}
	options := Options{Goarch: arch, TargetTriple: x86TLSExpectedTriple(target), Sigs: map[string]FuncSig{"Value": sig},
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
	return pkg, file, options, []byte(source), GoX86TLSMoveCaptureRequest{GoBinary: frame.GoBinary, Directory: frame.Directory,
		PackagePath: pkg.Path, AssemblyFile: frame.AssemblyFile, Target: target, Shared: shared, Environment: environment}
}

func x86TLSMoveBoundAPI(t *testing.T, pkg GoPackage, file *File, source []byte, options Options, api string) (string, error) {
	t.Helper()
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "module" {
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
			return module.String(), err
		}
		return "", err
	}
	goos, _, _ := strings.Cut(options.X86TLSMoves.source.request.Target, "/")
	module, err := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{GOOS: goos, GOARCH: options.Goarch,
		TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym, X86TLSMoves: options.X86TLSMoves})
	if module != nil && !module.Module.IsNil() {
		defer module.Module.Dispose()
		return module.Module.String(), err
	}
	return "", err
}

func TestGoX86TLSMoveActualNOPBindingThreeAPIsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "freebsd/386"} {
		t.Run(target, func(t *testing.T) {
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, target, false, "func Value(a uint32) uint32",
				"MOVL a+0(FP),CX\nMOVL TLS,CX\nMOVQ TLS,CX\nMOVD TLS,CX\nMOVDQ2Q TLS,CX\nMOVL CX,ret+8(FP)\nRET")
			if options.Goarch == "386" {
				original = bytes.ReplaceAll(original, []byte("ret+8"), []byte("ret+4"))
				var err error
				file, err = Parse(ArchAMD64, string(original))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unbound public source acquired TLS permission: %v", err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := observed.Close(); err != nil {
					t.Error(err)
				}
			}()
			if len(observed.noops) != 4 {
				t.Fatalf("native direct-TLS rewrite inventory: %+v", observed.noops)
			}
			bound, err := observed.BindTLSMoves(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := x86CallerSourceFingerprint(file)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api)
				if err != nil {
					t.Fatal(api, err)
				}
				if strings.Contains(ir, "reg_TLS") || strings.Contains(ir, "runtime.tls_g") {
					t.Fatalf("NOP invented native TLS state: %s", ir)
				}
				x86ResultInitializationObject(t, llc, bound.TargetTriple, ir, api)
			}
			after, _ := x86CallerSourceFingerprint(file)
			if before != after {
				t.Fatal("consumer mutated the original source")
			}
		})
	}
}

func TestGoX86TLSMoveActualProfilesRemainDistinct(t *testing.T) {
	for _, profile := range []struct {
		target string
		shared bool
	}{
		{"linux/amd64", false}, {"linux/amd64", true}, {"darwin/amd64", true},
		{"freebsd/amd64", false}, {"freebsd/amd64", true}, {"freebsd/386", true},
		{"android/amd64", false}, {"android/386", false}, {"solaris/amd64", false},
		{"plan9/amd64", false}, {"plan9/386", false},
		{"windows/amd64", false}, {"linux/386", false}, {"linux/386", true}, {"windows/386", false},
	} {
		t.Run(fmt.Sprintf("%s/shared=%v", profile.target, profile.shared), func(t *testing.T) {
			_, file, options, _, request := x86TLSMoveSourceFixture(t, profile.target, profile.shared, "func Value() uint32",
				"MOVL $1,AX\nMOVQ TLS,CX\nMOVL AX,ret+0(FP)\nRET")
			if options.Goarch == "386" {
				original, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
				if err != nil {
					t.Fatal(err)
				}
				original = bytes.ReplaceAll(original, []byte("MOVQ TLS"), []byte("MOVL TLS"))
				file, err = Parse(ArchAMD64, string(original))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			_, err = observed.BindTLSMoves(ctx, file, options)
			wantNOP := (profile.target == "linux/amd64" || profile.target == "freebsd/amd64") && !profile.shared ||
				profile.target == "darwin/amd64" || profile.target == "freebsd/386"
			if (len(observed.noops) != 0) != wantNOP {
				t.Fatalf("original Go TLS source effect confused profile: noops=%+v", observed.noops)
			}
			if wantNOP && err != nil || !wantNOP && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("actual native rewrite confused profile: %v; noops=%+v", err, observed.noops)
			}
			for _, text := range observed.texts[0] {
				t.Logf("original %s shared=%v code=%x relocations=%+v", profile.target, profile.shared, text.Code, text.Relocations)
			}
		})
	}
}

func TestGoX86TLSMoveNOPPreservesUnknownResultBytes(t *testing.T) {
	for _, body := range []string{
		"MOVQ TLS,AX\nMOVL AX,ret+0(FP)\nRET",
		"MOVB $1,AL\nMOVL TLS,AX\nMOVL AX,ret+0(FP)\nRET",
		"MOVQ TLS,AX\nCMPL AX,$0\nSETEQ AL\nMOVL AX,ret+0(FP)\nRET",
	} {
		t.Run(body, func(t *testing.T) {
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, "linux/amd64", false, "func Value() uint32", body)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			bound, err := observed.BindTLSMoves(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("%s NOP initialized unknown GP bytes: %v\n%s", api, err, ir)
				}
			}
		})
	}
}

func TestGoX86TLSMoveSourceMutationAndCloseRevoke(t *testing.T) {
	for _, mutation := range []string{"source", "shared", "object", "close"} {
		t.Run(mutation, func(t *testing.T) {
			_, file, options, original, request := x86TLSMoveSourceFixture(t, "linux/amd64", false,
				"func Value() uint32", "MOVL $7,AX\nMOVQ TLS,AX\nMOVL AX,ret+0(FP)\nRET")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			bound, err := observed.BindTLSMoves(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "source":
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), append(original, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "shared":
				observed.request.Shared = true
			case "object":
				observed.objects[0][len(observed.objects[0])-1] ^= 1
			case "close":
				if err := observed.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ir, err := Translate(file, bound)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("revoked NOP observation escaped: %v\n%s", err, ir)
			}
			if mutation == "source" {
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), original, 0600); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(observed.Verify(context.Background()), ErrProbeNeedsContext) {
					t.Fatal("restored source revived revoked observation")
				}
			}
		})
	}
}

func TestGoX86TLSMoveNOPCompleteSourceRegisterRange(t *testing.T) {
	for _, target := range []string{"linux/amd64", "freebsd/386"} {
		t.Run(target, func(t *testing.T) {
			var body strings.Builder
			for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q"} {
				for _, register := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
					fmt.Fprintf(&body, "%s TLS,%s\n", op, register)
				}
			}
			body.WriteString("RET")
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, target, false, "func Value()", body.String())
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			if len(observed.noops) != 64 || !bytes.Equal(observed.texts[0][0].Code, []byte{0xc3}) {
				t.Fatalf("complete native NOP register range changed: noops=%d native=%x", len(observed.noops), observed.texts[0][0].Code)
			}
			bound, err := observed.BindTLSMoves(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api); err != nil {
					t.Fatal(api, err)
				}
			}
		})
	}
}

func TestGoX86TLSMoveOriginalCPPJoinAndRevocation(t *testing.T) {
	pkg, _, options, original, request := x86TLSMoveSourceFixture(t, "linux/amd64", false, "func Value() uint32",
		"MOVL $7,AX\nget_tls(AX)\nMOVL AX,ret+0(FP)\nRET")
	original = append([]byte("#include \"tls.h\"\n"), original...)
	for name, data := range map[string][]byte{
		request.AssemblyFile: original,
		"tls.h":              []byte("#define get_tls(r) MOVL TLS,r\n"),
	} {
		if err := os.WriteFile(filepath.Join(request.Directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	observed, err := CaptureGoX86TLSMoveSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	expanded, err := observed.AssemblySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := observed.BindTLSMoves(ctx, file, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		if _, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api); err != nil {
			t.Fatal(api, err)
		}
	}
	if err := os.WriteFile(filepath.Join(request.Directory, "tls.h"), []byte("#define get_tls(r) MOVQ TLS,r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if ir, err := Translate(file, bound); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
		t.Fatalf("changed original include revived an equivalent NOP rewrite: %v\n%s", err, ir)
	}
}

func TestGoX86TLSMoveConsumerCallbacksAndCopiedTokensFailClosed(t *testing.T) {
	for _, mutation := range []string{"close-callback", "source-callback", "file-callback", "target", "copy", "json"} {
		t.Run(mutation, func(t *testing.T) {
			_, file, options, original, request := x86TLSMoveSourceFixture(t, "linux/amd64", false,
				"func Value() uint32", "MOVL $7,AX\nMOVQ TLS,AX\nMOVL AX,ret+0(FP)\nRET")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			bound, err := observed.BindTLSMoves(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "close-callback", "source-callback", "file-callback":
				bound.ResolveSym = func(symbol string) string {
					switch mutation {
					case "close-callback":
						if err := observed.Close(); err != nil {
							t.Error(err)
						}
					case "source-callback":
						if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), append(original, '\n'), 0600); err != nil {
							t.Error(err)
						}
					case "file-callback":
						file.Funcs[0].Instrs[1].Args[0].Imm = 9
					}
					return strings.TrimPrefix(symbol, "·")
				}
			case "target":
				bound.TargetTriple = "x86_64-pc-windows-msvc"
			case "copy":
				copy := *bound.X86TLSMoves
				bound.X86TLSMoves = &copy
			case "json":
				encoded, err := json.Marshal(bound.X86TLSMoves)
				if err != nil {
					t.Fatal(err)
				}
				var restored GoX86TLSMoveBinding
				if err := json.Unmarshal(encoded, &restored); err != nil {
					t.Fatal(err)
				}
				bound.X86TLSMoves = &restored
			}
			if ir, err := Translate(file, bound); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("changed consumer generation emitted IR: %v\n%s", err, ir)
			}
		})
	}
}
