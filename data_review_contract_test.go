package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestReviewDataSymbolExpressions(t *testing.T) {
	f, err := Parse(ArchARM64, "DATA example.com/a-b/pkg·tab+(4+4)(SB)/4, $1\nGLOBL example.com/a-b/pkg·tab+0(SB), DUPOK|RODATA, $16\n")
	if err != nil {
		t.Fatal(err)
	}
	if d := f.Data[0]; d.Sym != "example.com/a-b/pkg·tab" || d.Off != 8 || d.Width != 4 {
		t.Fatalf("got %+v", d)
	}
	for _, src := range []string{"DATA ·tab+(k+4)(SB)/8, $1", "GLOBL ·tab+(4+4)(SB), $16"} {
		if _, err := Parse(ArchARM64, src+"\n"); err == nil {
			t.Errorf("accepted %s", src)
		}
	}
	for _, annotate := range []bool{false, true} {
		ir, err := Translate(f, Options{AnnotateSource: annotate})
		if err != nil || !strings.Contains(ir, "weak constant") || strings.Contains(ir, "tab+(") {
			t.Fatalf("global: %v, %s", err, ir)
		}
	}
}

func TestReviewModuleEntryContracts(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT entry(SB),4,$0-0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	expired := errors.New("frame lease revoked")
	for _, annotate := range []bool{false, true} {
		opt := Options{AnnotateSource: annotate, Sigs: map[string]FuncSig{"entry": {Ret: Void, FrameLease: func() error { return expired }}}}
		if _, err := Translate(file, opt); !errors.Is(err, expired) {
			t.Errorf("annotate=%v: lease: %v", annotate, err)
		}
		opt.Sigs["entry"] = FuncSig{Ret: Void, Attrs: "noinline"}
		ir, err := Translate(file, opt)
		if err != nil || !strings.Contains(ir, "noinline") {
			t.Errorf("annotate=%v: attributes: %v %s", annotate, err, ir)
		}
		for _, bad := range []Options{{X87Mode: 255}, {WASMABI: 255}} {
			bad.Sigs = opt.Sigs
			bad.AnnotateSource = annotate
			if _, err := Translate(file, bad); err == nil {
				t.Errorf("accepted invalid options %+v", bad)
			}
		}
	}
}

func TestDataSymbolLinkageAcrossEmitters(t *testing.T) {
	file, err := Parse(ArchAMD64, "GLOBL dup(SB), DUPOK|RODATA, $8\nGLOBL hidden(SB), LOCAL, $8\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, annotate := range []bool{false, true} {
		ir, err := Translate(file, Options{AnnotateSource: annotate, ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, "@dup = weak constant") || !strings.Contains(ir, "@hidden = hidden global") {
			t.Fatalf("annotate=%v: %s", annotate, ir)
		}
	}
}

func TestTargetCPUSubtypes(t *testing.T) {
	for triple, want := range map[string]Arch{"arm64e-apple-darwin": ArchARM64, "X86_64H-apple-darwin": ArchAMD64} {
		if got := targetInstructionSet(triple); got != want {
			t.Errorf("%s: got %s want %s", triple, got, want)
		}
	}
}

func TestDataPointerWidthIsBoundAtTranslation(t *testing.T) {
	f, err := Parse(ArchAMD64, "DATA tab(SB)/PTRSIZE, $fn(SB)\nDATA num(SB)/PTRSIZE, $1.5\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64", "386"} {
		for _, annotate := range []bool{false, true} {
			ir, err := Translate(f, Options{Goarch: arch, AnnotateSource: annotate})
			if err != nil {
				t.Fatal(err)
			}
			wantPtr, wantFloat := "to i32)", `c"\00\00\C0?"`
			if arch == "amd64" {
				wantPtr, wantFloat = "to i64)", `c"\00\00\00\00\00\00\F8?"`
			}
			if !strings.Contains(ir, wantPtr) || !strings.Contains(ir, wantFloat) {
				t.Errorf("%s annotation=%t: missing %s or %s in %s", arch, annotate, wantPtr, wantFloat, ir)
			}
		}
	}
}

func TestWasmDataRelocationWidth(t *testing.T) {
	f, err := Parse(ArchWASM, "DATA tab(SB)/PTRSIZE, $fn(SB)\nGLOBL tab(SB), $8\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"", "wasm32", "wasm32-unknown-unknown", "wasm64-unknown-unknown"} {
		ir, err := Translate(f, Options{Goarch: "wasm", TargetTriple: triple})
		if err != nil {
			t.Fatal(err)
		}
		expect := "to i32)"
		if strings.HasPrefix(triple, "wasm64") {
			expect = "to i64)"
		}
		if !strings.Contains(ir, expect) {
			t.Errorf("triple %q: missing %s in %s", triple, expect, ir)
		}
	}
}

func TestGoModuleLinuxTLSRelocation(t *testing.T) {
	pkg := mustGoPackage(t, "p", "package p\nfunc getg() uintptr")
	src := []byte("TEXT ·getg(SB),4,$0-8\nMOVQ 0(TLS), AX\nMOVQ AX, ret+0(FP)\nRET")
	tr, err := TranslateGoModule(pkg, src, GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if ir := tr.Module.String(); !strings.Contains(ir, "@llvm.threadlocal.address.p0(ptr @runtime.tlsg)") {
		t.Fatalf("expected Go runtime TLS relocation in %s", ir)
	}
}

func TestTLSBSSEmulatedTargets(t *testing.T) {
	f, err := Parse(ArchARM64, "GLOBL slot(SB),TLSBSS,$8")
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-unknown-openbsd7.8", "aarch64-linux-android", "aarch64-linux-android28", "aarch64-unknown-linux-ohos"} {
		if _, err := Translate(f, Options{TargetTriple: triple}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: %v", triple, err)
		}
	}
	for _, triple := range []string{"aarch64-linux-android29", "aarch64-unknown-freebsd14", "aarch64-unknown-linux-gnu"} {
		ir, err := Translate(f, Options{TargetTriple: triple})
		if err != nil || !strings.Contains(ir, "thread_local(localexec)") {
			t.Errorf("%s: %v %s", triple, err, ir)
		}
	}
}

func TestWindowsRelativeBranchSkipsTLSExpansion(t *testing.T) {
	pkg := mustGoPackage(t, "p", "package p\nfunc get() uintptr")
	src := []byte("TEXT ·get(SB),4,$0-8\nMOVQ $17, AX\nCMPQ AX, AX\nJE 2(PC)\nMOVQ 0(TLS), AX\nMOVQ AX, ret+0(FP)\nRET")
	tr, err := TranslateGoModule(pkg, src, GoModuleOptions{GOOS: "windows", GOARCH: "amd64", TargetTriple: "x86_64-pc-windows-msvc"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if ir := runOptO2(t, tr.Module.String()); !strings.Contains(ir, "ret i64 17") {
		t.Fatalf("branch landed inside TLS expansion:\n%s", ir)
	}
}
