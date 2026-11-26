package main

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestToPlan9Arch(t *testing.T) {
	if got, err := toPlan9Arch("386"); err != nil || got != plan9asm.ArchAMD64 {
		t.Fatalf("toPlan9Arch(386) = (%q, %v)", got, err)
	}
	if got, err := toPlan9Arch("amd64"); err != nil || got != plan9asm.ArchAMD64 {
		t.Fatalf("toPlan9Arch(amd64) = (%q, %v)", got, err)
	}
	if got, err := toPlan9Arch("arm"); err != nil || got != plan9asm.ArchARM {
		t.Fatalf("toPlan9Arch(arm) = (%q, %v)", got, err)
	}
	if got, err := toPlan9Arch("arm64"); err != nil || got != plan9asm.ArchARM64 {
		t.Fatalf("toPlan9Arch(arm64) = (%q, %v)", got, err)
	}
	if got, err := toPlan9Arch("wasm"); err != nil || got != plan9asm.ArchWASM {
		t.Fatalf("toPlan9Arch(wasm) = (%q, %v)", got, err)
	}
}

func TestValidateCorpusTarget(t *testing.T) {
	for _, test := range []struct {
		corpus string
		goarch string
	}{
		{corpus: "std", goarch: "wasm"},
		{corpus: "go-asm", goarch: "amd64"},
		{corpus: "go-asm", goarch: "wasm"},
		{corpus: "arm64-plan9", goarch: "arm64"},
	} {
		if err := validateCorpusTarget(test.corpus, test.goarch); err != nil {
			t.Fatalf("validateCorpusTarget(%q, %q) = %v", test.corpus, test.goarch, err)
		}
	}
	if err := validateCorpusTarget("arm64-plan9", "amd64"); err == nil || !strings.Contains(err.Error(), "requires -goarch arm64") {
		t.Fatalf("validateCorpusTarget(arm64-plan9, amd64) = %v", err)
	}
}

func TestScanARM64Plan9Cases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan9cases.txt")
	src := "00000000| BFI $8, R1, $16, R2\ninvalid line\n00000000| RET\n00000000| BFI [Z22.B-Z23.B]\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ops, forms, parseErrs, files, err := scanARM64Plan9Cases(path)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 || ops["BFI"].Count != 2 || len(forms) != 2 || len(parseErrs) != 0 {
		t.Fatalf("scanARM64Plan9Cases() = ops=%#v forms=%#v parseErrs=%#v files=%d", ops, forms, parseErrs, files)
	}
}

func TestNormalizeOpAndDirectiveHelpers(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "movd", want: "MOVD"},
		{in: "b.eq", want: "B"},
		{in: " foo ", want: "FOO"},
		{in: "CALL*", want: ""},
		{in: "foo_bar", want: ""},
	}
	for _, tc := range cases {
		if got := normalizeOp(tc.in); got != tc.want {
			t.Fatalf("normalizeOp(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if !isDirective("TEXT") || !isDirective("DATA") {
		t.Fatalf("expected directive recognition")
	}
	if isDirective("MOVD") {
		t.Fatalf("MOVD should not be a directive")
	}
}

func TestClusterOfAndTopFiles(t *testing.T) {
	if got := clusterOf("386", "CALL"); got != "x86-control" {
		t.Fatalf("clusterOf 386 CALL = %q", got)
	}
	if got := clusterOf("amd64", "CALL"); got != "x86-control" {
		t.Fatalf("clusterOf amd64 CALL = %q", got)
	}
	if got := clusterOf("amd64", "VPXOR"); got != "x86-simd" {
		t.Fatalf("clusterOf amd64 VPXOR = %q", got)
	}
	if got := clusterOf("arm64", "BL"); got != "arm64-control" {
		t.Fatalf("clusterOf arm64 BL = %q", got)
	}
	if got := clusterOf("arm64", "CASAL"); got != "arm64-atomic" {
		t.Fatalf("clusterOf arm64 CASAL = %q", got)
	}
	if got := clusterOf("arm64", "VADD"); got != "arm64-neon" {
		t.Fatalf("clusterOf arm64 VADD = %q", got)
	}
	if got := clusterOf("other", "MOV"); got != "other" {
		t.Fatalf("clusterOf other MOV = %q", got)
	}

	got := topFiles(map[string]int{
		"b.s": 3,
		"c.s": 3,
		"a.s": 5,
	}, 2)
	if len(got) != 2 || got[0] != "a.s" || got[1] != "b.s" {
		t.Fatalf("topFiles = %#v", got)
	}
}

func TestShortStdPath(t *testing.T) {
	goroot := runtime.GOROOT()
	if goroot == "" {
		t.Skip("GOROOT not available")
	}

	inRoot := filepath.Join(goroot, "src", "runtime", "sys_arm64.s")
	if got := shortStdPath(inRoot); got != "runtime/sys_arm64.s" {
		t.Fatalf("shortStdPath(inRoot) = %q", got)
	}

	outside := filepath.Join(t.TempDir(), "local.s")
	if got := shortStdPath(outside); got != filepath.ToSlash(outside) {
		t.Fatalf("shortStdPath(outside) = %q", got)
	}
}

func TestExtractSupportedOpsScansRepoRoot(t *testing.T) {
	dir := t.TempDir()
	src := `package plan9asm

func lower(op string) {
	switch op {
	case "VPXORQ", "VMOVDQU64", "AESENC":
	}
}

func lowerOp(op any) {
	switch op {
	case OpMOVQ, OpRET:
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "amd64_lower_vec.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	supported, err := extractSupportedOps(dir, "amd64")
	if err != nil {
		t.Fatalf("extractSupportedOps: %v", err)
	}
	want := []string{"VPXORQ", "VMOVDQU64", "AESENC", "MOVQ", "RET"}
	got := make([]string, 0, len(want))
	for _, op := range want {
		if _, ok := supported[op]; ok {
			got = append(got, op)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("supported ops = %#v, want %#v", got, want)
	}
	supported386, err := extractSupportedOps(dir, "386")
	if err != nil {
		t.Fatalf("extractSupportedOps(386): %v", err)
	}
	for _, op := range want {
		if _, ok := supported386[op]; !ok {
			t.Fatalf("386 supported ops missing shared x86 %s: %v", op, supported386)
		}
	}
}

func TestFamilyOfAMD64(t *testing.T) {
	cases := map[string]string{
		"VPXORQ":         "avx-vector",
		"VGF2P8AFFINEQB": "gfni",
		"KMOVQ":          "avx512-mask",
		"AESENCLAST":     "aes",
		"SHA1MSG1":       "sha",
		"RORXQ":          "bmi2-adx",
		"JEQ":            "branch-alias",
		"MOVOA":          "sse-simd",
		"MOVLQZX":        "move-pseudo",
		"XADDQ":          "atomic-memory",
	}
	for op, want := range cases {
		if got := familyOf("amd64", op); got != want {
			t.Fatalf("familyOf(%q) = %q, want %q", op, got, want)
		}
	}
}

func TestListStdPackages(t *testing.T) {
	pkgs, err := listStdPackages(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("listStdPackages() error = %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("listStdPackages() returned no packages")
	}
	foundRuntime := false
	for _, p := range pkgs {
		if p.ImportPath == "runtime" {
			foundRuntime = true
			break
		}
	}
	if !foundRuntime {
		t.Fatalf("listStdPackages() missing runtime package")
	}
}

func TestListStdPackagesAtGOROOT(t *testing.T) {
	pkgs, err := listStdPackagesAtGOROOT(runtime.GOOS, runtime.GOARCH, runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("listStdPackagesAtGOROOT returned no packages")
	}
	if _, err := listStdPackagesAtGOROOT("js", "wasm", t.TempDir()); err == nil || !strings.Contains(err.Error(), "Go command for GOROOT") {
		t.Fatalf("missing Go command error = %v", err)
	}
}

func TestListStdPackagesIgnoresDiagnostics(t *testing.T) {
	dir := t.TempDir()
	name := "go"
	script := "#!/bin/sh\nif [ \"$CGO_ENABLED\" != 0 ]; then echo cgo must be disabled >&2; exit 1; fi\necho warning from fake go >&2\nprintf '%s\\n' '{\"ImportPath\":\"runtime\"}'\n"
	if runtime.GOOS == "windows" {
		name = "go.cmd"
		script = "@echo off\r\nif not \"%CGO_ENABLED%\"==\"0\" exit /b 1\r\necho warning from fake go 1>&2\r\necho {\"ImportPath\":\"runtime\"}\r\n"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pkgs, err := listStdPackages("linux", "amd64")
	if err != nil {
		t.Fatalf("listStdPackages() error = %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].ImportPath != "runtime" {
		t.Fatalf("listStdPackages() = %#v, want one runtime package", pkgs)
	}
}

func TestPackageSFilesAndAddOpStat(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(t.TempDir(), "abs", "c.s")
	pkg := pkgJSON{
		ImportPath: "example/p",
		Dir:        dir,
		SFiles:     []string{"a.s", "b.S", abs},
	}
	got := packageSFiles(pkg)
	want := []string{filepath.Join(dir, "a.s"), abs}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageSFiles() = %#v, want %#v", got, want)
	}

	ops := map[string]*opStat{}
	addOpStat(ops, "MOVD", "a.s", "example/p", 2)
	addOpStat(ops, "bad*", "a.s", "example/p", 2)
	addOpStat(ops, "RET", "a.s", "example/p", 1)
	addOpStat(ops, "MOVD", "a.s", "example/p", 0)
	if got := ops["MOVD"].Count; got != 2 {
		t.Fatalf("MOVD count = %d, want 2", got)
	}
	if got := ops["RET"].Count; got != 1 {
		t.Fatalf("RET count = %d, want 1", got)
	}
	if _, ok := ops["BAD"]; ok {
		t.Fatalf("invalid op unexpectedly added")
	}
}

func TestScanPackagesAndBuildReport(t *testing.T) {
	dir := t.TempDir()
	good := `TEXT ·f(SB),NOSPLIT,$0-0
	MOVQ $1, AX
	NOP
	RET
`
	bad := `DATA foo(SB), $1
`
	dataOnly := `TEXT ·datafn(SB),NOSPLIT,$0-0
	RET
DATA foo+0(SB)/8, $1
GLOBL foo(SB), RODATA, $8
`
	if err := os.WriteFile(filepath.Join(dir, "good.s"), []byte(good), 0o644); err != nil {
		t.Fatalf("write good.s: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.s"), []byte(bad), 0o644); err != nil {
		t.Fatalf("write bad.s: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.s"), []byte(dataOnly), 0o644); err != nil {
		t.Fatalf("write data.s: %v", err)
	}

	pkgs := []pkgJSON{{
		ImportPath: "example/p",
		Dir:        dir,
		SFiles:     []string{"good.s", "bad.s", "data.s"},
	}}
	ops, forms, parseErrs, pkgsWithS, asmFiles, err := scanPackages(pkgs, plan9asm.ArchAMD64, "amd64")
	if err != nil {
		t.Fatalf("scanPackages() error = %v", err)
	}
	if pkgsWithS != 1 {
		t.Fatalf("pkgWithSFiles = %d, want 1", pkgsWithS)
	}
	if asmFiles != 3 {
		t.Fatalf("asmFiles = %d, want 3", asmFiles)
	}
	if len(parseErrs) != 1 {
		t.Fatalf("parseErrs = %#v, want 1 entry", parseErrs)
	}
	for _, op := range []string{"MOVQ", "NOP", "RET", "DATA", "GLOBL"} {
		if _, ok := ops[op]; !ok {
			t.Fatalf("scanPackages() missing %q in ops %#v", op, ops)
		}
	}

	rep := buildReport("std", "go1.test", "linux", "amd64", 10, pkgsWithS, asmFiles, ops, forms, map[string]struct{}{
		"RET":  {},
		"MOVQ": {},
	}, nil, map[string]struct{}{
		"amd64\x00MOVQ immediate,gpr64": {},
	}, map[string]struct{}{}, parseErrs)
	if rep.Goos != "linux" || rep.Goarch != "amd64" {
		t.Fatalf("buildReport() wrong target: %#v", rep)
	}
	if rep.ParseErrCount != 1 || len(rep.ParseErrs) != 1 {
		t.Fatalf("buildReport() parse errs = %#v", rep.ParseErrs)
	}
	if len(rep.Unsupported) == 0 {
		t.Fatalf("buildReport() expected unsupported ops for NOP")
	}
	if len(rep.ClusterStats) == 0 || len(rep.FamilyStats) == 0 {
		t.Fatalf("buildReport() expected cluster/family stats")
	}
	if rep.RuntimeVerifiedForms != 1 || rep.ManifestExecuteForms != 1 || rep.DiffVerifiedForms != 0 || rep.DiffReportLoaded || rep.IRGeneratedForms != rep.SupportedForms {
		t.Fatalf("metrics mismatch without diff report: runtime=%d manifest=%d diff=%d loaded=%v ir=%d supported=%d",
			rep.RuntimeVerifiedForms, rep.ManifestExecuteForms, rep.DiffVerifiedForms, rep.DiffReportLoaded, rep.IRGeneratedForms, rep.SupportedForms)
	}
	attachManifestHWFeatures(&rep, map[string][]string{"amd64\x00MOVQ immediate,gpr64": {"sse4.2"}})
	if rep.ManifestHWGatedForms != 1 || rep.HWPendingForms != 0 {
		t.Fatalf("static manifest hw_gated=%d hw_pending=%d, want 1 and 0 before diff report", rep.ManifestHWGatedForms, rep.HWPendingForms)
	}
	if err := attachDiffExecutionReport(&rep, &diffExecutionReport{
		SchemaVersion:   1,
		Goarch:          "amd64",
		NativeOracleRan: true,
		ComparedInputs:  7,
		Cases: []diffCaseExecResult{
			{
				ID:                "case-pending",
				Status:            "hw_pending",
				MissingHWFeatures: []string{"sse4.2"},
				Forms:             []string{"MOVQ immediate,gpr64"},
			},
		},
	}); err != nil {
		t.Fatalf("attachDiffExecutionReport(hw_pending): %v", err)
	}
	if !rep.DiffReportLoaded || rep.DiffVerifiedForms != 0 || rep.HWPendingForms != 1 || len(rep.HWPendingByForm) != 1 {
		t.Fatalf("after hw_pending diff report: loaded=%v diff=%d pending=%d (%#v)", rep.DiffReportLoaded, rep.DiffVerifiedForms, rep.HWPendingForms, rep.HWPendingByForm)
	}
	if err := attachDiffExecutionReport(&rep, &diffExecutionReport{
		SchemaVersion:   1,
		Goarch:          "amd64",
		NativeOracleRan: true,
		ComparedInputs:  7,
		Cases: []diffCaseExecResult{
			{
				ID:             "case-pass",
				Status:         "passed",
				ExecutedInputs: 7,
				ComparedInputs: 7,
				Forms:          []string{"MOVQ immediate,gpr64"},
			},
		},
	}); err != nil {
		t.Fatalf("attachDiffExecutionReport(passed): %v", err)
	}
	if rep.DiffVerifiedForms != 1 || rep.HWPendingForms != 0 {
		t.Fatalf("after passed diff report: diff=%d pending=%d, want 1 and 0", rep.DiffVerifiedForms, rep.HWPendingForms)
	}
	attachObjectCompilation(&rep, map[string]bool{"MOVQ immediate,gpr64": true}, nil, "22.1.8")
	if !rep.ObjectCompiledVerified || rep.ObjectCompiledForms != 1 || rep.ObjectCompileLLVMVersion != "22.1.8" {
		t.Fatalf("object compilation metrics = (%v, %d, %q), want (true, 1, 22.1.8)", rep.ObjectCompiledVerified, rep.ObjectCompiledForms, rep.ObjectCompileLLVMVersion)
	}
	if got := normalizeUnsupportedReason(`plan9asm.probe: "FXSAVE (BX)": amd64: unsupported instruction FXSAVE (x87/SSE/XSAVE state save/restore is not modeled): "FXSAVE (BX)"`); got != "x87/SSE/XSAVE state save/restore is not modeled" {
		t.Fatalf("normalizeUnsupportedReason = %q", got)
	}

	md := string(renderMarkdown(rep))
	for _, want := range []string{
		"# Plan9 Asm Scan Report (linux/amd64)",
		"metric 1 — IR generated",
		"metric 2 — object compiled (LLVM 22.1.8 `llc -filetype=obj` verified)",
		"metric 3 — semantically differentially verified (execution report): `1` passed, `0` hw-pending",
		"## Explicit Unsupported Catalog (grouped by reason)",
		"## Hardware-Pending Forms (from execution report)",
		"## Cluster Summary",
		"## Unsupported Ops (vs current lowerers)",
		"good.s",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("renderMarkdown() missing %q in:\n%s", want, md)
		}
	}
}

func TestVerifyObjRequiresLLVM22AndRealObjectEmission(t *testing.T) {
	// 1. Verify findLLCTool rejects non-LLVM-22 binaries instead of accepting any llc.
	fakeDir := t.TempDir()
	fakeName := "llc"
	fakeScript := "#!/bin/sh\necho 'LLVM (http://llvm.org/):'\necho '  LLVM version 19.1.0'\n"
	if runtime.GOOS == "windows" {
		fakeName = "llc.cmd"
		fakeScript = "@echo off\r\necho LLVM version 19.1.0\r\n"
	}
	fakePath := filepath.Join(fakeDir, fakeName)
	if err := os.WriteFile(fakePath, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(fakePath, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("rejects-non-22", func(t *testing.T) {
		t.Setenv("LLVM_CONFIG", "")
		t.Setenv("PATH", fakeDir)
		if p, ver, err := findLLCTool(); err == nil {
			t.Fatalf("findLLCTool unexpectedly accepted non-22 llc: %q (%q)", p, ver)
		} else if !strings.Contains(err.Error(), "LLVM 22") {
			t.Fatalf("unexpected error for non-22 llc: %v", err)
		}
	})

	// 2. Verify runLLCOnIR runs real -filetype=obj emission (failing on a cross-section
	// symbol-difference relocation that -filetype=null silently accepts).
	llcPath, ver, err := findLLCTool()
	if err != nil {
		t.Skipf("LLVM 22 llc unavailable: %v", err)
	}
	if !strings.HasPrefix(ver, "22.") && ver != "22" {
		t.Fatalf("findLLCTool returned unexpected version %q", ver)
	}
	badRelocIR := `target triple = "x86_64-unknown-linux-gnu"
@g1 = global i32 1, section ".sec_a"
@g2 = global i32 2, section ".sec_b"
@diff = constant i64 sub (i64 ptrtoint (ptr @g1 to i64), i64 ptrtoint (ptr @g2 to i64))
`
	if err := runLLCOnIR(llcPath, "amd64", t.TempDir(), badRelocIR); err == nil {
		t.Fatalf("runLLCOnIR accepted cross-section symbol-difference relocation; expected -filetype=obj emission failure")
	}
	goodIR := `target triple = "x86_64-unknown-linux-gnu"
define i64 @ok(i64 %x) {
  %y = add i64 %x, 1
  ret i64 %y
}
`
	if err := runLLCOnIR(llcPath, "amd64", t.TempDir(), goodIR); err != nil {
		t.Fatalf("runLLCOnIR rejected valid IR: %v", err)
	}
}

func TestAddFormStatCachesConcreteInstructionsWithoutCollapsingValues(t *testing.T) {
	forms := map[string]*formStat{}
	for _, imm := range []int64{1, 17, 17} {
		addFormStat(forms, plan9asm.ArchAMD64, "amd64", plan9asm.Instr{
			Op:  "PSRLDQ",
			Raw: "PSRLDQ immediate, X0",
			Args: []plan9asm.Operand{
				{Kind: plan9asm.OpImm, Imm: imm},
				{Kind: plan9asm.OpReg, Reg: plan9asm.Reg("X0")},
			},
		}, "fixture.s")
	}
	if len(forms) != 1 {
		t.Fatalf("forms = %d, want 1", len(forms))
	}
	for _, stat := range forms {
		if stat.SupportedCount != 1 || stat.UnsupportedCount != 1 {
			t.Fatalf("probe classifications = supported %d, unsupported %d; want 1 and 1", stat.SupportedCount, stat.UnsupportedCount)
		}
		if len(stat.ProbeKeys) != 2 {
			t.Fatalf("probe cache entries = %d, want 2", len(stat.ProbeKeys))
		}
	}
}

func TestBuildOpcodeCatalogIncludesGeneratedTables(t *testing.T) {
	goroot := t.TempDir()
	dir := filepath.Join(goroot, "src", "cmd", "internal", "obj", "arm64")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anames.go"), []byte("var Anames = []string{\n\"ADD\",\n\"LAST\",\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anames_gen.go"), []byte("var sveAnames = []string{\n\"ZADD\",\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops := map[string]*opStat{"ADD": {Count: 1}}
	catalog, err := buildOpcodeCatalog(goroot, plan9asm.ArchARM64, "arm64", ops, map[string]*formStat{}, map[string]struct{}{"ADD": {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 2 || catalog[0].Opcode != "ADD" || catalog[1].Opcode != "ZADD" {
		t.Fatalf("catalog = %#v", catalog)
	}
	if !catalog[0].Observed || !catalog[0].NameClaimed {
		t.Fatalf("ADD catalog flags = %#v", catalog[0])
	}
	if catalog[1].Family != "sve" {
		t.Fatalf("ZADD family = %q, want sve", catalog[1].Family)
	}
}

func TestBuildWASMOpcodeCatalogNormalizesOfficialNames(t *testing.T) {
	goroot := t.TempDir()
	dir := filepath.Join(goroot, "src", "cmd", "internal", "obj", "wasm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anames.go"), []byte("var Anames = []string{\n\"I32Add\",\n\"ReservedFD01\",\n\"LAST\",\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := buildOpcodeCatalog(goroot, plan9asm.ArchWASM, "wasm", map[string]*opStat{"I32ADD": {Count: 1}}, nil, map[string]struct{}{"I32ADD": {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 1 || catalog[0].Opcode != "I32ADD" || !catalog[0].Observed || !catalog[0].NameClaimed {
		t.Fatalf("wasm catalog = %#v", catalog)
	}
}

func TestRenderMarkdownWASMOpcodeInventory(t *testing.T) {
	md := string(renderMarkdown(report{Goos: "js", Goarch: "wasm", EncoderForms: 3, EncoderOpcodes: 3, EncoderOpsObserved: 2}))
	if !strings.Contains(md, "official wasm opcode entries: `3` (`2` observed in the official GOROOT corpus)") {
		t.Fatalf("wasm report has the wrong inventory description:\n%s", md)
	}
}

func TestGoAsmInstructionLine(t *testing.T) {
	for _, line := range []string{"XORB SI, (AX)", "  PUNPCKLQDQ X0, X0 // encoding", "RET"} {
		if !goAsmInstructionLine(line) {
			t.Errorf("goAsmInstructionLine(%q) = false", line)
		}
	}
	for _, line := range []string{"", "// comment", "#include \"textflag.h\"", "TEXT f(SB),$0", "label:"} {
		if goAsmInstructionLine(line) {
			t.Errorf("goAsmInstructionLine(%q) = true", line)
		}
	}
}

func TestBuildReportAndJSONShape(t *testing.T) {
	ops := map[string]*opStat{
		"CALL":   {Count: 3, Files: map[string]int{"a.s": 2}, Pkgs: map[string]int{"p": 3}},
		"VPXORQ": {Count: 5, Files: map[string]int{"b.s": 5}, Pkgs: map[string]int{"p": 5}},
		"DATA":   {Count: 1, Files: map[string]int{"c.s": 1}, Pkgs: map[string]int{"p": 1}},
	}
	rep := buildReport("std", "go1.test", "linux", "amd64", 3, 1, 2, ops, map[string]*formStat{}, map[string]struct{}{"CALL": {}}, nil, map[string]struct{}{}, map[string]struct{}{}, []parseErr{{File: "bad.s", Err: "boom"}})
	if rep.UniqueOps != 3 {
		t.Fatalf("UniqueOps = %d, want 3", rep.UniqueOps)
	}
	if len(rep.OpsByFreq) != 3 {
		t.Fatalf("OpsByFreq len = %d, want 3", len(rep.OpsByFreq))
	}
	if rep.OpsByFreq[0].Op != "VPXORQ" {
		t.Fatalf("OpsByFreq[0] = %#v", rep.OpsByFreq[0])
	}
	if len(rep.Unsupported) != 1 {
		t.Fatalf("Unsupported len = %d, want 1", len(rep.Unsupported))
	}
	js, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal(report) error = %v", err)
	}
	if !strings.Contains(string(js), `"goarch":"amd64"`) {
		t.Fatalf("json output missing goarch: %s", js)
	}
}

func TestClusterAndFamilyCoverageMore(t *testing.T) {
	clusterCases := []struct {
		goarch string
		op     string
		want   string
	}{
		{"amd64", "RET", "x86-control"},
		{"amd64", "VZEROUPPER", "x86-simd"},
		{"amd64", "CRC32Q", "x86-crc"},
		{"amd64", "LOCK", "x86-atomic"},
		{"amd64", "BTQ", "x86-bit-shift"},
		{"amd64", "MOVQ", "x86-scalar"},
		{"arm64", "VADD", "arm64-neon"},
		{"arm64", "CBNZ", "arm64-control"},
		{"arm64", "SWPALD", "arm64-atomic"},
		{"arm64", "RBIT", "arm64-bit-shift"},
		{"arm64", "ADD", "arm64-scalar"},
		{"other", "MOV", "other"},
	}
	for _, tc := range clusterCases {
		if got := clusterOf(tc.goarch, tc.op); got != tc.want {
			t.Fatalf("clusterOf(%q, %q) = %q, want %q", tc.goarch, tc.op, got, tc.want)
		}
	}

	familyCases := []struct {
		goarch string
		op     string
		want   string
	}{
		{"amd64", "AESENC", "aes"},
		{"amd64", "SHA256MSG2", "sha"},
		{"amd64", "VGF2P8AFFINEQB", "gfni"},
		{"amd64", "KORW", "avx512-mask"},
		{"amd64", "VZEROALL", "avx-vector"},
		{"amd64", "MOVAPS", "sse-simd"},
		{"amd64", "ADCXQ", "bmi2-adx"},
		{"amd64", "MFENCE", "atomic-memory"},
		{"amd64", "JCS", "branch-alias"},
		{"amd64", "SHRQ", "bit-rotate-shift"},
		{"amd64", "ADJSP", "move-pseudo"},
		{"amd64", "ADDQ", "scalar-misc"},
		{"arm64", "AESD", "crypto"},
		{"arm64", "VEOR", "neon"},
		{"arm64", "TBZ", "branch"},
		{"arm64", "CASALD", "atomic-memory"},
		{"arm64", "ADD", "scalar-misc"},
		{"other", "X", "other"},
	}
	for _, tc := range familyCases {
		if got := familyOf(tc.goarch, tc.op); got != tc.want {
			t.Fatalf("familyOf(%q, %q) = %q, want %q", tc.goarch, tc.op, got, tc.want)
		}
	}
}

func TestMainAndFatalfSubprocess(t *testing.T) {
	testBin := os.Args[0]
	if os.Getenv("PLAN9ASMSCAN_MAIN_HELPER") == "1" {
		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		os.Args = []string{
			"plan9asmscan",
			"-goos=linux",
			"-goarch=amd64",
			"-format=json",
			"-repo-root=../..",
			"-out=" + filepath.Join(os.TempDir(), "plan9asmscan-test.json"),
		}
		main()
		return
	}
	if os.Getenv("PLAN9ASMSCAN_FATALF_HELPER") == "1" {
		fatalf("boom %d", 7)
		return
	}

	outPath := filepath.Join(t.TempDir(), "report.json")
	helperHome := t.TempDir()
	oldArgs := os.Args
	oldFlags := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	}()
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{
		"plan9asmscan",
		"-goos=linux",
		"-goarch=amd64",
		"-format=json",
		"-repo-root=../..",
		"-out=" + outPath,
	}
	main()
	if data, err := os.ReadFile(outPath); err != nil || !strings.Contains(string(data), `"goarch": "amd64"`) {
		t.Fatalf("main() output = (%q, %v)", string(data), err)
	}

	wasmOut := filepath.Join(t.TempDir(), "wasm-report.json")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{
		"plan9asmscan",
		"-corpus=go-asm",
		"-goos=js",
		"-goarch=wasm",
		"-format=json",
		"-repo-root=../..",
		"-out=" + wasmOut,
	}
	main()
	data, err := os.ReadFile(wasmOut)
	if err != nil {
		t.Fatal(err)
	}
	var wasmReport report
	if err := json.Unmarshal(data, &wasmReport); err != nil || wasmReport.Goarch != "wasm" || wasmReport.OfficialOpcodes < 100 {
		t.Fatalf("wasm main() output = (%q, %v)", string(data), err)
	}

	cmd := exec.Command(testBin, "-test.run=TestMainAndFatalfSubprocess")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + helperHome,
		"GOCACHE=" + filepath.Join(helperHome, "gocache"),
		"PLAN9ASMSCAN_MAIN_HELPER=1",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("main helper failed: %v\n%s", err, out)
	}

	fcmd := exec.Command(testBin, "-test.run=TestMainAndFatalfSubprocess")
	fcmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + helperHome,
		"GOCACHE=" + filepath.Join(helperHome, "gocache"),
		"PLAN9ASMSCAN_FATALF_HELPER=1",
	}
	fout, err := fcmd.CombinedOutput()
	if err == nil {
		t.Fatalf("fatalf helper unexpectedly succeeded")
	}
	if !strings.Contains(string(fout), "boom 7") {
		t.Fatalf("fatalf output = %q, want boom 7", string(fout))
	}
}
