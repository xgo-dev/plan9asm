package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64OpaquePreservationCase struct {
	name, save, restore string
}

func arm64OpaquePreservationCases() []arm64OpaquePreservationCase {
	return []arm64OpaquePreservationCase{
		{"scalar_offset", "SUB $32,RSP\nMOVD R22,0(RSP)\nMOVD R21,8(RSP)\nMOVD R20,16(RSP)\nMOVD R19,24(RSP)\n", "MOVD 24(RSP),R19\nMOVD 16(RSP),R20\nMOVD 8(RSP),R21\nMOVD 0(RSP),R22\nADD $32,RSP\n"},
		{"scalar_pre_post", "MOVD.W R22,-32(RSP)\nMOVD R21,8(RSP)\nMOVD R20,16(RSP)\nMOVD R19,24(RSP)\n", "MOVD 24(RSP),R19\nMOVD 16(RSP),R20\nMOVD 8(RSP),R21\nMOVD.P 32(RSP),R22\n"},
		{"scalar_post_pre", "SUB $64,RSP\nMOVD.P R22,32(RSP)\nMOVD R21,-24(RSP)\nMOVD R20,-16(RSP)\nMOVD R19,-8(RSP)\n", "MOVD -8(RSP),R19\nMOVD -16(RSP),R20\nMOVD -24(RSP),R21\nMOVD.W -32(RSP),R22\nADD $64,RSP\n"},
		{"pair_offset", "SUB $32,RSP\nSTP (R22,R21),0(RSP)\nSTP (R20,R19),16(RSP)\n", "LDP 16(RSP),(R20,R19)\nLDP 0(RSP),(R22,R21)\nADD $32,RSP\n"},
		{"pair_pre_post", "STP.W (R22,R21),-32(RSP)\nSTP (R20,R19),16(RSP)\n", "LDP 16(RSP),(R20,R19)\nLDP.P 32(RSP),(R22,R21)\n"},
		{"pair_post_pre", "SUB $64,RSP\nSTP.P (R22,R21),32(RSP)\nSTP (R20,R19),-16(RSP)\n", "LDP -16(RSP),(R20,R19)\nLDP.W -32(RSP),(R22,R21)\nADD $64,RSP\n"},
		{"raw_pair_pre_post", "WORD $0xa9be57f6\nWORD $0xa9014ff4\n", "WORD $0xa9414ff4\nWORD $0xa8c257f6\n"},
		{"raw_pair_pre_post_branch", "WORD $0xa9be57f6\nWORD $0xa9014ff4\n", "WORD $0xa9414ff4\nWORD $0xa8c257f6\n"},
	}
}

func arm64OpaquePreservationSource(tc arm64OpaquePreservationCase, body string) string {
	return "TEXT ·saveAlias(SB),516,$0-16\nMOVD alias+0(FP),R0\nMOVD out+8(FP),R1\n" + tc.save + body + tc.restore + "RET\n"
}

func arm64OpaqueObservationBody(branch bool) string {
	body := "MOVD $77,R22\nMOVD $88,R21\nMOVD $0,R20\nMOVD $99,R19\nMOVD (R0),R4\n"
	if branch {
		body += "CBZ R4,zero\nMOVD R4,(R1)\nB remaining\nzero:\nMOVD R4,(R1)\nremaining:\n"
	} else {
		body += "MOVD R4,(R1)\n"
	}
	return body + "MOVD 8(R0),R4\nMOVD R4,8(R1)\nMOVD 16(R0),R4\nMOVD R4,16(R1)\nMOVD 24(R0),R4\nMOVD R4,24(R1)\n"
}

func arm64OpaqueRunOriginalGo(t *testing.T, source, main string, cross bool) {
	t.Helper()
	formatted, err := format.Source([]byte(main))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ACTUAL_FIRST_PARTY_MODULE go=1.20 sdk=%s main_sha256=%x asm_sha256=%x\nMAIN:\n%s", runtime.Version(), sha256.Sum256(formatted), sha256.Sum256([]byte(source)), formatted)
	runARM64LocalRegisterGoOracle(t, source, string(formatted), cross)
}

// This helper invokes the selected SDK on both historical and current lanes.
// It never borrows the current-table-only oracle's quiet old-SDK return.
func arm64OpaqueOriginalObject(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	driver, err = filepath.EvalSymlinks(driver)
	if err != nil {
		t.Fatal(err)
	}
	want := "go"
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	actual := filepath.Join(runtime.GOROOT(), "bin", want)
	actual, err = filepath.EvalSymlinks(actual)
	if err != nil || driver != actual {
		t.Fatalf("selected driver does not match actual SDK: %s != %s: %v", driver, actual, err)
	}
	driverBytes, err := os.ReadFile(driver)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "tool", "asm", "-S", "-p", "main", "-o", object, asm)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOOS=linux", "GOARCH=arm64")
	output, commandErr := runtimeOracleCombinedOutput(ctx, command)
	if err := goAssemblerOracleOutcome(asm, object, output, commandErr, ctx.Err(), true, "arm64"); err != nil {
		t.Fatalf("%v\n%s\n%s", err, output, source)
	}
	objectBytes, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ACTUAL_OBJECT sdk=%s driver=%s driver_sha256=%x source_sha256=%x object_sha256=%x bytes=%d\nSOURCE:\n%s\nLISTING:\n%s", runtime.Version(), driver, sha256.Sum256(driverBytes), sha256.Sum256([]byte(source)), sha256.Sum256(objectBytes), len(objectBytes), source, output)
	return string(output)
}

func TestARM64OpaquePreservationOriginalObjectsAndCurrentContext(t *testing.T) {
	pkg := mustGoPackage(t, "test/opaque", "package opaque\nfunc saveAlias(*uint64,*uint64)\n")
	for _, tc := range arm64OpaquePreservationCases() {
		t.Run(tc.name, func(t *testing.T) {
			source := arm64OpaquePreservationSource(tc, arm64OpaqueObservationBody(strings.HasSuffix(tc.name, "_branch")))
			listing := arm64OpaqueOriginalObject(t, source)
			if !strings.Contains(listing, "NOFRAME") || strings.Contains(listing, "MOVD.W\tR30,") {
				t.Fatal("actual original object unexpectedly synthesized a native frame")
			}
			file, err := Parse(ArchARM64, source)
			if err != nil || len(file.Funcs) != 1 {
				t.Fatalf("complete original source parse: %v", err)
			}
			transport := &arm64PrivateFrameTransport{entry: arm64RawZeroFrameSig()}
			t.Logf("SOURCE_ONLY_FRESH_FRAME_PROOF=%t (not a native caller no-alias certificate)", arm64RawZeroFrameUnexposedForTransport(file.Funcs[0], transport))
			for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
				ctx := llvm.NewContext()
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				if tr != nil && !tr.Module.IsNil() {
					tr.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "R22 read") {
					t.Fatalf("%s: retain the actual unbound R22 source rejection: %v", target, err)
				}
				t.Logf("CURRENT_CONTEXT target=%s error=%v", target, err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64OpaqueSaveSlotCallerObservation(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range arm64OpaquePreservationCases() {
		t.Run(tc.name, func(t *testing.T) {
			target := arm64OpaquePreservationSource(tc, arm64OpaqueObservationBody(strings.HasSuffix(tc.name, "_branch")))
			// The caller knows its own actual SP. The leaf callee allocates
			// exactly 32 or 64 bytes below that same SP. No guessed heap length,
			// garbage pointer, invalid continuation or third-party code is used.
			distance := 32
			if strings.HasSuffix(tc.name, "post_pre") {
				distance = 64
			}
			caller := fmt.Sprintf(`TEXT ·observe(SB),4,$160-16
MOVD pattern+0(FP),R22
ADD $3,R22,R21
ADD $5,R22,R20
ADD $7,R22,R19
MOVD out+8(FP),R6
SUB $%d,RSP,R0
MOVD R0,8(RSP)
MOVD R6,16(RSP)
CALL ·saveAlias(SB)
MOVD out+8(FP),R6
MOVD R22,32(R6)
MOVD R21,40(R6)
MOVD R20,48(R6)
MOVD R19,56(R6)
RET
`, distance)
			arm64OpaqueOriginalObject(t, caller+target)
			main := `package main
func observe(uint64,*[8]uint64)
func saveAlias(*uint64,*uint64)
func main() {
  for _, pattern := range []uint64{0,1,0x1122334455667788,0x8000000000000000,^uint64(0)} {
    out := [10]uint64{0xa1a2a3a4a5a6a7a8,0,0,0,0,0,0,0,0,0xb1b2b3b4b5b6b7b8}
    observe(pattern,(*[8]uint64)(unsafe.Pointer(&out[1])))
    for i:=1;i<=8;i++ {
      want := pattern + []uint64{0,3,5,7}[(i-1)&3]
      if out[i]!=want { println(i,out[i],want); panic("original save bytes or opaque restore differ") }
    }
    if out[0]!=0xa1a2a3a4a5a6a7a8 || out[9]!=0xb1b2b3b4b5b6b7b8 {
      panic("observable output memory canary mismatch")
    }
  }
}
`
			main = strings.Replace(main, "package main\n", "package main\nimport \"unsafe\"\n", 1)
			arm64OpaqueRunOriginalGo(t, caller+target, main, len(runner) != 0)
			t.Log("ACTUAL_NATIVE_OBSERVATION: original caller supplies a pointer to the future callee save cell; saved incoming R22 bytes are observable")
		})
	}
}
