package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This first-party fragment retains the observed native RSP-relative buffer,
// not a source rewrite which changes it into a positive virtual-SP offset.
// Its clamped copies execute only initialized, bounded fixture buffers.
func arm64PrivateSPHelperSource(bufferBytes ...int) string {
	const root = `TEXT ·Buffer(SB),4,$32-24
MOVD dst+0(FP),R2
MOVD src+8(FP),R1
MOVD n+16(FP),R3
CMP $32,R3
BLS bounded
MOVD $32,R3
bounded:
MOVD RSP,R8
SUB $32,R8
STP (ZR,ZR),(R8)
STP (ZR,ZR),16(R8)
CALL copy<>(SB)
MOVD R8,R1
MOVD R2,R8
MOVD $32,R3
CALL copy<>(SB)
RET
`
	_, helper, found := strings.Cut(arm64PrivateCallCFGCopySource, "TEXT copy<>(SB)")
	if !found {
		panic("first-party private copy fixture lost its complete helper")
	}
	caller := root
	if len(bufferBytes) == 1 && bufferBytes[0] == 16 {
		caller = strings.ReplaceAll(caller, "$32", "$16")
		caller = strings.Replace(caller, "STP (ZR,ZR),16(R8)\n", "", 1)
	} else if len(bufferBytes) > 1 || len(bufferBytes) == 1 && bufferBytes[0] != 32 {
		panic("unregistered first-party buffer fixture span")
	}
	return caller + "TEXT copy<>(SB)" + helper
}

func TestARM64PrivateSPHelperOriginalGoObjects(t *testing.T) {
	dir := t.TempDir()
	for _, bufferBytes := range []int{16, 32} {
		source := arm64PrivateSPHelperSource(bufferBytes)
		path := filepath.Join(dir, fmt.Sprintf("private_sp_%d_arm64.s", bufferBytes))
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		for _, goos := range []string{"darwin", "linux", "windows"} {
			t.Run(fmt.Sprintf("%d/%s", bufferBytes, goos), func(t *testing.T) {
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				object := filepath.Join(dir, fmt.Sprintf("%d-%s.o", bufferBytes, goos))
				cmd := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "main", "-o", object, path)
				cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
				listing, err := runtimeOracleCombinedOutput(ctx, cmd)
				if err != nil {
					t.Fatalf("original framed source object: %v\n%s", err, listing)
				}
				// The actual Go frame saves LR at body SP and BP at body SP-8.
				// Neither receipt says its automatic locals own the negative buffer.
				text := string(listing)
				if !strings.Contains(text, "TEXT\tmain.Buffer(SB)") && !strings.Contains(text, "TEXT\t\"\".Buffer(SB)") {
					t.Fatalf("actual original object lost its Buffer symbol:\n%s", listing)
				}
				// Go 1.20 restores BP and LR as a pair; current Go uses a BP
				// load followed by the post-index LR load. Both read BP at -8.
				bpRestore := "MOVD\t-8(RSP), R29"
				if !strings.Contains(text, bpRestore) {
					bpRestore = "LDP\t-8(RSP), (R29, R30)"
				}
				for _, expected := range []string{fmt.Sprintf("MOVD.W\tR30, -%d(RSP)", bufferBytes+16), "MOVD\tR29, -8(RSP)", "MOVD\tRSP, R8", fmt.Sprintf("SUB\t$%d, R8", bufferBytes), "CALL\tcopy(SB)", bpRestore} {
					if !strings.Contains(string(listing), expected) {
						t.Fatalf("actual Go listing omitted %q:\n%s", expected, listing)
					}
				}
				bytes, err := os.ReadFile(object)
				if err != nil || len(bytes) == 0 {
					t.Fatalf("missing actual object: %v", err)
				}
				t.Logf("selected SDK actual go tool asm: %s/arm64 source=%x object=%x bytes=%d BP-restore=%q", goos, sha256.Sum256([]byte(source)), sha256.Sum256(bytes), len(bytes), bpRestore)
			})
		}
	}
}

func TestARM64PrivateSPHelperNeedsOriginalBacking(t *testing.T) {
	source := arm64PrivateSPHelperSource()
	pkg := mustGoPackage(t, "test/privatesp", "package privatesp\nfunc Buffer(dst, src *[32]byte, n uint64)\n")
	context := llvm.NewContext()
	defer context.Dispose()
	result, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: arm64LinuxGNUTriple,
		ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
	})
	if result != nil && !result.Module.IsNil() {
		defer result.Module.Dispose()
	}
	if !errors.Is(err, ErrProbeNeedsContext) || result != nil {
		t.Fatalf("original negative-SP buffer acquired an unproved native frame contract: result=%v err=%v", result, err)
	}
	t.Logf("conservative translator rejection remains distinct from original Go ABI corruption: %v", err)
}

func TestCrossLinuxRuntimeMatrixARM64PrivateSPHelperOriginalCanaries(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	const program = `package main

import "unsafe"

func Buffer(dst, src *[32]byte, n uint64)

func main() {
    for trial := 0; trial < 64; trial++ {
        for _, off := range []int{0, 1, 7, 16, 32} {
            for _, n := range []uint64{0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 23, 31, 32, 33, 64, ^uint64(0)} {
                var input, inputBefore, output, want [96]byte
                for i := range input {
                    input[i] = byte(trial*17 + i*37 + off)
                    inputBefore[i] = input[i]
                    output[i] = byte(i*19 + trial + 0xa5)
                    want[i] = output[i]
                }
                q := n
                if q > 32 { q = 32 }
                for i := 0; i < 32; i++ {
                    want[off+i] = 0
                    if uint64(i) < q { want[off+i] = input[off+i] }
                }
                Buffer((*[32]byte)(unsafe.Pointer(&output[off])), (*[32]byte)(unsafe.Pointer(&input[off])), n)
                if input != inputBefore { panic("original private SP helper changed input/full canary") }
                if output != want { panic("original private SP helper mathematical/full canary mismatch") }
            }
        }
    }
}

`
	runARM64LocalRegisterGoOracle(t, arm64PrivateSPHelperSource(), program, len(runner) != 0)
	t.Log(fmt.Sprintf("original Go only: %d initialized cases; all 96 input/output bytes observed; no LLVM/backing permission claim", 64*5*16))
}

// The observation trampoline owns its outgoing arguments and independently
// restores the real Go caller LR/SP/BP. Buffer cannot overwrite the protected
// cells above this trampoline's SP. Its damaged BP is observed, never used as
// an address or exposed to the caller after the original BP is restored.
func TestCrossLinuxRuntimeMatrixARM64PrivateSPHelperSavedBPObservation(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	const trampoline = `TEXT ·Measure(SB),516,$0-40
MOVD dst+0(FP),R0
MOVD src+8(FP),R1
MOVD n+16(FP),R2
SUB $64,RSP
STP (R30,R29),48(RSP)
MOVD R0,8(RSP)
MOVD R1,16(RSP)
MOVD R2,24(RSP)
CALL ·Buffer(SB)
MOVD R29,R0
LDP 48(RSP),(R30,R29)
MOVD R29,R1
ADD $64,RSP
MOVD R1,before+24(FP)
MOVD R0,after+32(FP)
RET
`
	const program = `package main

import (
    "encoding/binary"
    "fmt"
)

func Buffer(dst, src *[32]byte, n uint64)
func Measure(dst, src *[32]byte, n uint64) (before, after uint64)

func main() {
    for _, n := range []uint64{0, 1, 7, 16, 24, 25, 31, 32} {
        var input, inputBefore, output, want [32]byte
        for i := range input { input[i] = byte(0x41+i); inputBefore[i] = input[i] }
        for i := uint64(0); i < n; i++ { want[i] = input[i] }
        before, after := Measure(&output, &input, n)
        expectedBP := binary.LittleEndian.Uint64(want[24:])
        const positiveControl = false
        if positiveControl {
            if before != after { panic("disjoint positive-SP control changed the entry BP") }
        } else {
            if after != expectedBP { panic("original saved BP does not match the independent overwritten-byte reference") }
            if before == after { panic("fixture did not expose original saved-BP corruption") }
        }
        if input != inputBefore || output != want { panic("original saved-BP observation changed source/output data") }
        fmt.Printf("n=%d before=%016x after=%016x expectedData=%016x positiveControl=%t\n", n, before, after, expectedBP, positiveControl)
    }
}
`
	for _, bufferBytes := range []int{16, 32} {
		t.Run(fmt.Sprint(bufferBytes), func(t *testing.T) {
			bound := strings.ReplaceAll(program, "i < n", fmt.Sprintf("i < n && i < %d", bufferBytes))
			bound = strings.ReplaceAll(bound, "want[24:]", fmt.Sprintf("want[%d:%d]", bufferBytes-8, bufferBytes))
			for _, positiveControl := range []bool{false, true} {
				name := "negativeSP"
				if positiveControl {
					name = "positiveSPControl"
				}
				t.Run(name, func(t *testing.T) {
					source := arm64PrivateSPHelperSource(bufferBytes)
					main := bound
					if positiveControl {
						// This separate first-party harness control is not an Aegis
						// rewrite or a permission certificate for its negative buffer.
						source = strings.Replace(source, fmt.Sprintf("SUB $%d,R8", bufferBytes), "ADD $8,R8", 1)
						main = strings.Replace(main, "const positiveControl = false", "const positiveControl = true", 1)
					}
					runARM64PrivateSPGoObservation(t, trampoline+source, main, len(runner) != 0)
				})
			}
		})
	}
}

func runARM64PrivateSPGoObservation(t *testing.T, source, main string, cross bool) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":  "module privatebpobservation\n\ngo 1.20\n",
		"main.go": main, "oracle_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"run", "-p=2", "."}
	env := append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
	if cross {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
		env = append(env, "GOOS=linux")
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir, cmd.Env = dir, env
	output, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil {
		t.Fatalf("safe original Go BP observation: %v\n%s", err, output)
	}
	if strings.Count(string(output), "positiveControl=") != 8 {
		t.Fatalf("missing independent BP observation receipts: %q", output)
	}
	t.Logf("actual original Go observation: asm=%x Go=%x args=%q\n%s", sha256.Sum256([]byte(source)), sha256.Sum256([]byte(main)), args, output)
}
