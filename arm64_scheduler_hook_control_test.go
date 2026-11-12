package plan9asm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These are the unmodified two functions and declarations from x/sys v0.18.0
// unix/asm_linux_arm64.s and unix/syscall_linux_gc.go. The complete original
// files have SHA-256 9d1514c08da093cd38b77f03ff5fe265c16500a42295b32c66509dc828a34045
// and 41a54001d221205e9f1538066105b46c08cd329e85d4529426063961daa86235.
const arm64OriginalNoErrorSyscalls = `TEXT ·SyscallNoError(SB),NOSPLIT,$0-48
	BL	runtime·entersyscall(SB)
	MOVD	a1+8(FP), R0
	MOVD	a2+16(FP), R1
	MOVD	a3+24(FP), R2
	MOVD	$0, R3
	MOVD	$0, R4
	MOVD	$0, R5
	MOVD	trap+0(FP), R8
	SVC
	MOVD	R0, r1+32(FP)
	MOVD	R1, r2+40(FP)
	BL	runtime·exitsyscall(SB)
	RET

TEXT ·RawSyscallNoError(SB),NOSPLIT,$0-48
	MOVD	a1+8(FP), R0
	MOVD	a2+16(FP), R1
	MOVD	a3+24(FP), R2
	MOVD	$0, R3
	MOVD	$0, R4
	MOVD	$0, R5
	MOVD	trap+0(FP), R8
	SVC
	MOVD	R0, r1+32(FP)
	MOVD	R1, r2+40(FP)
	RET
`

func requireARM64SchedulerHookGoObject(t *testing.T, source string) {
	t.Helper()
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return // Old-Go lanes still execute the API and LLVM object tests.
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "syscalls.s"), filepath.Join(dir, "syscalls.o")
	if err := os.WriteFile(input, []byte("#include \"textflag.h\"\n"+source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-S", "-I", filepath.Join(runtime.GOROOT(), "pkg", "include"), "-p", "golang.org/x/sys/unix", "-o", output, input)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("original Go source object failed: %v\n%s", err, out)
	}
	if strings.Contains(source, "TEXT ·SyscallNoError") {
		listing := strings.Join(strings.Fields(string(out)), " ")
		for _, want := range []string{"MOVD.W R30, -16(RSP)", "MOVD.P 16(RSP), R30"} {
			if !strings.Contains(listing, want) {
				t.Fatalf("Go's nonleaf zero-TEXT-frame must save and restore the caller LR; missing %q:\n%s", want, out)
			}
		}
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() == 0 {
		t.Fatalf("Go assembler did not create an object: %v", err)
	}
}

func TestARM64SchedulerHookOriginalSyscallReturn(t *testing.T) {
	pkg := mustGoPackage(t, "golang.org/x/sys/unix", `package unix
func SyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
func RawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
`)
	requireARM64SchedulerHookGoObject(t, arm64OriginalNoErrorSyscalls)

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, call := range []string{"BL", "CALL"} {
		source := strings.ReplaceAll(arm64OriginalNoErrorSyscalls, "BL\t", call+"\t")
		requireARM64SchedulerHookGoObject(t, source)
		for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
			t.Run(call+"/"+triple, func(t *testing.T) {
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOOS: "linux", GOARCH: "arm64", TargetTriple: triple,
					ResolveSym: testResolveSym(pkg.Path),
				})
				if triple != "aarch64-unknown-linux-gnu" && triple != "aarch64-unknown-linux-musl" {
					if tr != nil && !tr.Module.IsNil() {
						tr.Module.Dispose()
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("Linux bare-SVC source cannot acquire another target's syscall ABI: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Module.Dispose()
				ir := tr.Module.String()
				for _, line := range strings.Split(ir, "\n") {
					if strings.Contains(line, " call ") && (strings.Contains(line, "runtime.entersyscall") || strings.Contains(line, "runtime.exitsyscall")) {
						t.Fatal("elided scheduler hooks must not become native calls")
					}
				}
				if len(tr.Signatures[pkg.Path+".SyscallNoError"].Frame.Params) != 4 || len(tr.Signatures[pkg.Path+".SyscallNoError"].Frame.Results) != 2 {
					t.Fatal("original Go declaration must supply the actual ABI0 frame")
				}
				compileLLVMToObject(t, llc, triple, "no-error-syscalls.ll", "no-error-syscalls.o", ir)
			})
		}
	}
}

func TestARM64SchedulerHookUnknownCalleeStillInvalidatesReturn(t *testing.T) {
	pkg := mustGoPackage(t, "golang.org/x/sys/unix", `package unix
func SyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
func RawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
`)
	for _, name := range []string{"runtime·entersyscall", "runtime·exitsyscall"} {
		for _, unknown := range []string{"runtime·entersyscallblock", "other·entersyscall", "runtime·exitsyscallfast", name + "+4"} {
			t.Run(name+"/"+unknown, func(t *testing.T) {
				source := strings.Replace(arm64OriginalNoErrorSyscalls, name+"(SB)", unknown+"(SB)", 1)
				requireARM64SchedulerHookGoObject(t, source)
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					ResolveSym: testResolveSym(pkg.Path),
				})
				if err == nil {
					tr.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("untyped native call must keep the caller-LR gap: %v", err)
				}
			})
		}
	}
}

func TestARM64SchedulerHookLoweringHasNoMachineCallEffect(t *testing.T) {
	for _, name := range []string{"runtime.entersyscall", "runtime.exitsyscall"} {
		t.Run(name, func(t *testing.T) {
			flow := &arm64MachineAvailability{blocks: make([]arm64MachineBlock, 1)}
			ctx, ir := newARM64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.f", Ret: Void}, nil)
			ctx.machineAvailability = flow
			before := ir.String()
			if err := ctx.callSym(Operand{Kind: OpSym, Sym: name + "(SB)"}); err != nil {
				t.Fatal(err)
			}
			if ir.String() != before || len(flow.blocks[0].effects) != 0 {
				t.Fatalf("an elided hook has neither emitted call nor virtual register effect: %q, %+v", ir.String()[len(before):], flow.blocks[0].effects)
			}
		})
	}
}

func TestARM64SchedulerHookDoesNotRepairSourceContinuation(t *testing.T) {
	for _, mutation := range []string{
		"MOVD $0,0(RSP)",
		"MOVD RSP,R20\nMOVD $0,(R20)",
		"SUB $16,RSP",
	} {
		t.Run(mutation, func(t *testing.T) {
			source := "TEXT ·stub(SB),NOSPLIT,$0-0\nBL runtime·entersyscall(SB)\n" + mutation + "\nBL runtime·exitsyscall(SB)\nRET\n"
			requireARM64SchedulerHookGoObject(t, source)
			pkg := mustGoPackage(t, "example.com/hooks", "package hooks\nfunc stub()\n")
			tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				ResolveSym: testResolveSym(pkg.Path),
			})
			if err == nil {
				tr.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("no-op hooks cannot repair a source-clobbered continuation: %v", err)
			}
		})
	}
}

func TestARM64SchedulerHookSyscallFrameExposureRemainsContext(t *testing.T) {
	pkg := mustGoPackage(t, "golang.org/x/sys/unix", `package unix
func SyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
func RawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
`)
	for _, exposure := range []string{
		"MOVD RSP,R1",
		"MOVD RSP,R20\nMOVD R20,R1",
		"MOVD R30,R1\nADD $1,R1",
	} {
		t.Run(exposure, func(t *testing.T) {
			source := strings.Replace(arm64OriginalNoErrorSyscalls, "\tSVC\n", exposure+"\n\tSVC\n", 1)
			requireARM64SchedulerHookGoObject(t, source)
			tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				ResolveSym: testResolveSym(pkg.Path),
			})
			if err == nil {
				tr.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved native syscall frame effects must remain context: %v", err)
			}
		})
	}
}

func TestARM64SchedulerHookSyscallResultsCannotReestablishContinuation(t *testing.T) {
	pkg := mustGoPackage(t, "golang.org/x/sys/unix", `package unix
func SyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
func RawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
`)
	for _, reg := range []string{"R0", "R1"} {
		for _, svc := range []string{"SVC", "SVC $0"} {
			t.Run(reg+"/"+svc, func(t *testing.T) {
				replacement := "MOVD 0(RSP)," + reg + "\n" + svc + "\nMOVD " + reg + ",0(RSP)\n"
				source := strings.Replace(arm64OriginalNoErrorSyscalls, "\tSVC\n", replacement, 1)
				requireARM64SchedulerHookGoObject(t, source)
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					ResolveSym: testResolveSym(pkg.Path),
				})
				if err == nil {
					tr.Module.Dispose()
				}
				if reg == "R0" && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("new Linux R0 result is not the old caller continuation: %v", err)
				}
				if reg == "R1" && err != nil {
					t.Fatalf("untouched Linux R1 lost its original saved caller continuation: %v", err)
				}
			})
		}
	}
}
