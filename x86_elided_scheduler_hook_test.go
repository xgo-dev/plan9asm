package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86SchedulerHookFixture(arch string) (string, string) {
	move, typ, width := "MOVQ", "uint64", 8
	if arch == "386" {
		move, typ, width = "MOVL", "uint32", 4
	}
	declaration := fmt.Sprintf("func probe(x %s) (a, b %s)", typ, typ)
	source := fmt.Sprintf("TEXT ·probe(SB),4,$0-%d\nCALL runtime·entersyscall(SB)\n%s x+0(FP),AX\n%s AX,a+%d(FP)\n%s $0,b+%d(FP)\nCALL runtime·exitsyscall(SB)\nRET\n",
		3*width, move, move, width, move, 2*width)
	return source, declaration
}

func x86SchedulerHookAPI(t *testing.T, source, declaration, arch, target, api string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "scheduler", "package scheduler\n"+declaration+"\n")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	resolve := testResolveSym(pkg.Path)
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: arch, TargetTriple: target, ResolveSym: resolve, Sigs: signatures}
	return arm64ScratchSourceAPIWithAssembly(t, pkg, file, options, api, source)
}

func TestX86ElidedSchedulerHookPairedSource(t *testing.T) {
	source := x86SchedulerKernelFixture()
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86SchedulerHookAPI(t, source, x86LinuxSyscallDeclaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("elided hooks did not retain the complete initialized syscall path", err)
			}
		})
	}
}

func x86SchedulerKernelFixture() string {
	source := strings.Replace(x86LinuxSyscallAssembly, "\n", "\nCALL runtime·entersyscall(SB)\n", 1)
	return strings.Replace(source, "RET", "CALL runtime·exitsyscall(SB)\nRET", 1)
}

func TestX86ElidedSchedulerHookPortableSources(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		source, declaration := x86SchedulerHookFixture(arch)
		for _, target := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+target+"/"+api, func(t *testing.T) {
					ir, err := x86SchedulerHookAPI(t, source, declaration, arch, target, api)
					if err != nil {
						t.Fatal("existing elided hooks rejected actual initialized frame values", err)
					}
					if ir == "" || strings.Contains(ir, "call void @runtime.enter") || strings.Contains(ir, "call void @runtime.exit") {
						t.Fatal("elided hook became a native runtime call", ir)
					}
				})
			}
		}
	}
}

func TestX86ElidedSchedulerHookKeepsSourceBoundaries(t *testing.T) {
	source, declaration := x86SchedulerKernelFixture(), x86LinuxSyscallDeclaration
	for _, row := range []struct{ name, before, after string }{
		{"unknown", "runtime·entersyscall", "runtime·entersyscallblock"},
		{"other-package", "runtime·entersyscall", "other·entersyscall"},
		{"offset", "runtime·entersyscall(SB)", "runtime·entersyscall+1(SB)"},
		{"unknown-selector", "runtime·entersyscall(SB)", "runtime·entersyscall<ABI99>(SB)"},
		{"stale-register", "MOVQ AX, r1+56(FP)", "CALL runtime·exitsyscall(SB)\nMOVQ AX, r1+56(FP)"},
		{"private-stack", "CALL runtime·entersyscall(SB)", "PUSHQ $1\nCALL runtime·entersyscall(SB)\nPOPQ BX"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				input := strings.Replace(source, row.before, row.after, 1)
				ir, err := x86SchedulerHookAPI(t, input, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err == nil || ir != "" {
					t.Fatalf("hook supplied missing source/call context: output=%t error=%v", ir != "", err)
				}
			})
		}
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "strictscheduler", "package strictscheduler\n"+declaration+"\n")
	signatures, err := goSigsForAsmFile(pkg, file, testResolveSym(pkg.Path), "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckX86ABI0ResultInitialization(file.Funcs[0], signatures[pkg.Path+".Raw"], "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("standalone query borrowed paired hook handling", err)
	}
}
