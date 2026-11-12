package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are numerical, zero-frame fixtures. Neither a syscall format nor a
// target OS supplies a native entry, saved-frame or local-memory capability.
const arm64SyscallEffectSetup = "MOVD $0,R0\nMOVD $11,R1\nMOVD $12,R2\nMOVD $13,R3\nMOVD $14,R4\nMOVD $15,R5\nMOVD $172,R8\nMOVD $57,R16\n"

func arm64SyscallEffectSource(body string) string {
	return "TEXT ·trap(SB),516,$0-8\n" + arm64SyscallEffectSetup + body + "\nMOVD R0,ret+0(FP)\nRET\n"
}

func arm64SyscallEffectAPI(t *testing.T, api, triple, source string) (string, error) {
	t.Helper()
	const packagePath = "example.com/syscalleffects"
	pkg := mustGoPackage(t, packagePath, "package syscalleffects\nfunc trap() uint64\n")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return "", err
	}
	resolve := testResolveSym(packagePath)
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs, AnnotateSource: true}
	context := llvm.NewContext()
	defer context.Dispose()
	switch api {
	case "text":
		return Translate(file, options)
	case "module":
		module, err := TranslateModuleInContext(context, file, options)
		if !module.IsNil() {
			defer module.Dispose()
			return module.String(), err
		}
		return "", err
	case "Go":
		goos := "linux"
		if strings.Contains(triple, "apple-darwin") {
			goos = "darwin"
		}
		result, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
			GOOS: goos, GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve, AnnotateSource: true,
		})
		if result != nil && !result.Module.IsNil() {
			defer result.Module.Dispose()
			return result.Module.String(), err
		}
		return "", err
	default:
		t.Fatalf("unknown syscall API %q", api)
		return "", nil
	}
}

func arm64SyscallEffectIR(t *testing.T, ir, spelling string) string {
	t.Helper()
	// LLVM's parser removes source comments. Observe the sole actual call and
	// its contiguous number/argument loads, through the later result read.
	lines := strings.Split(ir, "\n")
	call, start, end := -1, -1, -1
	for index, line := range lines {
		if strings.Contains(line, "call i64 @syscall(") {
			if call >= 0 {
				t.Fatalf("ambiguous actual syscall call for %s", spelling)
			}
			call = index
		}
	}
	if call >= 0 {
		for index := call - 1; index >= 0; index-- {
			line := lines[index]
			if strings.Contains(line, "load i64, ptr %reg_R8,") || strings.Contains(line, "load i64, ptr %reg_R16,") {
				start = index
				break
			}
		}
		for index := call + 1; index < len(lines); index++ {
			if strings.Contains(lines[index], "load i64, ptr %reg_R0,") {
				end = index
				break
			}
		}
	}
	if start < 0 || end <= call {
		t.Fatalf("actual number/call/result sequence absent for %s", spelling)
	}
	return strings.Join(lines[start:end], "\n")
}

func TestARM64SyscallLinuxNormalReturnEffects(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, spelling := range []string{"SVC", "SVC $0", "SVC $0x80", "SVC $65535", "SVC $65536", "SVC $-1"} {
			t.Run(api+"/"+spelling, func(t *testing.T) {
				source := arm64SyscallEffectSource("CMP R2,R1\n" + spelling + "\nCSET MI,R2\nCSET EQ,R3\nCSET CS,R4\nCSET VS,R5")
				ir, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", source)
				if err != nil {
					t.Fatal(err)
				}
				fragment := arm64SyscallEffectIR(t, ir, spelling)
				if !strings.Contains(fragment, "@syscall(") || !strings.Contains(fragment, "ptr %reg_R8") ||
					!strings.Contains(fragment, "sub i64 0") {
					t.Fatalf("Linux trap must use R8 and raw -errno: %s", fragment)
				}
				for _, line := range strings.Split(fragment, "\n") {
					if strings.Contains(line, "store ") && (strings.Contains(line, "ptr %reg_R1") || strings.Contains(line, "ptr %flags_")) {
						t.Errorf("Linux normal-return GP/NZCV preservation violated: %s", line)
					}
				}
			})
		}
	}
}

func TestARM64SyscallFlagsRequireCompletePredecessors(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, body := range []string{
			"SVC\nCSET CS,R2",
			"SVC $0x80\nCSET MI,R2",
			"SVC\nJMP observe\nobserve:\nCSET VS,R2",
			"CBZ R0,trap\nCMP R2,R1\ntrap:\nSVC\nCSET EQ,R2",
		} {
			t.Run(api+"/"+body, func(t *testing.T) {
				_, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource(body))
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("SVC cannot supply missing original NZCV: %v", err)
				}
			})
		}
		for _, body := range []string{
			"CMP R2,R1\nJMP trap\ntrap:\nSVC\nJMP observe\nobserve:\nCSET CS,R2",
			"JMP compare\nobserve:\nCSET VS,R2\nJMP finish\ncompare:\nCMP R2,R1\nSVC\nJMP observe\nfinish:",
			"CBZ R0,left\nCMP R2,R1\nJMP trap\nleft:\nCMP R3,R1\ntrap:\nSVC\nCSET EQ,R2",
		} {
			t.Run(api+"/defined/"+body, func(t *testing.T) {
				if _, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource(body)); err != nil {
					t.Fatalf("complete reaching CMP must survive Linux SVC: %v", err)
				}
			})
		}
	}
}

func TestARM64SyscallRequiresExplicitSupportedTarget(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"", "aarch64-unknown-freebsd", "aarch64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-unknown-notlinux-gnu", "aarch64-unknown-linuxish-gnu"} {
			t.Run(api+"/"+triple, func(t *testing.T) {
				_, err := arm64SyscallEffectAPI(t, api, triple, arm64SyscallEffectSource("SVC $0x80"))
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("target cannot be inferred from host, immediate or GP values: %v", err)
				}
			})
		}
	}
}

func TestARM64SyscallDarwinCarryRoleIsSeparate(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := arm64SyscallEffectAPI(t, api, "aarch64-apple-darwin", arm64SyscallEffectSource("SVC $0x80\nCSET CS,R2"))
			if err != nil {
				t.Fatal(err)
			}
			fragment := arm64SyscallEffectIR(t, ir, "SVC $0x80")
			if !strings.Contains(fragment, "ptr %reg_R16") || strings.Contains(fragment, "ptr %reg_R8") || strings.Contains(fragment, "sub i64 0") {
				t.Fatalf("Darwin carry bridge selected Linux number/error convention: %s", fragment)
			}
			if !strings.Contains(fragment, "store i1") || !strings.Contains(fragment, "ptr %flags_c") {
				t.Fatal("Darwin carry write missing")
			}
		})
		for _, spelling := range []string{"SVC", "SVC $0", "SVC $1", "SVC $65535"} {
			t.Run(api+"/unknown-trap/"+spelling, func(t *testing.T) {
				_, err := arm64SyscallEffectAPI(t, api, "aarch64-apple-darwin", arm64SyscallEffectSource(spelling))
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unmodeled Darwin trap cannot become Linux: %v", err)
				}
			})
		}
	}
}

func TestARM64SyscallDarwinUnknownOutputsRemainContext(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, observation := range []string{
			"CSET MI,R2", "CSET EQ,R2", "CSET VS,R2", "CSET HI,R2",
			"MOVD R1,R0", "JMP observe\nobserve:\nCSET GT,R2",
		} {
			t.Run(api+"/"+observation, func(t *testing.T) {
				_, err := arm64SyscallEffectAPI(t, api, "aarch64-apple-darwin",
					arm64SyscallEffectSource("CMP R2,R1\nSVC $0x80\n"+observation))
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("Darwin carry-only bridge cannot invent secondary result or other NZCV: %v", err)
				}
			})
		}
		for _, body := range []string{
			"SVC $0x80\nCMP R3,R2\nCSET HI,R2",
			"SVC $0x80\nMOVD $37,R1\nMOVD R1,R0",
			"SVC $0x80\nJMP redefine\nredefine:\nCMP R3,R2\nCSET GT,R2",
		} {
			t.Run(api+"/redefined/"+body, func(t *testing.T) {
				if _, err := arm64SyscallEffectAPI(t, api, "aarch64-apple-darwin", arm64SyscallEffectSource(body)); err != nil {
					t.Fatalf("complete fresh writes must restore only their actual defined outputs: %v", err)
				}
			})
		}
	}
}

func TestARM64SyscallContinuationEffects(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, register := range []string{"R0", "R1", "R2", "R16"} {
			t.Run(api+"/"+register, func(t *testing.T) {
				body := fmt.Sprintf("ADR resume,%s\nSVC\nJMP (%s)\nresume:", register, register)
				_, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource(body))
				if register == "R0" {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("new syscall R0 cannot impersonate old local continuation: %v", err)
					}
				} else if err != nil {
					t.Fatalf("untouched Linux %s local continuation lost: %v", register, err)
				}
			})
		}
	}
}

func TestARM64SyscallRejectsNonIntegerAndMalformedForms(t *testing.T) {
	for _, spelling := range []string{"SVC R0", "SVC (R0)", "SVC $0,$1", "SVC $1.5", "SVC $missing", "SVC.P $0", "SVC.W $0"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api+"/"+spelling, func(t *testing.T) {
				if _, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource(spelling)); err == nil {
					t.Fatal("malformed/unresolved syscall emitted successful IR")
				}
			})
		}
	}
}

func TestARM64SyscallCarryReadersRequireActualDefinition(t *testing.T) {
	for _, op := range []string{"ADC", "ADCW", "ADCS", "ADCSW", "SBC", "SBCW", "SBCS", "SBCSW", "NGC", "NGCW", "NGCS", "NGCSW"} {
		instruction := op + " R2,R3"
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api+"/missing/"+op, func(t *testing.T) {
				_, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource("SVC\n"+instruction))
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("carry read cannot consume alloca initialization or fabricated SVC carry: %v", err)
				}
			})
			t.Run(api+"/defined/"+op, func(t *testing.T) {
				body := "CMP R2,R1\nJMP trap\ntrap:\nSVC\nJMP observe\nobserve:\n" + instruction
				if _, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource(body)); err != nil {
					t.Fatalf("actual reaching C must survive Linux SVC for %s: %v", op, err)
				}
			})
		}
	}
}
