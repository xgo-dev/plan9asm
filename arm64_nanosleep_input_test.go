package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Independent ordinary ABI0 source, not a runtime-name or SDK permission.
const arm64NanosleepInputSource = `TEXT ·sleep(SB),4,$24-4
	MOVWU usec+0(FP),R3
	MOVD R3,R5
	MOVW $1000000,R4
	UDIV R4,R3
	MOVD R3,8(RSP)
	MUL R3,R4
	SUB R4,R5
	MOVW $1000,R4
	MUL R4,R5
	MOVD R5,16(RSP)
	ADD $8,RSP,R0
	MOVD $0,R1
	MOVD $101,R8
	SVC
	RET
`

func arm64NanosleepInputAPI(t *testing.T, api, triple, source string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "example.invalid/sleepinput", "package sleepinput\nfunc sleep(usec uint32)\n")
	return arm64NanosleepPackageAPI(t, api, triple, source, pkg)
}

func arm64NanosleepPackageAPI(t *testing.T, api, triple, source string, pkg GoPackage) (string, error) {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return "", err
	}
	resolve := testResolveSym(pkg.Types.Path())
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
		bound, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
		})
		if bound != nil && !bound.Module.IsNil() {
			defer bound.Module.Dispose()
			return bound.Module.String(), err
		}
		return "", err
	default:
		t.Fatalf("unknown nanosleep API %q", api)
		return "", nil
	}
}

func TestARM64NanosleepInputCompleteSource(t *testing.T) {
	for _, spelling := range []string{"SVC", "SVC $0"} {
		source := strings.Replace(arm64NanosleepInputSource, "\tSVC\n", "\t"+spelling+"\n", 1)
		requireARM64GoAssemblerResult(t, source, true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api+"/"+spelling, func(t *testing.T) {
				ir, err := arm64NanosleepInputAPI(t, api, "aarch64-unknown-linux-gnu", source)
				if err != nil {
					t.Fatal("complete initialized private nanosleep input", err)
				}
				if strings.Count(ir, "call i64 @syscall(") != 1 || !strings.Contains(ir, "%local_stack = alloca [") {
					t.Fatal("accepted source lost its actual syscall or fresh private allocation")
				}
			})
		}
	}
}

func TestARM64NanosleepTypedInputCertificate(t *testing.T) {
	file, err := Parse(ArchARM64, arm64NanosleepInputSource)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "example.invalid/sleepinput", "package sleepinput\nfunc sleep(usec uint32)\n")
	resolve := testResolveSym(pkg.Types.Path())
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fn := file.Funcs[0]
	sig := sigs[resolve(fn.Sym)]
	collector := &arm64NanosleepInputProof{
		source: arm64NanosleepCloneSource(fn), sig: arm64NanosleepCloneSignature(sig),
		target: "aarch64-unknown-linux-gnu", inputs: make(map[[2]int]arm64NanosleepInput),
	}
	transport := &arm64PrivateFrameTransport{entry: sig, resolve: resolve, sigs: sigs, nanosleep: collector}
	if _, err := arm64PrivateDataProofDetails(fn, transport); err != nil {
		t.Fatal("complete original-source collector failed", err)
	}
	transport.nanosleep = nil
	proof, required := arm64NanosleepInputForSource(fn, transport, collector.target)
	if proof == nil || !required || !proof.matchesSource(fn, sig, collector.target) {
		t.Fatal("complete CFG did not publish its exact input certificate")
	}
}

func TestARM64NanosleepInputUnprovedMemoryRemainsContext(t *testing.T) {
	for _, change := range []struct{ name, old, replacement string }{
		{"unknown-number", "$101,R8", "$113,R8"},
		{"dynamic-number", "$101,R8", "R3,R8"},
		{"late-number", "\tSVC\n", "\tMOVD $57,R8\n\tSVC\n"},
		{"wrong-number-register", "$101,R8", "$101,R16"},
		{"trap-80", "\tSVC\n", "\tSVC $0x80\n"},
		{"trap-high-alias", "\tSVC\n", "\tSVC $65536\n"},
		{"nonnull-rem", "$0,R1", "$1,R1"},
		{"private-rem", "$0,R1", "R0,R1"},
		{"unbound-rem", "\tMOVD $0,R1\n", ""},
		{"unbound-input", "\tADD $8,RSP,R0\n", ""},
		{"saved-link-read", "$8,RSP,R0", "$0,RSP,R0"},
		{"saved-fp-read", "$8,RSP,R0", "$-8,RSP,R0"},
		{"out-of-bounds", "$8,RSP,R0", "$24,RSP,R0"},
		{"missing-sec", "\tMOVD R3,8(RSP)\n", ""},
		{"missing-nsec", "\tMOVD R5,16(RSP)\n", ""},
		{"partial-sec", "MOVD R3,8(RSP)", "MOVW R3,8(RSP)"},
		{"late-store", "\tMOVD R5,16(RSP)\n", "\tSVC\n\tMOVD R5,16(RSP)\n"},
		{"saved-link-write", "MOVD R3,8(RSP)", "MOVD R3,0(RSP)"},
		{"saved-fp-write", "MOVD R3,8(RSP)", "MOVD R3,-8(RSP)"},
		{"escaped-pointer", "\tMOVD $101,R8\n", "\tMOVD R0,16(RSP)\n\tMOVD $101,R8\n"},
		{"result-observation", "\tRET\n", "\tMOVD R0,R2\n\tRET\n"},
		{"flag-observation", "\tRET\n", "\tCSET CS,R2\n\tRET\n"},
		{"join-missing-store", "\tMOVD R5,16(RSP)\n", "\tCBZ R3,skip\n\tMOVD R5,16(RSP)\nskip:\n"},
		{"join-number", "\tMOVD $101,R8\n", "\tCBZ R3,other\n\tMOVD $101,R8\n\tJMP trap\nother:\n\tMOVD $113,R8\ntrap:\n"},
	} {
		t.Run(change.name, func(t *testing.T) {
			source := strings.Replace(arm64NanosleepInputSource, change.old, change.replacement, 1)
			if source == arm64NanosleepInputSource {
				t.Fatal("mutation did not change actual source")
			}
			requireARM64GoAssemblerResult(t, source, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					_, err := arm64NanosleepInputAPI(t, api, "aarch64-unknown-linux-gnu", source)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unproved syscall memory/continuation acquired permission: %v", err)
					}
				})
			}
		})
	}
	for _, triple := range []string{"", "aarch64-apple-darwin", "aarch64-pc-windows-msvc", "aarch64-unknown-freebsd"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api+"/target/"+triple, func(t *testing.T) {
				if _, err := arm64NanosleepInputAPI(t, api, triple, arm64NanosleepInputSource); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("foreign/unknown target acquired Linux private read: %v", err)
				}
			})
		}
	}
}
