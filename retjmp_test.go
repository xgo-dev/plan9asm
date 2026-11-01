package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateRetjmp(t *testing.T) {
	for _, tc := range retjmpArchitectures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(tc.arch, "TEXT ·f(SB),NOSPLIT,$0-0\n\tRET ·next(SB)\n")
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			ir, err := Translate(file, retjmpOptions(tc.goarch))
			if err != nil {
				t.Fatalf("Translate() error = %v", err)
			}
			if !strings.Contains(ir, "call void @example.next()") {
				t.Fatalf("RET target was not lowered as a tail jump:\n%s", ir)
			}
		})
	}
}

func TestTranslateRetjmpUsesCallerSignatureWhenCalleeIsExternal(t *testing.T) {
	for _, tc := range retjmpArchitectures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(tc.arch, "TEXT ·f(SB),NOSPLIT,$0-0\n\tRET ·external(SB)\n")
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			opt := retjmpOptions(tc.goarch)
			opt.Sigs = map[string]FuncSig{
				"example.f": {Name: "example.f", Ret: Void},
			}
			ir, err := Translate(file, opt)
			if err != nil {
				t.Fatalf("Translate() error = %v", err)
			}
			if !strings.Contains(ir, "call void @example.external()") {
				t.Fatalf("external RET target did not inherit the caller signature:\n%s", ir)
			}
		})
	}
}

var retjmpArchitectures = []struct {
	name   string
	arch   Arch
	goarch string
}{
	{name: "arm", arch: ArchARM, goarch: "arm"},
	{name: "arm64", arch: ArchARM64, goarch: "arm64"},
	{name: "amd64", arch: ArchAMD64, goarch: "amd64"},
}

func retjmpOptions(goarch string) Options {
	return Options{
		ResolveSym: func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Goarch:     goarch,
		Sigs: map[string]FuncSig{
			"example.f":    {Name: "example.f", Ret: Void},
			"example.next": {Name: "example.next", Ret: Void},
		},
	}
}

func TestTranslateRetRegister(t *testing.T) {
	for _, tc := range retjmpArchitectures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			source := "TEXT ·f(SB),4,$0-0\nRET (R14)\n"
			switch tc.arch {
			case ArchARM:
				requireARMGoAssemblerResult(t, source, true)
			case ArchARM64:
				// A register return is ordinary only when source really copied
				// the caller link into its target. An uninitialized R27 is not.
				source = "TEXT ·f(SB),4,$0-0\nMOVD R30,R27\nRET (R27)\n"
				requireARM64GoAssemblerResult(t, source, true)
			case ArchAMD64:
				source = "TEXT ·f(SB),4,$0-0\nRET (AX)\n"
				requireX86GoAssemblerResult(t, "amd64", source, false)
			}
			file, err := Parse(tc.arch, source)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			ir, err := Translate(file, retjmpOptions(tc.goarch))
			if tc.arch == ArchAMD64 {
				if err == nil {
					t.Fatal("accepted a register RET that Go's x86 assembler rejects")
				}
				return
			}
			if err != nil {
				t.Fatalf("Translate() error = %v", err)
			}
			if !strings.Contains(ir, "ret void") {
				t.Fatalf("register RET was not lowered as a function return:\n%s", ir)
			}
		})
	}
}

func TestTranslateARM64RetRegisterRequiresCallerLinkProof(t *testing.T) {
	const source = "TEXT ·f(SB),4,$0-0\nRET (R27)\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			opt := retjmpOptions("arm64")
			opt.TargetTriple = triple
			if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("opaque register return must require context, got %v", err)
			}
			linked, err := Parse(ArchARM64, "TEXT ·f(SB),4,$0-0\nMOVD R30,R27\nRET (R27)\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(linked, opt)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "register-return.ll", "register-return.o", ir)
		})
	}
}

func TestTranslateX86RETRejectsNonGoOperands(t *testing.T) {
	for _, arch := range []struct {
		arch Arch
		name string
	}{{ArchAMD64, "386"}, {ArchAMD64, "amd64"}} {
		for _, operand := range []string{"(AX)", "8(SP)", "$16"} {
			t.Run(arch.name+"/"+operand, func(t *testing.T) {
				source := "TEXT ·f(SB),4,$0-0\nRET " + operand + "\n"
				requireX86GoAssemblerResult(t, arch.name, source, false)
				file, err := Parse(arch.arch, source)
				if err != nil {
					return
				}
				if _, err := Translate(file, retjmpOptions(arch.name)); err == nil {
					t.Fatalf("accepted %s RET %s outside Go's ynone row", arch.name, operand)
				}
			})
		}
	}
}

func TestTranslateX86RETRegisterRequiresNativeTailContract(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			// Go's obj6 preprocess preserves the register and emits a JMP
			// after its frame epilogue. Unknown AX must not become ret void.
			const source = "TEXT ·f(SB),4,$0-0\nRET AX\n"
			requireX86GoAssemblerResult(t, arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, retjmpOptions(arch)); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("register tail return requires a native contract, got %v", err)
			}
		})
	}
}

func TestTranslateRetjmpRejectsMultipleTargets(t *testing.T) {
	for _, tc := range retjmpArchitectures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(tc.arch, "TEXT ·f(SB),NOSPLIT,$0-0\n\tRET ·one(SB), ·two(SB)\n")
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			_, err = Translate(file, retjmpOptions(tc.goarch))
			if err == nil || !strings.Contains(err.Error(), "RET expects at most 1 operand") {
				t.Fatalf("Translate() error = %v, want RET operand count error", err)
			}
		})
	}
}
