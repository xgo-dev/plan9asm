package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This first-party source is a continuation, not a separately callable Go
// function: the private body reads the real ABIInternal caller's pointer and
// returns through its unchanged caller LR. No private helper signature exists.
func arm64ClosedTailPointerSource(op string) string {
	return fmt.Sprintf(`TEXT ·Read<ABIInternal>(SB),516,$0-16
%s readbody<>(SB)
TEXT readbody<>(SB),516,$0-0
MOVD (R0),R0
RET
`, op)
}

func TestARM64ClosedTailPointerOriginalGoObjects(t *testing.T) {
	for _, op := range []string{"B", "JMP", "RET"} {
		t.Run(op, func(t *testing.T) {
			// The stock assembler's runtime selector permission is only an
			// original object oracle. It does not grant a helper ABI or assert
			// that an ordinary user package can define ABIInternal assembly.
			requireARM64GoABIInternalObject(t, arm64ClosedTailPointerSource(op))
		})
	}
}

func TestARM64ClosedTailPointerContinuationThreeAPIs(t *testing.T) {
	llc, _, _ := findLlcAndClang(t)
	pkg := mustGoPackage(t, "test/privatetail", "package privatetail\nfunc Read(*uint64) uint64\n")
	resolve := func(symbol string) string {
		return strings.TrimPrefix(goStripABISuffix(symbol), "·")
	}
	for _, op := range []string{"B", "JMP", "RET"} {
		source := arm64ClosedTailPointerSource(op)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		original, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		// Bind only the real source declaration through the central derivation.
		// Passing a fabricated helper FuncSig would hide the actual gap.
		entry := *file
		entry.Funcs = append([]Func(nil), file.Funcs[:1]...)
		entry.Funcs[0].Instrs = entry.Funcs[0].Instrs[:1]
		sigs, err := goSigsForAsmFile(pkg, &entry, resolve, "arm64", nil, nil, nil)
		if err != nil || sigs["Read"].ARM64GoRegisterABI == nil {
			t.Fatalf("real caller declaration lacks its register ABI: %v", err)
		}
		for _, target := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
			"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
		} {
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(op+"/"+target+"/"+api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
					var err error
					var ir string
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						module, failure := TranslateModuleInContext(ctx, file, options)
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
						err = failure
					case "GoModule":
						result, failure := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
							GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
							// The complete original file still reaches preparation;
							// filtering cannot supply the missing helper permission.
							KeepFunc: func(_, resolved string) bool { return resolved == "Read" },
						})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
						err = failure
					}
					if !reflect.DeepEqual(file, original) {
						t.Fatal("translation mutated the complete original source")
					}
					if err != nil {
						t.Fatalf("closed zero-frame source continuation needs no guessed helper ABI: %v", err)
					}
					compileLLVMToObject(t, llc, target, "closed-tail.ll", "closed-tail.o", ir)
				})
			}
		}
	}
}

func arm64ClosedTailTranslate(t *testing.T, source, declaration, target, api string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "test/closedtail", "package closedtail\n"+declaration+"\n")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return "", err
	}
	resolve := func(symbol string) string {
		return strings.TrimPrefix(goStripABISuffix(symbol), "·")
	}
	entry := *file
	entry.Funcs = nil
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			continue
		}
		fn.Instrs = fn.Instrs[:1]
		entry.Funcs = append(entry.Funcs, fn)
	}
	sigs, err := goSigsForAsmFile(pkg, &entry, resolve, "arm64", nil, nil, nil)
	if err != nil {
		return "", err
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	switch api {
	case "text":
		return Translate(file, options)
	case "module":
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
			if err == nil {
				return module.String(), nil
			}
		}
		return "", err
	case "GoModule":
		result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
			KeepFunc: func(_, resolved string) bool { return resolved != "Excluded" },
		})
		if result != nil && !result.Module.IsNil() {
			defer result.Module.Dispose()
			if err == nil {
				return result.Module.String(), nil
			}
		}
		return "", err
	default:
		t.Fatalf("unknown test API %q", api)
		return "", nil
	}
}

func TestARM64ClosedTailWholeSourceGuards(t *testing.T) {
	base := arm64ClosedTailPointerSource("B")
	for _, tc := range []struct{ name, source string }{
		{"root-frame", strings.Replace(base, "$0-16", "$16-16", 1)},
		{"root-unknown-flags", strings.Replace(base, "516,$0-16", "unknown,$0-16", 1)},
		{"root-unknown-args", strings.Replace(base, "$0-16", "$0", 1)},
		{"root-call", strings.Replace(base, "B readbody", "CALL external(SB)\nB readbody", 1)},
		{"same-helper-call-and-tail", strings.Replace(base, "B readbody", "CALL readbody<>(SB)\nB readbody", 1)},
		{"different-helper-call-and-tail", strings.Replace(base, "B readbody", "CALL mix<>(SB)\nB readbody", 1) + "TEXT mix<>(SB),516,$0-0\nADD $1,R0\nRET\n"},
		{"helper-frame", strings.Replace(base, "$0-0", "$16-0", 1)},
		{"helper-fp", strings.Replace(base, "MOVD (R0),R0", "MOVD x+0(FP),R0", 1)},
		{"helper-sp", strings.Replace(base, "MOVD (R0),R0", "MOVD (RSP),R0", 1)},
		{"helper-platform", strings.Replace(base, "MOVD (R0),R0", "MOVD R18_PLATFORM,R0", 1)},
		{"helper-g", strings.Replace(base, "MOVD (R0),R0", "MOVD g,R0", 1)},
		{"helper-hidden", strings.Replace(base, "MOVD (R0),R0", "MOVD 8(R26),R0", 1)},
		{"helper-lr", strings.Replace(base, "MOVD (R0),R0", "MOVD R30,R0", 1)},
		{"helper-scratch", strings.Replace(base, "MOVD (R0),R0", "ADD $0x123456789,R0,R0", 1)},
		{"helper-memory-scratch", strings.Replace(base, "MOVD (R0),R0", "MOVD 65537(R0),R0", 1)},
		{"helper-pair-scratch", strings.Replace(base, "MOVD (R0),R0", "LDP 1024(R0),(R0,R1)", 1)},
		{"helper-fp-memory-scratch", strings.Replace(base, "MOVD (R0),R0", "FMOVD 65536(R0),F0\nFMOVD F0,R0", 1)},
		{"helper-fp-pair-scratch", strings.Replace(base, "MOVD (R0),R0", "FLDPD 1024(R0),(F0,F1)\nFMOVD F0,R0", 1)},
		{"helper-unknown-gp", strings.Replace(base, "MOVD (R0),R0", "MOVD R9,R0", 1)},
		{"helper-unknown-f", strings.Replace(base, "MOVD (R0),R0", "FMOVD F1,R0", 1)},
		{"helper-unknown-vector", strings.Replace(base, "MOVD (R0),R0", "VMOV V1.D[0],R0", 1)},
		{"helper-join", strings.Replace(base, "MOVD (R0),R0", "CBZ R0,done\nMOVD $9,R9\ndone:\nMOVD R9,R0", 1)},
		{"helper-missing-label", strings.Replace(base, "MOVD (R0),R0", "B absent", 1)},
		{"helper-indirect-control", strings.Replace(base, "MOVD (R0),R0", "B (R0)", 1)},
		{"helper-nested", strings.Replace(base, "MOVD (R0),R0", "B other<>(SB)", 1) + "TEXT other<>(SB),516,$0\nB readbody<>(SB)\n"},
		{"helper-fallthrough", strings.TrimSuffix(base, "RET\n")},
		{"helper-duplicate", base + "TEXT readbody<>(SB),516,$0-0\nMOVD $1,R0\nRET\n"},
		{"data-address", base + "DATA address<>+0(SB)/8,$readbody<>(SB)\nGLOBL address<>(SB),8,$8\n"},
		{"data-address-offset", base + "DATA address<>+0(SB)/8,$readbody<>+4(SB)\nGLOBL address<>(SB),8,$8\n"},
		{"global-identity", base + "GLOBL readbody<>(SB),8,$8\n"},
		{"excluded-address", base + "TEXT ·Excluded(SB),516,$0-8\nMOVD $readbody<>(SB),R0\nRET\n"},
		{"excluded-word", base + "TEXT ·Excluded(SB),516,$0-8\nWORD $0xd65f03c0\nRET\n"},
		{"excluded-adr", base + "TEXT ·Excluded(SB),516,$0-8\nADR label,R0\nlabel:\nRET\n"},
	} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(tc.name+"/"+api, func(t *testing.T) {
				_, err := arm64ClosedTailTranslate(t, tc.source, "func Read(*uint64) uint64\nfunc Excluded() uint64", "aarch64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved complete source must stay Context: %v", err)
				}
			})
		}
	}
}

func TestARM64ClosedTailLabelsInputsAndBudget(t *testing.T) {
	base := strings.Replace(arm64ClosedTailPointerSource("B"), "MOVD (R0),R0", "CBZ R0,empty\nMOVD (R0),R0\nRET\nempty:\nMOVD $0,R0", 1)
	base = strings.Replace(base, "B readbody<>(SB)", "__arm64_tail_3:\nCBZ R0,alternate\nB readbody<>(SB)\nalternate:\nB readbody<>(SB)", 1)
	base += "TEXT ·Other<ABIInternal>(SB),516,$0-16\nB readbody<>(SB)\n"
	file, err := Parse(ArchARM64, base)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := Parse(ArchARM64, base)
	prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil || !reflect.DeepEqual(file, original) || len(prepared.Funcs) != 2 {
		t.Fatalf("complete shared-helper preparation/immutability: %v", err)
	}
	second, err := CoalesceARM64PrivateRegisterHelpers(prepared)
	if err != nil || !reflect.DeepEqual(prepared, second) {
		t.Fatalf("source preparation is not idempotent: %v", err)
	}
	for _, fn := range prepared.Funcs {
		names := map[string]bool{}
		for _, block := range arm64SplitBlocks(fn) {
			name := arm64LLVMBlockName(block.name)
			if names[name] {
				t.Fatalf("renamed source labels collide at %q", name)
			}
			names[name] = true
		}
	}
	// The CALL half uses 65534 original instructions. The separate three
	// instruction tail would fit another independent budget, but not the one
	// file-wide checked budget. No Cartesian allocation is permitted first.
	call := "TEXT ·Run(SB),4,$0-16\nMOVD x+0(FP),R0\nCALL mix<>(SB)\nMOVD R0,ret+8(FP)\nRET\nTEXT mix<>(SB),516,$0-0\n" +
		strings.Repeat("ADD $1,R0\n", arm64PrivateRegisterExpansionBudget-4) + "RET\n"
	for _, source := range []string{call, arm64ClosedTailPointerSource("B")} {
		parsed, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CoalesceARM64PrivateRegisterHelpers(parsed); err != nil {
			t.Fatalf("individual budget control: %v", err)
		}
	}
	mixed, err := Parse(ArchARM64, call+arm64ClosedTailPointerSource("B"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CoalesceARM64PrivateRegisterHelpers(mixed); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("CALL and tail must share the original-source budget: %v", err)
	}
	// A public preparation followed by the final API's preparation must not
	// reset the file's already consumed CALL/tail expansion allowance.
	parsedCall, err := Parse(ArchARM64, call)
	if err != nil {
		t.Fatal(err)
	}
	preparedCall, err := CoalesceARM64PrivateRegisterHelpers(parsedCall)
	if err != nil {
		t.Fatal(err)
	}
	parsedTail, err := Parse(ArchARM64, arm64ClosedTailPointerSource("B"))
	if err != nil {
		t.Fatal(err)
	}
	reprepared := *preparedCall
	reprepared.Funcs = append(append([]Func(nil), preparedCall.Funcs...), parsedTail.Funcs...)
	if _, err := CoalesceARM64PrivateRegisterHelpers(&reprepared); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("repeated public preparation reset its consumed expansion budget: %v", err)
	}
}
