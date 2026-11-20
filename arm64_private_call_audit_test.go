package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64PrivateCallCFGUnlinkedPreludeCannotHideNativeUse(t *testing.T) {
	for _, prelude := range []string{"MOVD $copy<>(SB),R0\n", "WORD $0xd503201f\n"} {
		t.Run(strings.TrimSpace(prelude), func(t *testing.T) {
			file, err := Parse(ArchARM64, prelude+arm64PrivateCallCFGCopySource)
			if err != nil {
				t.Fatal(err)
			}
			if len(file.UnlinkedPrelude) == 0 {
				t.Fatal("fixture did not retain its unbound native prelude")
			}
			if prepared, err := CoalesceARM64PrivateRegisterHelpers(file); prepared != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unbound prelude gained a private CALL continuation: %v", err)
			}
		})
	}
}

func TestARM64PrivateCallCFGLeafCannotCallOutOrWidenRegisterDomain(t *testing.T) {
	for _, instruction := range []string{
		"CALL R1", "BL R1", "BLR R1",
		"VEOR V0.B16,V0.B16,V0.B16", "FMOVD R1,F0",
	} {
		for _, dead := range []bool{false, true} {
			name := instruction
			body := instruction + "\nRET\n"
			if dead {
				name += "/dead_component"
				body = "RET\ndead:\n" + body
			}
			t.Run(name, func(t *testing.T) {
				source := strings.Split(arm64PrivateCallCFGCopySource, "TEXT copy<>")[0] +
					"TEXT copy<>(SB),516,$0-0\n" + body
				// BLR is accepted by the parsed IR API, not Go's spelling table.
				// Keep that distinction explicit while guarding both surfaces.
				requireARM64GoAssemblerResult(t, source, !strings.HasPrefix(instruction, "BLR"))
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				if prepared, err := CoalesceARM64PrivateRegisterHelpers(file); prepared != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("CALL data leaf gained a callout or unproved register domain: %v", err)
				}
			})
		}
	}
}

func TestARM64PrivateCallCFGPreparedFileCannotRecoverRemovedNativeIdentity(t *testing.T) {
	pkg := mustGoPackage(t, "test/privatecopy", "package privatecopy\nfunc Copy(dst,src *[32]byte,n uint64)\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	for _, observer := range []struct{ name, source string }{
		{"address", "TEXT observer<>(SB),516,$0-0\nMOVD $copy<>(SB),R0\nRET\n"},
		{"offset_address", "TEXT observer<>(SB),516,$0-0\nMOVD $copy<>+4(SB),R0\nRET\n"},
		{"native_call", "TEXT observer<>(SB),516,$0-0\nCALL copy<>(SB)\nRET\n"},
		{"data", "DATA saved<>+0(SB)/8,$copy<>(SB)\nGLOBL saved<>(SB),8,$8\n"},
		{"global", "GLOBL copy<>(SB),8,$8\n"},
		{"redefined_helper", "TEXT copy<>(SB),516,$0-0\nRET\n"},
		{"native_layout", "TEXT observer<>(SB),516,$0-0\nWORD $0xd503201f\nRET\n"},
		{"prelude", "MOVD $copy<>(SB),R0\nTEXT observer<>(SB),516,$0-0\nRET\n"},
	} {
		for _, api := range []string{"coalesce", "Go_preparation", "text", "module"} {
			t.Run(observer.name+"/"+api, func(t *testing.T) {
				file, err := Parse(ArchARM64, arm64PrivateCallCFGCopySource)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
				if err != nil {
					t.Fatal(err)
				}
				sigs, err := goSigsForAsmFile(pkg, prepared, resolve, "arm64", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				added, err := Parse(ArchARM64, observer.source)
				if err != nil {
					t.Fatal(err)
				}
				prepared.Funcs = append(prepared.Funcs, added.Funcs...)
				prepared.Data = append(prepared.Data, added.Data...)
				prepared.Globl = append(prepared.Globl, added.Globl...)
				prepared.UnlinkedPrelude = append(prepared.UnlinkedPrelude, added.UnlinkedPrelude...)
				options := Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, ResolveSym: resolve, Sigs: sigs}
				switch api {
				case "coalesce":
					_, err = CoalesceARM64PrivateRegisterHelpers(prepared)
				case "Go_preparation":
					_, err = PrepareGoARM64ABI0TailContinuations(prepared, sigs, resolve)
				case "text":
					_, err = Translate(prepared, options)
				case "module":
					context := llvm.NewContext()
					defer context.Dispose()
					module, failure := TranslateModuleInContext(context, prepared, options)
					if !module.IsNil() {
						module.Dispose()
					}
					err = failure
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("edited complete file recovered removed helper native identity: %v", err)
				}
			})
		}
	}
}

func TestARM64PrivateContinuationPreparedTailFileRetainsWholeAudit(t *testing.T) {
	for _, family := range []string{"ABIInternal", "ABI0"} {
		for _, observer := range []string{
			"DATA saved<>+0(SB)/8,$HELPER(SB)\nGLOBL saved<>(SB),8,$8\n",
			"TEXT observer<>(SB),516,$0-0\nMOVD $HELPER(SB),R0\nRET\n",
			"TEXT HELPER(SB),516,$0-0\nRET\n",
			"WORD $0xd503201f\nTEXT observer<>(SB),516,$0-0\nRET\n",
		} {
			t.Run(family+"/"+strings.Split(observer, "\n")[0], func(t *testing.T) {
				resolve := func(symbol string) string { return strings.TrimPrefix(goTextSymbolForResolution(symbol), "·") }
				var file *File
				var sigs map[string]FuncSig
				helper := "copy<>"
				if family == "ABI0" {
					_, file, sigs = arm64ABI0BoundFixture(t)
					helper = "resultbody<>"
				} else {
					var err error
					file, err = Parse(ArchARM64, "TEXT ·Copy<ABIInternal>(SB),516,$0-0\nB copy<>(SB)\nTEXT copy<>(SB),516,$0-0\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
				}
				prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, resolve)
				if err != nil || len(prepared.Funcs) != 1 {
					t.Fatalf("original complete tail fixture did not prepare: %v", err)
				}
				added, err := Parse(ArchARM64, strings.ReplaceAll(observer, "HELPER", helper))
				if err != nil {
					t.Fatal(err)
				}
				prepared.Funcs = append(prepared.Funcs, added.Funcs...)
				prepared.Data = append(prepared.Data, added.Data...)
				prepared.Globl = append(prepared.Globl, added.Globl...)
				prepared.UnlinkedPrelude = append(prepared.UnlinkedPrelude, added.UnlinkedPrelude...)
				if _, err := PrepareGoARM64ABI0TailContinuations(prepared, sigs, resolve); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("prepared tail recovered its removed helper native identity: %v", err)
				}
			})
		}
	}
}

func TestARM64PrivateCallCFGCopyCannotBorrowPointerPermissionForCallerFrame(t *testing.T) {
	pkg := mustGoPackage(t, "test/privatecopy", "package privatecopy\nfunc Copy(dst,src *[32]byte,n uint64)\n")
	for _, destination := range []string{
		"MOVD RSP,R8", "ADD $7,RSP,R8", "MOVD $dst+0(FP),R8",
	} {
		t.Run(destination, func(t *testing.T) {
			source := strings.Replace(arm64PrivateCallCFGCopySource, "MOVD dst+0(FP),R8", destination, 1)
			requireARM64GoAssemblerResult(t, source, true)
			for _, target := range arm64TypedNativeTargets {
				context := llvm.NewContext()
				result, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
				})
				if result != nil && !result.Module.IsNil() {
					result.Module.Dispose()
				}
				context.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s private caller-frame destination gained external-pointer permission: %v", target, err)
				}
			}
		})
	}
}
