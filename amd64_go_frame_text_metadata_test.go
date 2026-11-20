package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// Original Go object metadata and typed declarations are independent inputs.
func TestGoAMD64FrameTEXTArgumentMetadata(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		for _, row := range []struct {
			name, declaration, body string
			args                    []string
		}{
			{"void", "func Value()", "MOVQ $7,AX\nMOVQ AX,0(SP)\n", []string{"", "-0"}},
			{"input-result", "func Value(a uint64) uint64", "MOVQ a+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\n", []string{"", "-16"}},
			{"result-only", "func Value() uint64", "MOVQ $7,AX\nMOVQ AX,0(SP)\nMOVQ 0(SP),AX\nMOVQ AX,ret+0(FP)\n", []string{"", "-8"}},
			{"narrow-padded", "func Value(a uint8) uint32", "MOVBLZX a+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ 0(SP),AX\nMOVL AX,ret+8(FP)\n", []string{"", "-12", "-16"}},
		} {
			for _, args := range row.args {
				t.Run(target.name+"/"+row.name+"/24"+args, func(t *testing.T) {
					assembly := "TEXT ·Value(SB),4,$24" + args + "\n" + row.body + "RET\n"
					pkg, request := goAMD64FrameTypedFixture(t, row.declaration, assembly)
					request.Target = target.name
					listing := frameRelocationOriginal(t, pkg, request)
					known := false
					for _, line := range strings.Split(string(listing), "\n") {
						if header, valid := parseGoAMD64NativeHeader(line); valid {
							known = true
							if header.ArgsKnown != (args != "") {
								t.Fatal("original Go lost omitted/explicit argument metadata", header)
							}
						}
					}
					if !known {
						t.Fatal("original Go TEXT header missing")
					}
					if row.name == "void" && args == "" && target.name != "windows/amd64" {
						t.Run("known-header-cannot-replace-omission", func(t *testing.T) {
							changed := bytes.Replace(listing, []byte("args=0xffffffff80000000"), []byte("args=0x0"), 1)
							if bytes.Equal(changed, listing) {
								t.Fatal("actual Go omitted-argument header was not changed")
							}
							file, err := Parse(ArchAMD64, assembly)
							if err != nil {
								t.Fatal(err)
							}
							_, err = goAMD64FrameListing(changed, file, pkg,
								map[string]int{request.AssemblyFile: strings.Count(assembly, "\n") + 1})
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("a changed known-zero header replaced actual unknown metadata", err)
							}
						})
					}
					name := pkg.Path + ".Value"
					sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: "amd64", TargetTriple: target.triple,
						Sigs: map[string]FuncSig{name: sig}, ResolveSym: func(string) string { return name }}
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
						func(t *testing.T, ir string, err error) {
							if err != nil {
								t.Fatal("actual typed declaration and original TEXT metadata failed", err)
							}
							compileLLVMToObject(t, llc, target.triple, "text-args.ll", "text-args.o", ir)
							compileLLVMToObject(t, llc, target.triple, "text-args-o2.ll", "text-args-o2.o", x86MulDivRoundOptimize(t, ir))
						})
				})
			}
		}
	}
}

func TestGoAMD64FrameTEXTExplicitArgumentMismatch(t *testing.T) {
	for _, args := range []int{0, 8, 15, 17, 24} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			assembly := fmt.Sprintf("TEXT ·Value(SB),4,$24-%d\nMOVQ a+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n", args)
			pkg, request := goAMD64FrameTypedFixture(t, "func Value(a uint64) uint64", assembly)
			frameRelocationOriginal(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if owner != nil {
				if closeErr := owner.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(err, ErrProbeNeedsContext) || owner != nil {
				t.Fatal("explicit incorrect TEXT acquired a typed frame extent", err)
			}
		})
	}
}

func TestGoAMD64FrameDeclaredNoFrameMetadata(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		for _, args := range []string{"", "-0"} {
			t.Run(target+"/Idle0"+args, func(t *testing.T) {
				assembly := "TEXT ·Idle(SB),$0" + args + "\nRET\n" +
					"TEXT ·Value(SB),4,$24-16\nMOVQ a+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
				pkg, request := goAMD64FrameTypedFixture(t, "func Idle()\nfunc Value(a uint64) uint64", assembly)
				request.Target = target
				frameRelocationOriginal(t, pkg, request)
				owner := requireGoAMD64FrameCapture(t, pkg, request)
				idle, found := owner.functions[pkg.Path+".Idle"]
				if !found || idle.locals != 0 || idle.privateLeaf || idle.split || len(idle.signature.Frame.Params)+len(idle.signature.Frame.Results) != 0 {
					t.Fatal("ordinary declared no-frame entry acquired a private or incoming-frame role")
				}
				if value := owner.functions[pkg.Path+".Value"]; value.locals != 32 {
					t.Fatal("framed companion lost its exact independent physical frame")
				}
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				sigs := make(map[string]FuncSig)
				for _, name := range []string{"Idle", "Value"} {
					sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name,
						pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
					if err != nil {
						t.Fatal(err)
					}
					sigs[sig.Name] = sig
				}
				triple := map[string]string{
					"linux/amd64":   "x86_64-unknown-linux-gnu",
					"darwin/amd64":  "x86_64-apple-darwin",
					"windows/amd64": "x86_64-pc-windows-msvc",
				}[target]
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				bound, err := owner.BindFixedLocal(ctx, pkg, file, Options{
					Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
					ResolveSym: func(symbol string) string { return pkg.Path + "." + strings.TrimPrefix(symbol, "·") },
				})
				if err != nil {
					t.Fatal("ordinary no-frame companion did not retain complete source binding", err)
				}
				if bound.Sigs[pkg.Path+".Idle"].x86FixedLocal != nil || bound.Sigs[pkg.Path+".Value"].x86FixedLocal == nil {
					t.Fatal("ordinary no-frame entry borrowed its companion's local backing")
				}
			})
		}
		for _, args := range []string{"", "-16"} {
			t.Run(target+"/FPLeaf0"+args, func(t *testing.T) {
				assembly := "TEXT ·Leaf(SB),$0" + args + "\nMOVQ a+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n" +
					"TEXT ·Value(SB),4,$24-16\nMOVQ a+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
				pkg, request := goAMD64FrameTypedFixture(t, "func Leaf(a uint64) uint64\nfunc Value(a uint64) uint64", assembly)
				request.Target = target
				frameRelocationOriginal(t, pkg, request)
				sigs := make(map[string]FuncSig)
				for _, name := range []string{"Leaf", "Value"} {
					sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, pkg.Types.Scope().Lookup(name).(*types.Func),
						"amd64", types.SizesFor("gc", "amd64"))
					if err != nil {
						t.Fatal(err)
					}
					sigs[sig.Name] = sig
				}
				triple := map[string]string{
					"linux/amd64": "x86_64-unknown-linux-gnu", "darwin/amd64": "x86_64-apple-darwin",
					"windows/amd64": "x86_64-pc-windows-msvc",
				}[target]
				fixedLocalFreshAPIs(t, pkg, request, Options{
					Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
					ResolveSym: func(symbol string) string { return pkg.Path + "." + strings.TrimPrefix(symbol, "·") },
				}, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("ordinary frameless FP input/result lost its typed declaration", err)
					}
					compileLLVMToObject(t, llc, triple, "leaf.ll", "leaf.o", ir)
					compileLLVMToObject(t, llc, triple, "leaf-o2.ll", "leaf-o2.o", x86MulDivRoundOptimize(t, ir))
				})
			})
		}
	}
}
