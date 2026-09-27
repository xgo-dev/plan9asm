package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

func TestTranslateX86WideStoresSpanComplex64Result(t *testing.T) {
	for _, tc := range []struct {
		name         string
		instruction  string
		amd64Only    bool
		needsZeroXMM bool
	}{
		{name: "movsd", instruction: "MOVSD X0, ret+0(FP)", needsZeroXMM: true},
		{name: "movq-xmm", instruction: "MOVQ X0, ret+0(FP)", needsZeroXMM: true},
		{name: "vmovq-xmm", instruction: "VMOVQ X0, ret+0(FP)", needsZeroXMM: true},
		{name: "movq-gp", instruction: "MOVQ AX, ret+0(FP)", amd64Only: true},
		{name: "vmovsd", instruction: "VMOVSD X0, ret+0(FP)", amd64Only: true, needsZeroXMM: true},
	} {
		for _, target := range []struct {
			name   string
			goarch string
			triple string
		}{
			{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
			{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
			{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
			{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
			{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
		} {
			if tc.amd64Only && target.goarch != "amd64" {
				continue
			}
			t.Run(tc.name+"/"+target.name, func(t *testing.T) {
				functionName := "widestorecomplex64result"
				source := fmt.Sprintf("TEXT %s(SB),$0-8\n", functionName)
				if tc.needsZeroXMM {
					source += "\tPXOR X0, X0\n"
				}
				source += "\t" + tc.instruction + "\n\tRET\n"
				requireX86GoAssemblerResult(t, target.goarch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs: map[string]FuncSig{
						functionName: {
							Name: functionName,
							Ret:  LLVMType("{ float, float }"),
							Frame: FrameLayout{Results: []FrameSlot{
								{Offset: 0, Type: LLVMType("float"), Index: 0, Field: -1, Name: "ret"},
								{Offset: 4, Type: LLVMType("float"), Index: 1, Field: -1, Name: "ret"},
							}},
						},
					},
				}
				if tc.name == "movq-gp" {
					mod, directErr := translateModuleDirect(file, options)
					if directErr == nil {
						mod.Dispose()
						t.Fatal("direct linear prototype unexpectedly accepted a wide aggregate-result store")
					}
					if !errors.Is(directErr, errDirectModuleUnsupported) {
						t.Fatalf("direct linear prototype error = %v, want fallback request", directErr)
					}
				}
				ll, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM 22 llc not found")
				}
				compileLLVMToObject(t, llc, target.triple, "wide-store-complex64-result.ll", "wide-store-complex64-result.o", ll)
			})
		}
	}
}

func TestAMD64VMOVSDStoresComplex64ResultRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT vmovsdcomplex64result(SB),$0-16
	MOVQ input+0(FP), AX
	VMOVSD (AX), X0
	VMOVSD X0, ret+8(FP)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"vmovsdcomplex64result": {
				Name: "vmovsdcomplex64result",
				Args: []LLVMType{Ptr},
				Ret:  LLVMType("{ float, float }"),
				Frame: FrameLayout{
					Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1, Name: "input"}},
					Results: []FrameSlot{
						{Offset: 8, Type: LLVMType("float"), Index: 0, Field: -1, Name: "ret"},
						{Offset: 12, Type: LLVMType("float"), Index: 1, Field: -1, Name: "ret"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ll += `
define void @call_vmovsdcomplex64result(ptr %input, ptr %output) {
entry:
  %result = call { float, float } @vmovsdcomplex64result(ptr %input)
  %real = extractvalue { float, float } %result, 0
  %imag = extractvalue { float, float } %result, 1
  store float %real, ptr %output, align 4
  %imagptr = getelementptr float, ptr %output, i64 1
  store float %imag, ptr %imagptr, align 4
  ret void
}
`
	mainC := `
extern void call_vmovsdcomplex64result(const float *input, float *output);
int main(void) {
  const float input[2] = { 1.25f, -2.5f };
  float got[2] = { 0.0f, 0.0f };
  call_vmovsdcomplex64result(input, got);
  if (got[0] != input[0]) return 1;
  if (got[1] != input[1]) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vmovsd_complex64_result", triple, ll, mainC, runPrefix)
}
