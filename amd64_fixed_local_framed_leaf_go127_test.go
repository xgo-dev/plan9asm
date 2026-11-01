//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fixedLocalFramedLeafCase struct {
	name, caller, helper string
	frame                int
}

func fixedLocalFramedLeafCases() []fixedLocalFramedLeafCase {
	helper := "MOVQ $7,BP\n ADDQ BP,AX"
	return []fixedLocalFramedLeafCase{
		{"numeric_bp", "MOVQ $11,BP\n CALL leaf<>(SB)\n ADDQ BP,AX", helper, 8},
		{"private_address_bp", "LEAQ 16(SP),BP\n CALL leaf<>(SB)\n ADDQ (BP),AX", helper, 16},
		{"unknown_bp", "CALL leaf<>(SB)", helper, 24},
		{"untouched_bp", "CALL leaf<>(SB)", "ADDQ $7,AX", 56},
		{"partial_bp", "MOVB $11,BP\n CALL leaf<>(SB)\n MOVBLZX BP,BX\n ADDQ BX,AX", helper, 32},
		{"two_call_sites", "MOVQ $3,BP\n CALL leaf<>(SB)\n ADDQ BP,AX\n CALL leaf<>(SB)\n ADDQ BP,AX", helper, 40},
		{"loop_reentry", "MOVQ $11,BP\n MOVQ $3,SI\nagain:\n CALL leaf<>(SB)\n ADDQ BP,AX\n DECQ SI\n JNZ again", helper, 64},
		{"two_returns", "LEAQ 16(SP),BP\n CALL leaf<>(SB)\n ADDQ (BP),AX", `MOVQ $7,BP
 CMPQ AX,BP
 JCS small
 ADDQ BP,AX
 RET
small:
 SUBQ BP,AX`, 128},
	}
}

func fixedLocalFramedLeafSource(row fixedLocalFramedLeafCase) string {
	return fmt.Sprintf(`TEXT ·Value(SB),4,$80-16
 MOVQ a+0(FP),AX
 MOVQ AX,16(SP)
 MOVQ $7,BX
 %s
 MOVQ AX,ret+8(FP)
 RET
TEXT leaf<>(SB),4,$%d
 %s
 RET
`, row.caller, row.frame, row.helper)
}

func TestGoAMD64FixedLocalFramedLeafCompleteSources(t *testing.T) {
	for _, row := range fixedLocalFramedLeafCases() {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalFramedLeafSource(row)
			x86InsertExtractGoListing(t, "amd64", assembly)
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil || strings.Count(ir, "define ") != 1 {
						t.Fatal("observed framed leaf lost its caller or acquired an independent ABI", err)
					}
					fixedLocalPrivateLeafObjects(t, ir)
				})
		})
	}
}

const fixedLocalFramedLeafIncomingAddress = `TEXT ·Value(SB),4,$80-16
 MOVQ a+0(FP),BP
 MOVQ (BP),AX
 CALL leaf<>(SB)
 ADDQ (BP),AX
 MOVQ AX,ret+8(FP)
 RET
TEXT leaf<>(SB),4,$48
 MOVQ $7,BP
 ADDQ BP,AX
 RET
`

func TestGoAMD64FixedLocalFramedLeafIncomingAddress(t *testing.T) {
	x86InsertExtractGoListing(t, "amd64", fixedLocalFramedLeafIncomingAddress)
	pkg, request, options := fixedLocalPrivateLeafFixture(t, fixedLocalFramedLeafIncomingAddress,
		"func Value(a *uint64) uint64")
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal("caller incoming address did not survive the observed helper frame", err)
			}
			fixedLocalPrivateLeafObjects(t, ir)
		})
}

func TestGoAMD64WindowsFramedLeafCompleteObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, spelling := range []string{"leaf<>", "leaf"} {
		t.Run(spelling, func(t *testing.T) {
			assembly := strings.ReplaceAll(fixedLocalFramedLeafSource(fixedLocalFramedLeafCases()[1]), "leaf<>", spelling)
			dir := t.TempDir()
			input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
			if err := os.WriteFile(input, []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "oracle", "-o", object, input)
			command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=windows", "GOARCH=amd64")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, "amd64"); failure != nil {
				t.Fatalf("original Windows framed-helper object: %v\n%s", failure, output)
			}
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
			request.Target = "windows/amd64"
			options.TargetTriple = "x86_64-pc-windows-msvc"
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("Windows helper lost its complete frame and SEH observation", err)
					}
					compileLLVMToObject(t, llc, options.TargetTriple, "framed-leaf.ll", "framed-leaf.o", ir)
					compileLLVMToObject(t, llc, options.TargetTriple, "framed-leaf-opt.ll", "framed-leaf-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}

func TestGoAMD64WindowsFramedLeafRequiresSEH(t *testing.T) {
	assembly := fixedLocalFramedLeafSource(fixedLocalFramedLeafCases()[1])
	pkg, request, _ := fixedLocalPrivateLeafFixture(t, assembly)
	request.Target = "windows/amd64"
	source := requireGoAMD64FrameCapture(t, pkg, request)
	object, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o"))
	if err != nil {
		t.Fatal(err)
	}
	listing, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	data, err := source.frameDataObject(assembly, object)
	if err != nil {
		t.Fatal(err)
	}
	leaves, err := goAMD64WindowsPrivateLeafTexts(file, pkg, listing, data)
	if err != nil || len(leaves) != 1 {
		t.Fatal("original source lost its single private framed helper", err)
	}
	observed, err := source.observeWindowsUnwind(object, leaves)
	if err != nil {
		t.Fatal("original framed helper must carry actual Go unwind metadata", err)
	}
	for index, text := range observed.Texts {
		if text.Index != leaves[0].Index {
			continue
		}
		filtered := text.Auxiliary[:0:0]
		links := 0
		for _, aux := range text.Auxiliary {
			if aux.Type == observed.AuxType {
				links++
			} else {
				filtered = append(filtered, aux)
			}
		}
		if links != 1 {
			t.Fatal("original private frame lacks exactly one SEH owner", links)
		}
		observed.Texts[index].Auxiliary = filtered
		if err := goAMD64FrameWindowsUnwindFunctions(source.functions, source.origins, request.Directory, observed); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("framed helper borrowed the zero-frame SEH exemption", err)
		}
		return
	}
	t.Fatal("original complete object lost its helper TEXT")
}

func TestGoAMD64FixedLocalFramedLeafBoundaries(t *testing.T) {
	for _, row := range []fixedLocalFramedLeafCase{
		{"incoming_bp", "MOVQ $11,BP\n CALL leaf<>(SB)", "MOVQ BP,AX", 8},
		{"incoming_bp_memory", "LEAQ 16(SP),BP\n CALL leaf<>(SB)", "MOVQ (BP),AX", 8},
		{"partial_callee_bp", "CALL leaf<>(SB)", "MOVB $11,BP\n MOVQ BP,AX", 16},
		{"partial_caller_bp", "MOVB $11,BP\n CALL leaf<>(SB)\n MOVQ BP,AX", "MOVQ $7,BP", 24},
		{"incoming_flags", "CMPQ AX,BX\n CALL leaf<>(SB)", "SETCS CL\n MOVBLZX CL,AX", 32},
		{"returned_flags", "CALL leaf<>(SB)\n SETCS CL\n MOVBLZX CL,AX", "CMPQ AX,BX", 128},
		{"different_saved_private_bp", `LEAQ 16(SP),BP
 LEAQ 24(SP),R8
 MOVQ $3,SI
again:
 CALL leaf<>(SB)
 XCHGQ BP,R8
 DECQ SI
 JNZ again`, "MOVQ $7,BP\n ADDQ BP,AX", 8},
		{"no_automatic_bp", "MOVQ $11,BP\n CALL leaf<>(SB)\n ADDQ BP,AX", "MOVQ $7,BP\n ADDQ BP,AX", 8},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalFramedLeafSource(row)
			if row.name == "no_automatic_bp" {
				// NOSPLIT|NOFRAME is legal Go source with explicit locals,
				// but it lacks the automatic BP save that this class requires.
				assembly = strings.Replace(assembly, "TEXT leaf<>(SB),4,$8", "TEXT leaf<>(SB),516,$8", 1)
			}
			x86InsertExtractGoListing(t, "amd64", assembly)
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if owner != nil {
				defer owner.Close()
			}
			if err != nil && row.name != "no_automatic_bp" {
				t.Fatal("semantic boundary requires successful original source/frame capture", err)
			}
			if err == nil {
				file, parseErr := Parse(ArchAMD64, assembly)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				_, err = owner.BindFixedLocal(ctx, pkg, file, options)
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("automatic frame supplied caller BP or arithmetic FLAGS to source", err)
			}
			t.Logf("original Go accepted; observed frame or typed state refused: %v", err)
		})
	}
}

func TestGoAMD64SDKFramedLeafWholeOriginalSource(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/internal/fips140/nistec")
	original, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("complete original SDK source/object precondition", err)
	}
	defer original.Close()
	pkg := sdkAMD64FrameActualPackage(t, original.source)
	owner, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, Target: request.Target,
		AssemblyFile: "p256_asm_amd64.s", Environment: request.Environment,
	})
	if err != nil {
		t.Fatal("complete SDK source lost its independently observed helper frames", err)
	}
	defer owner.Close()
	// This supersedes the former whole-source rejection: automatic private
	// frames now have an observed contract. Keep every original TEXT and the
	// native-identity negatives below; cropping the helper is not acceptance.
	expanded := owner.sdkFrame.owner.source.observation.CPP[0].Output
	file, err := Parse(ArchAMD64, expanded)
	if err != nil || len(file.Funcs) != len(owner.functions) {
		t.Fatal("complete original SDK TEXT inventory changed", err)
	}
	for _, name := range []string{"p256MulInternal", "p256SqrInternal"} {
		fn, found := owner.functions[name]
		if !found || !fn.privateLeaf || fn.locals != 16 || fn.signature.Name != "" || len(fn.code) == 0 {
			t.Fatal("original nonzero helper lost its native frame or acquired a callable ABI", name)
		}
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("complete SDK frame observation changed during consumption", err)
	}
	data := owner.sdkFrame.owner.source
	data.operation.Lock()
	defer data.operation.Unlock()
	controls := 0
	for frame := range data.observation.Frames {
		for index := range data.observation.Frames[frame].Records {
			record := &data.observation.Frames[frame].Records[index]
			if record.Symbol != "p256MulInternal" && record.Symbol != "p256SqrInternal" {
				continue
			}
			for _, locals := range []uint64{0, 8, 24} {
				t.Run(fmt.Sprintf("%s/native_locals_%d", record.Symbol, locals), func(t *testing.T) {
					original := record.Locals
					record.Locals = locals
					_, _, err := owner.sdkFrameRecords()
					record.Locals = original
					if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "SDK-primary private leaf/native identity differs") {
						t.Fatal("mismatched native locals acquired the original helper frame", err)
					}
				})
				controls++
			}
		}
	}
	if controls != 6 {
		t.Fatal("complete original SDK helper mismatch inventory changed", controls)
	}
}
