package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86ENDSourceAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	const head = "TEXT ·Value(SB),4,$0-4\n"
	const tail = "MOVL AX,ret+0(FP)\nRET\n"
	const declaration = "func Value() uint32"
	targets := []struct {
		arch, triple string
		maxOperands  string
	}{
		{"amd64", "x86_64-unknown-linux-gnu", "AX,BX,CX,DX,SI"},
		{"386", "i386-unknown-linux-gnu", "AX,BX,CX"},
	}
	for _, target := range targets {
		plain := head + "MOVL $7,AX\n" + tail
		marker := strings.Join([]string{
			"END", "END.Z AX", "END.BCST", "END.BCST.Z $metadata(SB)",
			"END.SAE $1", "END.SAE.Z", "END.RN_SAE", "END.RN_SAE.Z 1(PC)",
			"END.RD_SAE", "END.RD_SAE.Z", "END.RU_SAE", "END.RU_SAE.Z",
			"END.RZ_SAE", "END.RZ_SAE.Z", "END " + target.maxOperands,
		}, "\n") + "\n"
		for _, row := range []struct {
			name, source, originalWithoutEND string
		}{
			{"fallthrough", head + "MOVL $7,AX\n" + marker + tail, plain},
			{"raw-fragments", head + "BYTE $0xb8\n" + marker + "LONG $7\n" + tail, plain},
			{"source-pc", head + "MOVL $7,AX\nJMP 3(PC)\nEND\nMOVL $31,AX\n" + tail,
				head + "MOVL $7,AX\nJMP 2(PC)\nMOVL $31,AX\n" + tail},
			{"source-pc-and-raw-fragments", head + "JMP 2(PC)\nEND\nBYTE $0xb8\nEND\nLONG $7\n" + tail,
				head + "JMP 1(PC)\nMOVL $7,AX\n" + tail},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				got := assembleX87ControlBytes(t, target.arch, row.source)
				want := assembleX87ControlBytes(t, target.arch, row.originalWithoutEND)
				if !bytes.Equal(got, want) {
					t.Fatalf("original Go emitted %x with END, want %x", got, want)
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s: %v", api, err)
					}
					optimized := x86MulDivRoundOptimize(t, ir)
					if !strings.Contains(optimized, "ret i32 7") {
						t.Fatalf("%s changed the original result:\n%s", api, optimized)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, api)
				}
			})
		}
		t.Run(target.arch+"/discarded-target", func(t *testing.T) {
			source := head + "MOVL $7,AX\nJMP removed\nMOVL $31,AX\nremoved:\nEND\n" + tail
			code := assembleX87ControlBytes(t, target.arch, source)
			if len(code) < 7 || !bytes.Equal(code[5:7], []byte{0xeb, 0}) {
				t.Fatalf("original Go no longer emits a zero-displacement jump to removed END: %x", code)
			}
			_, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, "Go")
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "discarded END") {
				t.Fatalf("discarded branch target needs its original machine layout: %v", err)
			}
		})
	}
}

func TestX86ENDRejectsInvalidSourceForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		forms := []string{"END.P AX", "END.Z.BCST AX", "END missing", "END AX,BX,CX,DX,SI,DI"}
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
			forms = append(forms, "END AX,BX,CX,DX")
		}
		for _, form := range forms {
			t.Run(arch+"/"+form, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-0\nRET\n" + form + "\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				_, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, triple, "Go")
				if err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("invalid directive must fail original source grammar: %v", err)
				}
			})
		}
	}
}

func TestX86ENDDoesNotBindAnUndefinedSourceLabel(t *testing.T) {
	const source = "TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nJMP __x86_source_pc\n" +
		"JMP 2(PC)\nEND\nMOVL AX,ret+0(FP)\nRET\n"
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"}, {"386", "i386-unknown-linux-gnu"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.s")
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"),
				"tool", "asm", "-p", "example.com/forms", "-o", path+".o", path)
			command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+target.arch, "GOTOOLCHAIN=local")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 ||
				!bytes.Contains(output, []byte("undefined label __x86_source_pc")) {
				t.Fatalf("expected original Go to reject the exact missing label: %v\n%s", err, output)
			}
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api); err == nil {
					t.Errorf("%s silently bound an undefined source label", api)
				}
			}
		})
	}
}

func TestNativeAMD64ENDLeavesMachineCodeUnchanged(t *testing.T) {
	nativeAMD64RequirePhysicalObjectBytes(t,
		"TEXT physical<>(SB),516,$0-0\nMOVL $7,AX\nEND.Z AX\nRET\n")
}
