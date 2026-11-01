package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func arm64NativeTargetPoolSource(t *testing.T, payload []uint32) string {
	t.Helper()
	// Actual code loads eight data bytes, kills its pool address and returns.
	// The data deliberately resembles every preflight family and invalid code.
	words := assembleARM64LLVMWords(t, []string{
		"adr x9,#16", "ldr x0,[x9]", "mov x9,xzr", "ret",
	}, "")
	var source strings.Builder
	source.WriteString("TEXT comparison(SB),516,$0-0\n")
	for _, word := range append(words, payload...) {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	return source.String()
}

func TestARM64NativeTargetPreflightPreservesProvenPoolData(t *testing.T) {
	payload := []uint32{
		0x9e620000, 0x1e602000, 0x1e600400, 0x1e602800, 0x1e604800,
		0xd53b4400, 0xd53b2400, 0x1eaf9499, 0xffffffff, 0x14000000,
	}
	source := arm64NativeTargetPoolSource(t, payload)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, blobs, err := prepareARM64RawPCRelative(file.Funcs[0])
	if err != nil || len(blobs) != 1 || len(blobs[0].bytes) != 4*len(payload) {
		t.Fatalf("independent existing pool proof lost the fixture: blobs=%v err=%v", blobs, err)
	}
	for _, target := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
		if err := validateARM64NativeTargets(file, Options{Goarch: "arm64", TargetTriple: target}); err != nil {
			t.Errorf("data acquired an instruction/target requirement for %q: %v", target, err)
		}
	}
	if !reflect.DeepEqual(file, original) {
		t.Fatal("preflight changed the original source consumed by later proofs")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		for _, consumer := range arm64NZCVConsumerIRs(t, source, "package compare\nfunc comparison()\n", target) {
			t.Run(target+"/"+consumer.name, func(t *testing.T) {
				compileLLVMToObject(t, llc, target, "pool.ll", "pool.o", consumer.ir)
			})
		}
	}
}

func TestARM64NativeTargetPreflightDataKeepsSourceAndNativeGates(t *testing.T) {
	source := arm64NativeTargetPoolSource(t, []uint32{0x1eaf9499, 0xffffffff})
	for _, instruction := range []string{
		"SCVTFD R0,F0", "FCMPD F0,F0", "MRS FPCR,R0",
		"FADDD F0,F0", "FMAXD F0,F0", "MRS RNDR,R0",
	} {
		withNative := strings.Replace(source, "$0-0\n", "$0-0\n"+instruction+"\n", 1)
		requireARM64GoAssemblerResult(t, withNative, true)
		file, err := Parse(ArchARM64, withNative)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateARM64NativeTargets(file, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("data damaged %s native-target requirement: %v", instruction, err)
		}
		if err := validateARM64NativeTargets(file, Options{TargetTriple: "aarch64-unknown-linux-gnu"}); err != nil {
			t.Errorf("data damaged %s native-target acceptance: %v", instruction, err)
		}
	}
	for _, changed := range []string{
		strings.Replace(source, "WORD $0x1eaf9499", "WORD $0x11eaf9499", 1),
		strings.Replace(source, "WORD $0x1eaf9499", "WORD $(missing_data)", 1),
		strings.Replace(source, "WORD $0x1eaf9499", "WORD $(1.0)", 1),
		// A pool address still live at return is not a closed data proof.
		strings.Replace(source, "WORD $0xaa1f03e9", "WORD $0xd503201f", 1),
	} {
		if changed == source {
			t.Fatal("negative fixture did not mutate the original source")
		}
		for _, api := range []string{"text", "module", "Go", "public-module"} {
			present, err := arm64FPControlTargetAPI(t, api, changed, "aarch64-unknown-linux-gnu")
			if present || err == nil {
				t.Errorf("%s invalid/unproved data became successful translation: %v", api, err)
			}
		}
	}
}

func TestARM64NativeTargetPreflightCannotHideExecutablePoolWords(t *testing.T) {
	// A branch into the apparent pool makes it code. A dead component after
	// RET followed by another RET is likewise not a proven literal island.
	for _, prefix := range []string{"", "RET\n", "B code\ncode:\n"} {
		for _, word := range []uint32{0x1e602000, 0x1eaf9499} {
			source := fmt.Sprintf("TEXT comparison(SB),516,$0-0\n%sWORD $%#08x\nRET\n", prefix, word)
			for _, api := range []string{"text", "module", "Go", "public-module"} {
				present, err := arm64FPControlTargetAPI(t, api, source, "")
				if present || err == nil || errors.Is(err, ErrProbeNeedsContext) != (word == 0x1e602000) {
					t.Errorf("executable WORD lost its grammar/target gate: %s %s: %v", api, source, err)
				}
			}
		}
	}
}
