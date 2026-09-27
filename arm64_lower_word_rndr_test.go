package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestARM64RawRNDRDecoderCompleteArchitectureFamily(t *testing.T) {
	for _, form := range []struct {
		base   uint32
		reseed bool
	}{
		{base: 0xd53b2400},
		{base: 0xd53b2420, reseed: true},
	} {
		for reg := 0; reg < 32; reg++ {
			word := form.base | uint32(reg)
			decoded, ok := decodeARM64RawRNDR(word)
			if !ok || decoded.reseed != form.reseed || decoded.reg != reg {
				t.Fatalf("decode %#08x = %+v, %v", word, decoded, ok)
			}
		}
	}
	// Every bit outside the register and reseed fields is fixed. In
	// particular, adjacent system registers must keep generic MRS semantics.
	for bit := uint(6); bit < 32; bit++ {
		word := uint32(0xd53b2400) ^ (1 << bit)
		if decoded, ok := decodeARM64RawRNDR(word); ok {
			t.Fatalf("accepted mutated fixed bit %d in %#08x: %+v", bit, word, decoded)
		}
	}
}

func TestARM64RawRNDRCompleteRegisterAndStatusForms(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range []struct {
		name string
		base uint32
	}{
		{name: "rndr", base: 0xd53b2400},
		{name: "rndrrs", base: 0xd53b2420},
	} {
		for reg := uint32(0); reg < 32; reg++ {
			name := fmt.Sprintf("%s%d", form.name, reg)
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			fmt.Fprintf(&source, "WORD $%#08x\n", form.base|reg)
			fmt.Fprintf(&source, "BEQ %sdone\n", name)
			fmt.Fprintf(&source, "%sdone:\nRET\n", name)
			sigs[name] = FuncSig{Name: name, Ret: Void}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         sigs,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"rndr", "rndrrs"} {
				call := "call { i64, i1 } @llvm.aarch64." + name + "()"
				if count := strings.Count(ir, call); count != 32 {
					t.Errorf("%s has %d calls, want 32", call, count)
				}
			}
			for _, want := range []string{
				`"target-features"="+rand"`,
				"extractvalue { i64, i1 }",
				"store i1 false, ptr %flags_n",
				"store i1 false, ptr %flags_c",
				"store i1 false, ptr %flags_v",
			} {
				if !strings.Contains(ir, want) {
					t.Errorf("missing %q", want)
				}
			}
			if t.Failed() {
				return
			}
			compileLLVMToObject(t, llc, triple, "arm64-rndr.ll", "arm64-rndr.o", ir)
		})
	}
}

func TestARM64RawRNDRLLVMAssemblerOracle(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc not found")
	}
	for _, fixture := range []struct{ source, encoding string }{
		{"mrs x0, rndr", "[0x00,0x24,0x3b,0xd5]"},
		{"mrs x31, rndr", "[0x1f,0x24,0x3b,0xd5]"},
		{"mrs x0, rndrrs", "[0x20,0x24,0x3b,0xd5]"},
		{"mrs x31, rndrrs", "[0x3f,0x24,0x3b,0xd5]"},
	} {
		cmd := exec.Command(mc, "-triple=aarch64", "-mattr=+rand", "-show-encoding")
		cmd.Stdin = strings.NewReader(fixture.source + "\n")
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), fixture.encoding) {
			t.Fatalf("LLVM oracle %q: %v\n%s", fixture.source, err, output)
		}
	}
}
