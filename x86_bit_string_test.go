package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func optimizedX86Module(t *testing.T, arch string, f *File, sigs map[string]FuncSig) llvm.Module {
	t.Helper()
	mod, err := TranslateModule(f, Options{Sigs: sigs, Goarch: arch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mod.Dispose)
	opts := llvm.NewPassBuilderOptions()
	defer opts.Dispose()
	if err := mod.RunPasses("default<O2>", llvm.TargetMachine{}, opts); err != nil {
		t.Fatal(err)
	}
	return mod
}

func TestX86BitStringRegisterOffset(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var src strings.Builder
		sigs := map[string]FuncSig{}
		want := map[string]int{}
		for _, width := range []int{16, 32, 64} {
			if arch == "386" && width == 64 {
				continue
			}
			suffix := map[int]string{16: "W", 32: "L", 64: "Q"}[width]
			for _, stem := range []string{"BT", "BTC", "BTR", "BTS"} {
				for _, tc := range []struct {
					name     string
					index    int
					register bool
					delta    int
				}{{"before", -1, true, -width / 8}, {"after", width, true, width / 8}, {"immediate", width, false, 0}} {
					name := stem + suffix + tc.name
					idx := fmt.Sprintf("$%d", tc.index)
					fmt.Fprintf(&src, "TEXT %s(SB),4,$0-4\nMOVL $4096, BX\n", name)
					if tc.register {
						fmt.Fprintf(&src, "MOV%s %s, CX\n", suffix, idx)
						idx = "CX"
					}
					fmt.Fprintf(&src, "%s%s %s,(BX)\nSETCS AL\nMOVBLZX AL,AX\nMOVL AX,ret+0(FP)\nRET\n", stem, suffix, idx)
					sigs[name] = FuncSig{Name: name, Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}
					want[name] = 4096 + tc.delta
				}
			}
		}
		f, err := Parse(ArchAMD64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		mod := optimizedX86Module(t, arch, f, sigs)
		for name, addr := range want {
			body := mod.NamedFunction(name).String()
			if !strings.Contains(body, fmt.Sprintf(" %d to ptr)", addr)) {
				t.Errorf("%s/%s did not access address %d:\n%s", arch, name, addr, body)
			}
		}
	}
}

func TestX86MULXOperandOrder(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, dst := range []string{"BX", "CX"} {
			src := "TEXT product(SB),4,$0-4\nMOVL $3, DX\nMOVL $0x80000000,AX\nMULXL AX,BX,CX\nMOVL " + dst + ",ret+0(FP)\nRET\n"
			f, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{"product": {Name: "product", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}}
			body := optimizedX86Module(t, arch, f, sigs).NamedFunction("product").String()
			want := map[string]string{"BX": "-2147483648", "CX": "1"}[dst]
			if !strings.Contains(body, "ret i32 "+want+"\n") {
				t.Errorf("%s %s want %s: %s", arch, dst, want, body)
			}
		}
	}
}

func TestX86RejectMissingIntegerOperandContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, instruction := range []string{"MOVL $const_Missing, AX", "TESTL $const_Missing, AX", "MOVL arg+48(FP),AX"} {
			src := "TEXT missing(SB),4,$0-4\nMOVL $1,AX\n" + instruction + "\nMOVL AX,ret+0(FP)\nRET\n"
			f, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(f, Options{Goarch: arch, Sigs: map[string]FuncSig{"missing": {Name: "missing", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s %s: %v", arch, instruction, err)
			}
		}
	}
}

func TestX86UnexpandedRuntimeMacrosRequireContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"get_tls(CX)", "PUSH_REGS_HOST_TO_ABI0()", "POP_REGS_HOST_TO_ABI0()"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT macro(SB),4,$0-0\n"+op+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"macro": {Name: "macro", Ret: Void}}})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unexpanded %s returned %v", op, err)
				}
			})
		}
	}
}

func TestX86RawDirectiveTranslation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		// b8 34 12 00 00 encodes MOVL $0x1234, AX.
		src := "TEXT fromBytes(SB),4,$0-4\nBYTE $0xb8\nLONG $0x1234\nMOVL AX,ret+0(FP)\nRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			t.Fatal(err)
		}
		sigs := map[string]FuncSig{"fromBytes": {Name: "fromBytes", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}}
		fn := optimizedX86Module(t, arch, file, sigs).NamedFunction("fromBytes").String()
		if !strings.Contains(fn, "ret i32 4660") {
			t.Errorf("raw directive on %s: %s", arch, fn)
		}
		for _, raw := range []string{"BYTE $0x0f", "BYTE $0xeb; BYTE $0x2", "BYTE $0xc2; WORD $4"} {
			f, err := Parse(ArchAMD64, "TEXT bad(SB),4,$0-0\n"+raw+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(f, Options{Goarch: arch, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Errorf("raw %s unexpectedly accepted %s", arch, raw)
			}
		}
	}
}

func TestX86GoTLSAndCallerPC(t *testing.T) {
	for _, tc := range []struct{ arch, target, slot, ins, offset string }{
		{"386", "i386-unknown-linux-gnu", "@runtime.tlsg", "MOVL", "4"},
		{"amd64", "x86_64-unknown-linux-gnu", "@runtime.tlsg", "MOVQ", "8"},
		{"386", "i686-pc-windows-msvc", "addrspace(257)", "MOVL", "4"},
		{"amd64", "x86_64-pc-windows-msvc", "addrspace(256)", "MOVQ", "8"},
		{"amd64", "x86_64-apple-macosx", "addrspace(256)", "MOVQ", "8"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			ty := I64
			if tc.arch == "386" {
				ty = I32
			}
			f, err := Parse(ArchAMD64, fmt.Sprintf("TEXT fromTLS(SB),4,$0-%s\n%s TLS,BX\n%s 4(BX)(TLS*1),AX\n%s AX,ret+0(FP)\nRET\nTEXT fromPC(SB),4,$0-%s\n%s addr-%s(FP),AX\n%s AX,ret+0(FP)\nRET\n", tc.offset, tc.ins, tc.ins, tc.ins, tc.offset, tc.ins, tc.offset, tc.ins))
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{}
			for _, name := range []string{"fromTLS", "fromPC"} {
				sigs[name] = FuncSig{Name: name, Ret: ty, Frame: FrameLayout{Results: []FrameSlot{{Type: ty, Field: -1}}}}
			}
			ir, err := Translate(f, Options{Goarch: tc.arch, TargetTriple: tc.target, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, tc.slot) || !strings.Contains(ir, "call ptr @llvm.returnaddress(i32 0)") || !strings.Contains(ir, "noinline") {
				t.Fatalf("missing TLS addressing or caller-PC contract: %s", ir)
			}
			verifyLLVMWithTargetLLC(t, ir, tc.target)
		})
	}
}

func TestX86GoTLSRejectsTargetWidthMismatch(t *testing.T) {
	f, err := Parse(ArchAMD64, "TEXT readSlot(SB),4,$0-4\nMOVL TLS,BX\nMOVL (BX)(TLS*1),AX\nMOVL AX,ret+0(FP)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "readSlot", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}
	for _, target := range []string{"x86_64-pc-windows-msvc", "x86_64-linux-gnu"} {
		if _, err := Translate(f, Options{Goarch: "386", TargetTriple: target, Sigs: map[string]FuncSig{"readSlot": sig}}); err == nil {
			t.Errorf("i386 TLS accepted on %s", target)
		}
	}
}

func TestX86MemoryOperandWriteBoundaries(t *testing.T) {
	for _, tc := range []struct{ op, target, want string }{
		{"MOVQ AX, 0(TLS)", "x86_64-unknown-linux", "@runtime.tlsg"},
		{"MOVQ AX, 0(TLS)", "x86_64-apple-darwin", "ptr addrspace(256)"},
		{"MOVQ AX, 0(BX)(TLS*1)", "x86_64-unknown-freebsd", ""},
		{"MOVQ AX, retpc-8(FP)", "x86_64-unknown-linux", ""},
		{"BTQ CX, 0(AX)(SP*1)", "x86_64-unknown-linux", ""},
	} {
		f, err := Parse(ArchAMD64, "TEXT store(SB),4,$16-0\nMOVQ $7, AX\nMOVQ $1, CX\n"+tc.op+"\nRET")
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(f, Options{Goarch: "amd64", TargetTriple: tc.target, Sigs: map[string]FuncSig{"store": {Name: "store", Ret: Void}}})
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: accepted %s", tc.target, tc.op)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			opt := runOptO2(t, ir)
			if !strings.Contains(opt, tc.want) || !strings.Contains(opt, "store i64 7,") {
				t.Errorf("%s: missing TLS write:\n%s", tc.target, opt)
			}
		}
	}
}
