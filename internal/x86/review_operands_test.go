package x86

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func TestDecodedSegmentAndReservedVEX32(t *testing.T) {
	ops, err := DecodeRawBytes([]byte{0x65, 0x48, 0x8b, 0x40, 0x30}, 64)
	if err != nil {
		t.Fatal(err)
	}
	m := ops[0].Args[0].Mem
	if m.Segment != asm.GS || m.Off != 48 || m.Base != asm.AX {
		t.Errorf("decoded memory = %+v", m)
	}
	if _, err = DecodeRawBytes([]byte{0xc4, 0xe1, 0x38, 0x77}, 32); err == nil {
		t.Error("reserved vvvv accepted")
	}
}

func TestSyscallPreservedDXAndTLSBase(t *testing.T) {
	for _, body := range []string{"MOVQ $39, AX\nSYSCALL\nMOVQ DX,ret+0(FP)", "LEAQ 0(SP),DX\nMOVQ $39, AX\nSYSCALL\nMOVQ DX,ret+0(FP)", "MOVQ TLS,BX\nMOVQ BX,ret+0(FP)"} {
		f, err := asm.Parse(asm.ArchAMD64, "TEXT f(SB),4,$16-8\n"+body+"\nRET")
		if err != nil {
			t.Fatal(err)
		}
		sig := asm.FuncSig{Name: "f", Ret: asm.I64, Frame: asm.FrameLayout{Results: []asm.FrameSlot{{Type: asm.I64, Field: -1}}}}
		for _, tr := range []string{"", "x86_64-unknown-linux"} {
			if _, err := CheckABI0ResultInitWithOptions(f.Funcs[0], sig, "amd64", nil, nil, asm.X87Auto, tr); err == nil {
				t.Errorf("accepted %q on %q", body, tr)
			}
		}
	}
}

func TestWindows386VEHExactAdapter(t *testing.T) {
	for _, body := range [][]asm.Instr{vehDispatchBody, legacyVEHBody} {
		fn := asm.Func{Sym: "sigtramp<>", Instrs: append([]asm.Instr{{Op: asm.OpTEXT}}, body...)}
		sig := asm.FuncSig{Name: "sigtramp", Ret: asm.Void}
		opt := asm.Options{TargetTriple: "i686-pc-windows-msvc", Goarch: "386", Sigs: map[string]asm.FuncSig{
			"runtime·badsignal2": {Ret: asm.Void},
			"runtime·sigtrampgo": {Args: []asm.LLVMType{asm.Ptr, asm.I32}, Ret: asm.I32},
		}}
		var b strings.Builder
		ok, err := translateWindows386Entry(&b, fn, sig, opt)
		if !ok || err != nil || !strings.Contains(b.String(), "retl $$4") || !strings.Contains(b.String(), "andl $$-16, %esp") {
			t.Fatalf("adapter: %t %v %s", ok, err, b.String())
		}
		fn.Instrs[2] = asm.Instr{Op: "NOP"}
		if _, err := PrepareFile(&asm.File{Funcs: []asm.Func{fn}}, "386", opt.TargetTriple); err == nil {
			t.Error("accepted a changed callee-cleanup body")
		}
	}
}

func TestRetpolineNoResultFrame(t *testing.T) {
	fn, err := asm.Parse(asm.ArchAMD64, "TEXT thunk(SB),4,$0-0\nBYTE $0xe8;LONG $4;BYTE $0xf3;BYTE $0x90;BYTE $0xeb;BYTE $0xfc;BYTE $0x48;BYTE $0x89;BYTE $4;BYTE $0x24;BYTE $0xc3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckABI0ResultInit(fn.Funcs[0], asm.FuncSig{Ret: asm.Void}, "amd64"); err != nil {
		t.Fatal(err)
	}
	var ir strings.Builder
	if err := TranslateFunc(&ir, fn.Funcs[0], asm.FuncSig{Name: "thunk", Ret: asm.Void}, nil, nil, "amd64", "x86_64h-apple-darwin", asm.X87Auto, false); err != nil || !strings.Contains(ir.String(), " prologue ") {
		t.Fatalf("native x86_64h thunk: %v\n%s", err, ir.String())
	}
}

func TestRawBlockBroadcastVEX(t *testing.T) {
	for _, op := range []struct {
		code byte
		want asm.Op
	}{{0x1a, "VBROADCASTF128"}, {0x5a, "VBROADCASTI128"}} {
		for _, tcase := range []struct {
			bytes       []byte
			base, index asm.Reg
			scale, off  int64
		}{
			{[]byte{0x70, 0x10}, "R8", "", 0, 16},
			{[]byte{0xb4, 0x98, 0xe0, 0xff, 0xff, 0xff}, "R8", "BX", 4, -32},
		} {
			raw := append([]byte{0xc4, 0x42, 0x7d, op.code}, tcase.bytes...)
			ops, err := DecodeRawBytes(raw, 64)
			if err != nil {
				t.Fatal(err)
			}
			m := ops[0].Args[0].Mem
			if ops[0].Op != op.want || ops[0].Args[1].Reg != "Y14" || m.Base != tcase.base || m.Index != tcase.index || m.Scale != tcase.scale || m.Off != tcase.off {
				t.Fatal(ops)
			}
		}
		for _, bad := range [][]byte{{0xc4, 0xe2, 0x79, op.code, 0x00}, {0xc4, 0xe2, 0xfd, op.code, 0x00}, {0xc4, 0xe2, 0x7d, op.code, 0xc0}, {0xc4, 0xe2, 0x7d, op.code, 0x05, 0, 0, 0, 0}} {
			if _, err := DecodeRawBytes(bad, 64); err == nil {
				t.Errorf("accepted %x", bad)
			}
		}
	}
}

func TestVEHDispatchContracts(t *testing.T) {
	for _, triple := range []string{"i686-pc-windows-msvc", "i686-pc-windows10-msvc"} {
		opt := asm.Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]asm.FuncSig{"runtime·badsignal2": {Ret: asm.Void}, "runtime·sigtrampgo": {Ret: asm.I32, Args: []asm.LLVMType{asm.Ptr, asm.I32}}}}
		for _, tc := range []struct {
			body   []asm.Instr
			entry  string
			legacy bool
		}{
			{legacyVEHBody, "MOVL $runtime·exceptionhandler(SB),AX", true},
			{vehDispatchBody, "MOVL argframe+0(FP),AX\nMOVL $0,CX", false},
		} {
			file, err := asm.Parse(asm.ArchAMD64, "TEXT runtime·exceptiontramp(SB),4,$0\n"+tc.entry+"\nJMP sigtramp<>(SB)")
			if err != nil {
				t.Fatal(err)
			}
			dispatch := asm.Func{Sym: "sigtramp<>", Instrs: append([]asm.Instr{{Op: asm.OpTEXT}}, tc.body...)}
			file.Funcs = append(file.Funcs, dispatch)
			if _, err = PrepareFile(file, "386", triple); err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			ok, err := translateWindows386Entry(&b, dispatch, asm.FuncSig{Name: "sigtramp", Ret: asm.Void}, opt)
			if !ok || err != nil || !strings.Contains(b.String(), "retl $$4") {
				t.Fatalf("%s: %v %s", triple, err, b.String())
			}
			if tc.legacy {
				if strings.Contains(b.String(), "tls_g") || strings.Count(b.String(), "%fs:0x14") != 3 {
					t.Fatal(b.String())
				}
				if _, err := translateWindows386Entry(&b, dispatch, asm.FuncSig{Ret: asm.I32}, opt); err == nil {
					t.Fatal("accepted non-void dispatcher")
				}
				delete(opt.Sigs, "runtime·badsignal2")
				if _, err := translateWindows386Entry(&b, dispatch, asm.FuncSig{Ret: asm.Void}, opt); err == nil {
					t.Fatal("accepted missing badsignal2")
				}
				file.Funcs[1].Instrs = append([]asm.Instr{{Op: asm.OpTEXT}}, vehDispatchBody...)
			} else {
				file.Funcs[1].Instrs = append([]asm.Instr{{Op: asm.OpTEXT}}, legacyVEHBody...)
			}
			if _, err := PrepareFile(file, "386", triple); err == nil {
				t.Fatal("accepted mismatched callback and dispatcher")
			}
		}
	}
}

func TestTLSOperandRepresentations(t *testing.T) {
	for _, tc := range []struct {
		src, mode, triple string
		segment           asm.Reg
		valid             bool
	}{
		{"MOVQ 1*(0x30)(GS),AX", "amd64", "x86_64h-apple-darwin", asm.GS, true},
		{"MOVL 1*(0x14)(FS),AX", "386", "i686-pc-windows10", asm.FS, true},
		{"MOVQ 0(TLS),ret+0(FP)", "amd64", "x86_64-pc-windows-msvc", "", false},
	} {
		f, err := asm.Parse(asm.ArchAMD64, "TEXT f(SB),4,$0-8\n"+tc.src+"\nRET")
		if err != nil {
			t.Fatal(err)
		}
		f, err = PrepareFile(f, tc.mode, tc.triple)
		if (err == nil) != tc.valid {
			t.Fatalf("%s: %v", tc.src, err)
		}
		if tc.valid && f.Funcs[0].Instrs[1].Args[0].Mem.Segment != tc.segment {
			t.Errorf("%s: lost segment", tc.src)
		}
	}
	if !matchesX86Target("amd64", "x86_64h-apple-darwin") {
		t.Fatal("x86_64h is not recognized as amd64")
	}
}

func TestWindows386TLSFollowsSourceAssembler(t *testing.T) {
	src, err := asm.Parse(asm.ArchAMD64, "TEXT f(SB),4,$0\nMOVL TLS,AX\nRET")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		fixed   bool
	}{{"go1.20.14", true}, {"devel go1.20-1234567", true}, {"go1.21rc1", false}, {"go1.27.3", false}} {
		src.SourceGoVersion = tc.version
		file, err := PrepareFile(src, "386", "i686-pc-windows10-msvc")
		if err != nil {
			t.Fatal(err)
		}
		op := file.Funcs[0].Instrs[1].Args[0]
		if tc.fixed {
			if op.Kind != asm.OpMem || op.Mem.Segment != asm.FS || op.Mem.Off != 0x14 {
				t.Errorf("%s: got %+v", tc.version, op)
			}
		} else if op.Kind != asm.OpSym || op.Sym != "runtime·tls_g(SB)" {
			t.Errorf("%s: got %+v", tc.version, op)
		}
	}
}

func TestWindows386VEHSourceVersionAndEntryShape(t *testing.T) {
	for _, tc := range []struct {
		version string
		body    []asm.Instr
	}{
		{"go1.20.14", vehDispatchBody}, {"devel go1.21-abc", legacyVEHBody}, {"not-a-go-version", nil},
	} {
		f := &asm.File{SourceGoVersion: tc.version}
		if tc.body != nil {
			f.Funcs = []asm.Func{{Sym: "sigtramp<>", Instrs: append([]asm.Instr{{Op: asm.OpTEXT}}, tc.body...)}}
		}
		if _, err := PrepareFile(f, "386", "i686-pc-windows-msvc"); err == nil {
			t.Errorf("accepted conflicting or invalid version %s", tc.version)
		}
	}
	f, err := asm.Parse(asm.ArchAMD64, "TEXT runtime·exceptiontramp(SB),4,$0\nNOP\nMOVL argframe+0(FP), AX\nMOVL $0, CX\nJMP sigtramp<>(SB)")
	if err != nil {
		t.Fatal(err)
	}
	var ir strings.Builder
	handled, err := translateWindows386Entry(&ir, f.Funcs[0], asm.FuncSig{Ret: asm.Void}, asm.Options{Goarch: "386", TargetTriple: "i686-pc-windows-msvc"})
	if !handled || err == nil || ir.Len() != 0 {
		t.Fatalf("unrecognized entry: handled=%v err=%v ir=%q", handled, err, ir.String())
	}
}

func TestSourcePCBranchesSurviveTLSExpansion(t *testing.T) {
	src := "TEXT f(SB),4,$0\np9_pc_0:\nJE 2(PC)\nMOVQ 0(TLS), AX\nMOVQ AX, BX\nJNE -2(PC)\nRET"
	f, err := asm.Parse(asm.ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareFile(f, "amd64", "x86_64-pc-windows-msvc")
	if err != nil {
		t.Fatal(err)
	}
	ins := prepared.Funcs[0].Instrs
	for _, i := range ins {
		if i.Op != "JE" && i.Op != "JNE" {
			continue
		}
		target := i.Args[0]
		found := false
		for j, label := range ins {
			if label.Op != asm.OpLABEL || label.Args[0].Sym != target.Ident {
				continue
			}
			next := ins[j+1]
			if i.Op == "JE" && next.Args[1].Reg != asm.BX || i.Op == "JNE" && next.Args[0].Sym != "runtime·tls_g(SB)" {
				t.Fatalf("%s targeted %+v", i.Op, next)
			}
			found = true
		}
		if !found || target.Kind != asm.OpIdent || target.Ident == "p9_pc_0" {
			t.Fatalf("unbound branch %+v", i)
		}
	}
	if f.Funcs[0].Instrs[2].Args[0].Kind != asm.OpMem {
		t.Fatal("mutated original source PC")
	}
}

func TestUnmodeledTLSOperandsRejected(t *testing.T) {
	for _, tc := range []struct{ triple, body string }{
		{"x86_64-unknown-linux", "CMPQ 0(TLS), 0(TLS)"}, {"x86_64-unknown-linux-ohos", "MOVQ 0(TLS), AX"},
	} {
		f, err := asm.Parse(asm.ArchAMD64, "TEXT f(SB),4,$0\n"+tc.body+"\nRET")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareFile(f, "amd64", tc.triple); err == nil {
			t.Errorf("accepted %s on %s", tc.body, tc.triple)
		}
	}
}

func Test386IndexedGoTLSBase(t *testing.T) {
	for _, base := range []string{"SP", "FP", "PC", "SB"} {
		src := "TEXT f(SB),4,$0-4\n MOVL 0(" + base + ")(TLS*1), AX\n RET"
		file, err := asm.Parse(asm.ArchAMD64, src)
		if err != nil {
			t.Fatal(err)
		}
		f, err := PrepareFile(file, "386", "i686-unknown-linux-gnu")
		if base != "SP" {
			if err == nil {
				t.Fatalf("accepted TLS base %s", base)
			}
			continue
		}
		found := false
		if err == nil {
			for _, ins := range f.Funcs[0].Instrs {
				if ins.Op == "MOVL" && ins.Args[0].Mem.GoTLSOffset {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("SP TLS rewrite: %v, %v", f, err)
		}
	}
}
