package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CustomHelperBoolFixture(t *testing.T, body, triple string) (*File, Options) {
	t.Helper()
	source := "TEXT compare(SB),NOSPLIT,$0-12\n" +
		"MOVL a+0(FP),SI\nMOVL b+4(FP),DI\nLEAL ret+8(FP),AX\nJMP comparebody<>(SB)\n" +
		"TEXT comparebody<>(SB),NOSPLIT,$0-0\n" + body + "\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file, Options{Goarch: "386", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimSuffix(symbol, "<>") },
		Sigs: map[string]FuncSig{
			"compare": {Name: "compare", Args: []LLVMType{I32, I32}, Ret: I1,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I1, Index: 0, Field: -1}},
				}},
			"comparebody": {Name: "comparebody", Args: []LLVMType{I32, I32, Ptr}, Ret: Void, ArgRegs: []Reg{SI, DI, AX}},
		},
	}
}

func TestX86CustomHelperCanonicalBoolCompleteSETccSource(t *testing.T) {
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(triple+"/SET"+condition+"/"+api, func(t *testing.T) {
					file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSET"+condition+" (AX)", triple)
					ir, err := x86CustomHelperBoolAPI(t, file, options, api)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ir, "call void @comparebody(i32") || !strings.Contains(ir, "define void @comparebody(i32") {
						t.Fatal("actual independent register ABI helper was removed or retyped", ir)
					}
					if signature := options.Sigs["comparebody"]; signature.Ret != Void || fmt.Sprint(signature.ArgRegs) != "[SI DI AX]" {
						t.Fatal("source proof changed the explicit helper declaration", signature)
					}
				})
			}
		}
	}
}

func x86CustomHelperBoolAPI(t *testing.T, file *File, options Options, api string, keep ...func(string, string) bool) (string, error) {
	t.Helper()
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "module" {
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
		}
		if err != nil {
			return "", err
		}
		return module.String(), nil
	}
	if api != "Go" {
		t.Fatal("unknown helper API", api)
	}
	var declarations strings.Builder
	declarations.WriteString("package custombool\n")
	helpers := make(map[string]bool)
	var assembly strings.Builder
	for _, fn := range file.Funcs {
		name := options.ResolveSym(fn.Sym)
		if strings.HasSuffix(fn.Sym, "<>") {
			helpers[name] = true
		} else {
			fmt.Fprintf(&declarations, "func %s(a,b int32) bool\n", name)
		}
		for _, ins := range fn.Instrs {
			assembly.WriteString(ins.Raw)
			assembly.WriteByte('\n')
		}
	}
	pkg := mustGoPackage(t, "custombool", declarations.String())
	request := GoModuleOptions{
		GOARCH: "386", TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym,
		ManualSig: func(name string) (FuncSig, bool) {
			if helpers[name] {
				sig, found := options.Sigs[name]
				return sig, found
			}
			return FuncSig{}, false
		},
	}
	if len(keep) != 0 {
		request.KeepFunc = keep[0]
	}
	module, err := translateGoModuleInContext(ctx, pkg, []byte(assembly.String()), request)
	if module != nil && !module.Module.IsNil() {
		defer module.Module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return module.Module.String(), nil
}

func TestX86CustomHelperBoolSelectedClosure(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(fmt.Sprint("complete=", complete), func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
			ir, err := x86CustomHelperBoolAPI(t, file, options, "Go", func(symbol, _ string) bool {
				return complete || symbol == "compare"
			})
			if complete && (err != nil || ir == "") || !complete && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
				t.Fatal("a filtered helper cannot become an unproved external result writer", complete, len(ir), err)
			}
		})
	}
}

func TestX86CustomHelperCanonicalBoolSourcePathsAndUnknowns(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"zero", "MOVB $0,(AX)", true},
		{"one", "MOVB $1,(AX)", true},
		{"branch", "CMPL SI,DI\nJE equal\nMOVB $0,(AX)\nJMP done\nequal:\nMOVB $1,(AX)\ndone:", true},
		{"missing-write", "CMPL SI,DI", false},
		{"unknown-flags", "SETLT (AX)", false},
		{"unknown-value", "MOVB CX,(AX)", false},
		{"noncanonical-two", "MOVB $2,(AX)", false},
		{"noncanonical-three", "MOVB $3,(AX)", false},
		{"noncanonical-overwrite", "CMPL SI,DI\nSETLT (AX)\nMOVB $3,(AX)", false},
		{"missing-path", "CMPL SI,DI\nJE done\nSETLT (AX)\ndone:", false},
		{"missing-input", "CMPL CX,DI\nSETLT (AX)", false},
		{"overwide-write", "MOVL $1,(AX)", false},
		{"padding-write", "MOVB $1,1(AX)", false},
		{"private-recursion", "CMPL SI,DI\nJE done\nJMP comparebody<>(SB)\ndone:\nSETLT (AX)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, row.body, "i386-unknown-linux-gnu")
			ir, err := Translate(file, options)
			if row.valid && (err != nil || ir == "") || !row.valid && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
				t.Fatal("helper result-pointer canonical proof", row.valid, len(ir), err)
			}
		})
	}
}

func TestX86CustomHelperCanonicalBoolDeclaredTransportBoundaries(t *testing.T) {
	for name, change := range map[string]func(*File, *Options){
		"missing-register": func(_ *File, options *Options) {
			sig := options.Sigs["comparebody"]
			sig.ArgRegs = sig.ArgRegs[:2]
			options.Sigs["comparebody"] = sig
		},
		"duplicate-register": func(_ *File, options *Options) {
			sig := options.Sigs["comparebody"]
			sig.ArgRegs[1] = SI
			options.Sigs["comparebody"] = sig
		},
		"unknown-argument": func(_ *File, options *Options) {
			sig := options.Sigs["comparebody"]
			sig.ArgRegs[0] = CX
			options.Sigs["comparebody"] = sig
		},
		"source-type-is-not-pointer": func(_ *File, options *Options) {
			sig := options.Sigs["comparebody"]
			sig.Args[2] = I32
			options.Sigs["comparebody"] = sig
		},
		"borrowed-I1-helper": func(_ *File, options *Options) {
			sig := options.Sigs["comparebody"]
			sig.Ret = I1
			options.Sigs["comparebody"] = sig
		},
		"fake-helper-frame": func(_ *File, options *Options) {
			sig := options.Sigs["comparebody"]
			sig.Frame.Results = []FrameSlot{{Offset: 8, Type: I1, Index: 0, Field: -1}}
			options.Sigs["comparebody"] = sig
		},
		"native-helper-entry": func(file *File, _ *Options) { file.Funcs[1].X86RawText = []byte{0xc3} },
		"source-padding":      func(file *File, _ *Options) { file.Funcs[0].Instrs[3].Args[0].FPOffset = 9 },
		"source-parameter":    func(file *File, _ *Options) { file.Funcs[0].Instrs[3].Args[0].FPOffset = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
			change(file, &options)
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved helper transport published", len(ir), err)
			}
		})
	}
}

func TestX86CanonicalBoolResultAliasWithIntegerParameters(t *testing.T) {
	file, options := x86CustomHelperBoolFixture(t, "", "i386-unknown-linux-gnu")
	var err error
	file, err = Parse(ArchAMD64, "TEXT compare(SB),NOSPLIT,$0-9\nMOVL a+0(FP),SI\nMOVL b+4(FP),DI\n"+
		"LEAL ret+8(FP),AX\nCMPL SI,DI\nSETLT (AX)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	delete(options.Sigs, "comparebody")
	if _, err := Translate(file, options); err != nil {
		t.Fatal(err)
	}
}

func TestX86CustomHelperBoolCannotInheritCallerFlags(t *testing.T) {
	file, options := x86CustomHelperBoolFixture(t, "SETLT (AX)", "i386-unknown-linux-gnu")
	var source strings.Builder
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			source.WriteString(ins.Raw)
			source.WriteByte('\n')
		}
	}
	input := strings.Replace(source.String(), "JMP comparebody<>(SB)", "CMPL SI,DI\nJMP comparebody<>(SB)", 1)
	file, err := Parse(ArchAMD64, input)
	if err != nil {
		t.Fatal(err)
	}
	if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("helper inherited caller FLAGS through its independent LLVM entry", len(ir), err)
	}
}

func TestX86CustomHelperBoolCompleteSourceRevocation(t *testing.T) {
	for _, changed := range []string{"root", "helper", "declaration"} {
		t.Run(changed, func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
			source, err := prepareX86ABI0BoolCalls(file, options)
			if err != nil || source == nil || source.callers["compare"].registerTail == nil {
				t.Fatal("actual complete canonical register-tail producer", err)
			}
			var restore func()
			if changed == "declaration" {
				sig := options.Sigs["comparebody"]
				prior := sig.ArgRegs[0]
				sig.ArgRegs[0] = CX
				restore = func() { sig.ArgRegs[0] = prior }
			} else {
				index := 0
				if changed == "helper" {
					index = 1
				}
				ins := &file.Funcs[index].Instrs[1]
				prior := ins.Raw
				ins.Raw += " // changed complete source"
				restore = func() { ins.Raw = prior }
			}
			if err := source.verify(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed source or register declaration retained its result proof", err)
			}
			restore()
			if err := source.verify(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("restoring old bytes revived a failed graph proof", err)
			}
		})
	}
}

func TestX86CustomHelperBoolAuditsOrdinaryNonparticipants(t *testing.T) {
	file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
	other, err := Parse(ArchAMD64, "TEXT other(SB),4,$0-4\nMOVL AX,X0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	file.Funcs = append(file.Funcs, other.Funcs...)
	options.Sigs["other"] = FuncSig{Name: "other", Ret: I32,
		Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}}}
	if source, err := prepareX86ABI0BoolCalls(file, options); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("whole-source helper proof hid an ordinary unwritten result", source != nil, err)
	}
}

func TestX86CustomHelperBoolSelectedPublicationRevocation(t *testing.T) {
	for _, changed := range []string{"helper-source", "helper-declaration", "missing-helper", "resolver", "target"} {
		t.Run(changed, func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
			source, err := prepareX86ABI0BoolCalls(file, options)
			if err != nil {
				t.Fatal(err)
			}
			selected := x86DirectTailSnapshot(file)
			request := options
			request.Sigs, err = numericalCloneSignatures(options.Sigs)
			if err != nil {
				t.Fatal(err)
			}
			changedResolver := false
			request.ResolveSym = func(symbol string) string {
				if changedResolver && symbol == "comparebody<>" {
					return "changed"
				}
				return options.ResolveSym(symbol)
			}
			if owned, err := source.ownsCustomRegisterTails(selected, request); err != nil || !owned {
				t.Fatal("bind the actual selected request", owned, err)
			}
			var restore func()
			switch changed {
			case "helper-source":
				prior := selected.Funcs[1].Instrs[1].Raw
				selected.Funcs[1].Instrs[1].Raw += " // changed after selection"
				restore = func() { selected.Funcs[1].Instrs[1].Raw = prior }
			case "helper-declaration":
				sig := request.Sigs["comparebody"]
				sig.ArgRegs[0] = CX
				restore = func() { sig.ArgRegs[0] = SI }
			case "missing-helper":
				prior := selected.Funcs
				selected.Funcs = selected.Funcs[:1]
				restore = func() { selected.Funcs = prior }
			case "resolver":
				changedResolver = true
				restore = func() { changedResolver = false }
			case "target":
				request.TargetTriple = "x86_64-unknown-linux-gnu"
				if owned, err := source.ownsCustomRegisterTails(selected, request); !errors.Is(err, ErrProbeNeedsContext) || owned {
					t.Fatal("an actual 64-bit target borrowed a 32-bit proof", owned, err)
				}
				request.TargetTriple = options.TargetTriple
				if owned, err := source.ownsCustomRegisterTails(selected, request); !errors.Is(err, ErrProbeNeedsContext) || owned {
					t.Fatal("restoring a target revived its failed graph", owned, err)
				}
				return
			}
			if err := source.verify(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("publication lost the selected source/declaration identity", err)
			}
			restore()
			if err := source.verify(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("restoring a selected request revived a failed graph", err)
			}
		})
	}
}
