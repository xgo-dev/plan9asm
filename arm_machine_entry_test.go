package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const armMachineEntrySource = `TEXT oracleEntry(SB),516,$0-0 // NOSPLIT|NOFRAME
 MOVW CPSR,R3
 MOVW R3,(R0)
 MOVW R13,R3
 MOVW R3,4(R0)
 MOVW R14,R3
 MOVW R3,8(R0)
 MOVW R1,-4(R13)
 MOVW -4(R13),R3
 MOVW R3,12(R0)
 MOVD F0,16(R0)
 MOVW.EQ $7,R2
 MOVW R2,24(R0)
 RET
`

func armMachineEntryOptions(triple string) Options {
	return Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{
		"oracleEntry": {Name: "oracleEntry", Ret: Void, ARMEntry: &ARMMachineEntry{
			StackBelow: 8, VFP: true, Return: ARMMachineReturnLR,
		}},
	}}
}

func TestARMMachineEntryCapturesSourceStateWithoutTypedCallerArguments(t *testing.T) {
	requireARMGoAssemblerResult(t, armMachineEntrySource, true)
	file, err := Parse(ArchARM, armMachineEntrySource)
	if err != nil {
		t.Fatal(err)
	}
	plain := armMachineEntryOptions("armv7-unknown-linux-gnueabihf")
	sig := plain.Sigs["oracleEntry"]
	sig.ARMEntry = nil
	plain.Sigs["oracleEntry"] = sig
	if _, err := Translate(file, plain); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("no native-entry contract must remain a real source failure: %v", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, armMachineEntryOptions(triple))
		if err != nil {
			t.Fatal(err)
		}
		for _, witness := range []string{"naked", "noinline", "ptr %machine_state", "mrs", "stm", "vstm", "msr", "vldm", "bx lr"} {
			if !strings.Contains(ir, witness) {
				t.Fatalf("machine-entry bridge lacks %s:\n%s", witness, ir)
			}
		}
		compileLLVMToObject(t, llc, triple, "arm-entry.ll", "arm-entry.o", ir)
	}
}

func TestARMMachineEntryRejectsUnprovedNativeBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, instruction string
		context           bool
	}{
		{"source_sp_write", "ADD $4,R13", true},
		{"source_lr_write", "MOVW R0,R14", true},
		{"pc_read", "MOVW R15,R3", true},
		{"pc_write", "MOVW R14,R15", true},
		{"unbridged_go_call", "BL external(SB)", true},
		{"unbridged_native_call", "BL (R1)", true},
		{"source_tail", "B external(SB)", true},
		{"raw_effect", "WORD $0xe1a00000", false},
		{"partial_fp_lane", "MOVF F0,F1", false},
		{"partial_fp_gp_lane", "MOVW R1,F0", false},
		{"unknown_system_state", "MOVW R1,CPSR", true},
		{"outside_source_backing", "MOVW R1,-16(R13)", true},
		{"source_sp_writeback", "MOVW.W R1,-4(R13)", true},
		{"lr_address_read", "MOVW (R14),R3", true},
		{"lr_address_writeback", "MOVW.W R1,4(R14)", true},
		{"source_sp_alias", "MOVW R13,R3\n MOVW (R3),R2", true},
		{"shifted_sp_alias", "ADD R13<<0,R1,R3\n MOVW (R3),R2", true},
		{"multiply_pair_sp_alias", "MULL R13,R1,(R2,R3)\n MOVW (R2),R4", true},
		{"shifted_sp_index", "MOVW R13<<0(R0),R3", true},
		{"unknown_return_target", "RET (R1)", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT oracleEntry(SB),516,$0-0\n " + test.instruction + "\n RET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, armMachineEntryOptions("armv7-unknown-linux-gnueabihf"))
			if err == nil || errors.Is(err, ErrProbeNeedsContext) != test.context {
				t.Fatalf("boundary context=%v, ordinary source effects never become N/A: %v", test.context, err)
			}
		})
	}
}

func TestARMMachineEntryRejectsGuessedTypedCallsAndMetadata(t *testing.T) {
	for _, op := range []string{"CALL", "B"} {
		source := "TEXT caller(SB),4,$0-0\n " + op + " oracleEntry(SB)\n RET\n" + armMachineEntrySource
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		options := armMachineEntryOptions("armv7-unknown-linux-gnueabihf")
		options.Sigs["caller"] = FuncSig{Name: "caller", Ret: Void}
		if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s may not treat an address-only carrier as an ordinary void C call: %v", op, err)
		}
	}
	for _, mutation := range []func(*FuncSig){
		func(sig *FuncSig) { sig.Args = []LLVMType{Ptr} },
		func(sig *FuncSig) { sig.Ret = I32 },
		func(sig *FuncSig) { sig.ArgRegs = []Reg{"R0"} },
		func(sig *FuncSig) { sig.Frame.Params = []FrameSlot{{Offset: 0, Type: I32, Field: -1}} },
		func(sig *FuncSig) { sig.Frame.Results = []FrameSlot{{Offset: 0, Type: I32, Field: -1}} },
		func(sig *FuncSig) { sig.ARMEntry.Return = 0 },
		func(sig *FuncSig) { sig.ARMEntry.StackBelow = 7 },
		func(sig *FuncSig) { sig.ARMEntry.StackBelow = 1<<20 + 8 },
		func(sig *FuncSig) { sig.ARMEntry.VFP = false },
	} {
		file, err := Parse(ArchARM, armMachineEntrySource)
		if err != nil {
			t.Fatal(err)
		}
		options := armMachineEntryOptions("armv7-unknown-linux-gnueabihf")
		sig := options.Sigs["oracleEntry"]
		mutation(&sig)
		options.Sigs["oracleEntry"] = sig
		if _, err := Translate(file, options); err == nil || errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("invalid caller-supplied machine contract is an error, not source N/A: %v", err)
		}
	}
}

func TestARMMachineEntryRequiresExactPhysicalEntryMetadata(t *testing.T) {
	for _, text := range []string{
		"TEXT oracleEntry(SB),4,$0-0", // NOSPLIT is not NOFRAME.
		"TEXT oracleEntry(SB),516,$-4-0",
		"TEXT oracleEntry(SB),4,$16-0",
		"TEXT oracleEntry(SB),516,$0-4",
	} {
		source := text + "\n RET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, armMachineEntryOptions("armv7-unknown-linux-gnueabihf")); err == nil {
			t.Fatalf("physical entry must not silently reinterpret source metadata %q", text)
		}
	}
	for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "armv7-apple-ios"} {
		file, err := Parse(ArchARM, armMachineEntrySource)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, armMachineEntryOptions(triple)); err == nil || errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unsupported requested entry target %q must be an options error: %v", triple, err)
		}
	}
	for _, target := range []struct {
		arch   Arch
		goarch string
	}{
		{ArchAMD64, "386"}, {ArchAMD64, "amd64"}, {ArchARM64, "arm64"}, {ArchWASM, "wasm"},
	} {
		file, err := Parse(target.arch, "TEXT oracleEntry(SB),516,$0-0\n RET\n")
		if err != nil {
			t.Fatal(err)
		}
		options := armMachineEntryOptions("armv7-unknown-linux-gnueabihf")
		options.Goarch = target.goarch
		if _, err := Translate(file, options); err == nil || errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("ARM entry option must not disappear on %s: %v", target.goarch, err)
		}
	}
}

func TestARMMachineEntryPublicAPIsAndFullRegisterObjects(t *testing.T) {
	source := armMachineEntryRegisterSource()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, armMachineEntryOptions("armv7-unknown-linux-gnueabihf"))
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	if module.Context() != ctx {
		t.Fatal("private entry body escaped its caller-owned LLVM context")
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}

	// The native source entry has no invented zero-argument Go declaration.
	// Only this explicit manual physical contract selects the address carrier.
	pkg := mustGoPackage(t, "example.com/entry", "package entry\nfunc anchor()\n")
	translation, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		ResolveSym: testResolveSym("example.com/entry"),
		ManualSig: func(name string) (FuncSig, bool) {
			if name != "example.com/entry.oracleEntry" {
				return FuncSig{}, false
			}
			sig := armMachineEntryOptions("armv7-unknown-linux-gnueabihf").Sigs["oracleEntry"]
			sig.Name = name
			return sig, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	if translation.Signatures["example.com/entry.oracleEntry"].ARMEntry == nil ||
		!strings.Contains(translation.Module.String(), ".machine_body") {
		t.Fatal("public Go binding discarded the explicit physical contract")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, armMachineEntryOptions(triple))
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "arm-entry-registers.ll", "arm-entry-registers.o", ir)
	}
}
