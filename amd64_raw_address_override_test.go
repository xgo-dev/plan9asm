package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawAddressOverrideDoesNotBorrowCallerPointer(t *testing.T) {
	for _, access := range []struct {
		name, old, replacement string
	}{
		{"load", "MOVL $7,AX", "BYTE $0x67\nBYTE $0x8b\nBYTE $0x07"},
		{"store", "MOVL AX,(DX)", "BYTE $0x67\nBYTE $0x89\nBYTE $0x02"},
	} {
		for _, triple := range []string{
			"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
		} {
			t.Run(access.name+"/"+triple, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, access.old, access.replacement, 1)
				// These are real stock-Go objects, not executions of a program
				// that could dereference a truncated incoming address.
				x86LEAActualTargetGoObject(t, "amd64", triple, assembly)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("physical EA32 %s borrowed a full-width caller pointer: %v", access.name, err)
				}
			})
		}
	}
}

func x86AddressOverrideDecoded(t *testing.T, mode int, code []byte) []Instr {
	t.Helper()
	instructions, err := x86AddressOverrideDecode(mode, code)
	if err != nil {
		t.Fatal(err)
	}
	return instructions
}

func x86AddressOverrideDecode(mode int, code []byte) ([]Instr, error) {
	arch := "amd64"
	if mode == 32 {
		arch = "386"
	}
	file, err := Parse(ArchAMD64, "TEXT raw(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
	if err != nil {
		return nil, err
	}
	function, err := decodeX86RawDirectives(file.Funcs[0], arch)
	if err != nil {
		return nil, err
	}
	return function.Instrs, nil
}

func x86AddressOverrideNamedBytes(t *testing.T, arch, instruction string) []byte {
	t.Helper()
	listing, err := x86ScalarLiteralGoListing(t, arch, "TEXT raw(SB),4,$0-0\n"+instruction+"\nRET\n")
	if err != nil {
		t.Fatalf("actual named implicit opcode: %v\n%s", err, listing)
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "0x0000" || len(fields[1]) != 2 {
			continue
		}
		var code []byte
		for _, field := range fields[1:] {
			if len(field) != 2 {
				break
			}
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil {
				t.Fatalf("actual named opcode byte: %v\n%s", err, listing)
			}
			code = append(code, byte(value))
		}
		return code
	}
	t.Fatalf("actual named opcode lacks its byte listing:\n%s", listing)
	return nil
}

func TestX86RawAddressOverrideGenericMemoryAndImplicitStrings(t *testing.T) {
	// Cover the generic decoder's explicit read/write/RMW, scalar/vector and
	// implicit memory shapes. Specialized prefix parsers are a separate scope.
	forms := []struct {
		name string
		code []byte
	}{
		{"byte-load", []byte{0x8a, 0x07}}, {"byte-store", []byte{0x88, 0x07}},
		{"word-load", []byte{0x66, 0x8b, 0x07}}, {"word-store", []byte{0x66, 0x89, 0x07}},
		{"long-load", []byte{0x8b, 0x07}}, {"long-store", []byte{0x89, 0x07}},
		{"add-read", []byte{0x03, 0x07}}, {"add-rmw", []byte{0x01, 0x07}},
		{"compare", []byte{0x3b, 0x07}}, {"test", []byte{0x85, 0x07}},
		{"exchange", []byte{0x87, 0x07}}, {"increment", []byte{0xff, 0x07}},
		{"shift-rmw", []byte{0xc1, 0x27, 0x01}},
		{"movups-load", []byte{0x0f, 0x10, 0x07}}, {"movups-store", []byte{0x0f, 0x11, 0x07}},
		{"addps", []byte{0x0f, 0x58, 0x07}},
		{"movsb", []byte{0xa4}}, {"cmpsb", []byte{0xa6}},
		{"stosb", []byte{0xaa}}, {"lodsb", []byte{0xac}}, {"scasb", []byte{0xae}},
		{"rep-movsb", []byte{0xf3, 0xa4}}, {"repne-scasb", []byte{0xf2, 0xae}},
		{"insb", []byte{0x6c}}, {"outsb", []byte{0x6e}}, {"xlat", []byte{0xd7}},
		{"insw", []byte{0x66, 0x6d}}, {"insl", []byte{0x6d}},
		{"outsw", []byte{0x66, 0x6f}}, {"outsl", []byte{0x6f}},
		{"movsw", []byte{0x66, 0xa5}}, {"movsl", []byte{0xa5}},
		{"cmpsw", []byte{0x66, 0xa7}}, {"cmpsl", []byte{0xa7}},
		{"stosw", []byte{0x66, 0xab}}, {"stosl", []byte{0xab}},
		{"lodsw", []byte{0x66, 0xad}}, {"lodsl", []byte{0xad}},
		{"scasw", []byte{0x66, 0xaf}}, {"scasl", []byte{0xaf}},
	}
	for _, mode := range []int{32, 64} {
		modeForms := append([]struct {
			name string
			code []byte
		}(nil), forms...)
		if mode == 64 {
			modeForms = append(modeForms, struct {
				name string
				code []byte
			}{"quad-load", []byte{0x48, 0x8b, 0x07}}, struct {
				name string
				code []byte
			}{"quad-store", []byte{0x48, 0x89, 0x07}})
			for _, form := range []struct {
				name string
				code []byte
			}{
				{"movsq", []byte{0x48, 0xa5}}, {"cmpsq", []byte{0x48, 0xa7}},
				{"stosq", []byte{0x48, 0xab}}, {"lodsq", []byte{0x48, 0xad}},
				{"scasq", []byte{0x48, 0xaf}},
			} {
				modeForms = append(modeForms, form)
			}
		}
		arch := "amd64"
		if mode == 32 {
			arch = "386"
		}
		var complete []byte
		for _, form := range modeForms {
			for _, segment := range []byte{0, 0x64, 0x65} {
				complete = append(complete, 0x67)
				if segment != 0 {
					complete = append(complete, segment)
				}
				complete = append(complete, form.code...)
			}
		}
		x86HandoffOriginalBytes(t, arch, append(complete, 0xc3))
		for _, form := range modeForms {
			for _, segment := range []byte{0, 0x64, 0x65} {
				t.Run(fmt.Sprintf("mode%d/%s/segment%02x", mode, form.name, segment), func(t *testing.T) {
					code := []byte{0x67}
					if segment != 0 {
						code = append(code, segment)
					}
					code = append(code, form.code...)
					physical, err := x86asm.Decode(code, mode)
					if err != nil || physical.Len != len(code) || physical.AddrSize != mode/2 {
						t.Fatalf("actual decoder input: %+v, %v", physical, err)
					}
					instructions, err := x86AddressOverrideDecode(mode, code)
					if strings.Contains(form.name, "stos") || strings.Contains(form.name, "scas") || strings.HasPrefix(form.name, "ins") {
						if segment != 0 {
							// The decoded destination remains ES, but x/arch
							// leaves this unused FS/GS prefix unmarked. Require
							// explicit Context, not a GoSyntax parser accident.
							if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "unbound physical") || instructions != nil {
								t.Fatalf("unbound segment did not retain Context: %v", err)
							}
							return
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					marked := 0
					for _, instruction := range instructions {
						if instruction.Op == OpTEXT || instruction.Op == OpRET {
							continue
						}
						if !instruction.x86UnboundAddressOverride || instruction.x86AddressBits != mode/2 {
							t.Fatalf("generic physical memory override lost its restriction: %+v", instruction)
						}
						marked++
						ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
						if mode == 32 {
							ctx.goarch = "386"
						}
						before := output.String()
						if terminated, err := ctx.lowerInstr(0, 0, instruction, nil, nil); terminated || !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
							t.Fatalf("unbound memory emitted IR: terminated=%t, error=%v", terminated, err)
						}
					}
					if marked == 0 {
						t.Fatal("lost complete physical memory instruction")
					}
				})
			}
		}
	}
}

func TestX86RawAddressOverrideAllAddressShapesAndMoffs(t *testing.T) {
	for _, mode := range []int{32, 64} {
		shapes := [][]byte{}
		if mode == 32 {
			// All eight EA16 r/m forms, including disp16-only and BP+disp8.
			for rm := byte(0); rm < 8; rm++ {
				shape := []byte{rm}
				if rm == 6 {
					shape = append(shape, 0xc0, 0xff)
				}
				shapes = append(shapes, shape, []byte{0x40 | rm, 0xc0}, []byte{0x80 | rm, 0xc0, 0xff})
			}
		} else {
			// All base registers and SIB scales; EIP-relative r/m=5 is
			// deliberately covered by the existing closed EIP boundary.
			for rm := byte(0); rm < 8; rm++ {
				if rm != 4 && rm != 5 {
					shapes = append(shapes, []byte{rm})
				}
				if rm != 4 {
					shapes = append(shapes, []byte{0x40 | rm, 0xc0}, []byte{0x80 | rm, 0xc0, 0xff, 0xff, 0xff})
				}
			}
			for scale := byte(0); scale < 4; scale++ {
				shapes = append(shapes,
					[]byte{0x04, scale<<6 | 0x18},
					[]byte{0x04, scale<<6 | 0x1d, 0xc0, 0xff, 0xff, 0xff})
			}
			shapes = append(shapes, []byte{0x04, 0x20}, []byte{0x04, 0x25, 0xc0, 0xff, 0xff, 0xff})
		}
		for _, opcode := range []byte{0x8b, 0x89} {
			for index, shape := range shapes {
				t.Run(fmt.Sprintf("mode%d/op%02x/shape%d", mode, opcode, index), func(t *testing.T) {
					code := append([]byte{0x67, opcode}, shape...)
					found := false
					for _, instruction := range x86AddressOverrideDecoded(t, mode, code) {
						if instruction.Op == OpMOVL {
							found = true
							if !instruction.x86UnboundAddressOverride || instruction.x86AddressBits != mode/2 {
								t.Fatalf("physical memory shape lost override: %+v", instruction)
							}
						}
					}
					if !found {
						t.Fatal("lost actual ModR/M address shape")
					}
				})
			}
		}
		for _, opcode := range []byte{0xa0, 0xa1, 0xa2, 0xa3} {
			t.Run(fmt.Sprintf("mode%d/moffs%02x", mode, opcode), func(t *testing.T) {
				code := []byte{0x67, opcode, 0xc0, 0xff}
				if mode == 64 {
					code = append(code, 0xff, 0xff)
				}
				found := false
				for _, instruction := range x86AddressOverrideDecoded(t, mode, code) {
					if instruction.Op == "MOVB" || instruction.Op == OpMOVL {
						found = true
						if !instruction.x86UnboundAddressOverride || instruction.x86AddressBits != mode/2 {
							t.Fatalf("absolute address override borrowed default addressing: %+v", instruction)
						}
					}
				}
				if !found {
					t.Fatal("lost actual moffs operand")
				}
			})
		}
	}
}

func TestX86RawAddressOverrideEA32ExtendedSIBFieldsStayRestricted(t *testing.T) {
	// Physical REX.B/X extend EA32 base/index fields in 64-bit mode. The
	// index field 4 without REX.X means no index, not an incoming SP grant.
	for base := byte(0); base < 16; base++ {
		for index := byte(0); index < 16; index++ {
			for scale := byte(0); scale < 4; scale++ {
				t.Run(fmt.Sprintf("base%d/index%d/scale%d", base, index, scale), func(t *testing.T) {
					rex := byte(0x40) | base>>3 | (index>>3)<<1
					code := []byte{0x67, rex, 0x8b, 0x44, scale<<6 | (index&7)<<3 | base&7, 0x80}
					physical, err := x86asm.Decode(code, 64)
					if err != nil || physical.Len != len(code) || physical.AddrSize != 32 {
						t.Fatalf("physical extended EA32 fields: %+v, %v", physical, err)
					}
					found := false
					for _, instruction := range x86AddressOverrideDecoded(t, 64, code) {
						if instruction.Op == OpMOVL {
							found = true
							if !instruction.x86UnboundAddressOverride || instruction.x86AddressBits != 32 {
								t.Fatalf("extended EA32 acquired native pointer semantics: %+v", instruction)
							}
						}
					}
					if !found {
						t.Fatal("lost extended physical memory form")
					}
				})
			}
		}
	}
}

func TestX86RawAddressOverrideExistingTypedConsumersRemainBound(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		mode := 64
		if target.arch == "386" {
			mode = 32
		}
		forms := []struct {
			name string
			code []byte
		}{
			{"ADCXL", []byte{0x67, 0x66, 0x0f, 0x38, 0xf6, 0x18}},
			{"ADOXL", []byte{0x67, 0xf3, 0x0f, 0x38, 0xf6, 0x18}},
			{"ENQCMD", []byte{0x67, 0xf2, 0x0f, 0x38, 0xf8, 0x00}},
			{"ENQCMDS", []byte{0x67, 0xf3, 0x0f, 0x38, 0xf8, 0x00}},
			{"UMONITOR", []byte{0x67, 0xf3, 0x0f, 0xae, 0xf3}},
		}
		if mode == 64 {
			forms = append(forms, struct {
				name string
				code []byte
			}{"ADCXQ", []byte{0x67, 0x66, 0x48, 0x0f, 0x38, 0xf6, 0x18}}, struct {
				name string
				code []byte
			}{"ADOXQ", []byte{0x67, 0xf3, 0x48, 0x0f, 0x38, 0xf6, 0x18}})
		}
		for _, form := range forms {
			t.Run(target.triple+"/"+form.name, func(t *testing.T) {
				assembly := "TEXT raw(SB),4,$0-0\n" + x86RawDisplacementDirectives(form.code) + "RET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly)
				found := false
				for _, instruction := range x86AddressOverrideDecoded(t, mode, form.code) {
					if instruction.Op != Op(form.name) {
						continue
					}
					found = true
					if instruction.x86SourceRaw == nil || instruction.x86AddressBits != mode/2 || instruction.x86UnboundAddressOverride {
						t.Fatalf("dedicated typed address receipt changed: %+v", instruction)
					}
				}
				if !found {
					t.Fatal("lost dedicated width-consuming instruction")
				}
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				var ir string
				if form.name == "UMONITOR" {
					// Retain this family's existing physical-width observation;
					// it does not establish a monitor extent or runtime result.
					ir, err = Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"raw": {Name: "raw", Ret: Void}},
					})
				} else {
					// ADX and enqueue inputs are absent. Original Go/emitter
					// objects remain required, while every public API retains
					// Context instead of inventing numerical or native authority.
					ir = x86UnboundVoidRawScalarFormatObject(t, assembly, target.arch, target.triple)
				}
				if err != nil || !strings.Contains(ir, fmt.Sprintf("to i%d", mode/2)) {
					t.Fatalf("dedicated consumer lost physical truncation: %v", err)
				}
				compileLLVMToObject(t, llc, target.triple, "address-consumer.ll", "address-consumer.o", ir)
			})
		}
	}
}

func TestX86RawAddressOverrideImplicitMaskedStoreAndMonitor(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		for _, form := range []struct {
			name, named string
			code        []byte
		}{
			{"MASKMOVQ", "MASKMOVQ M1,M0", []byte{0x67, 0x0f, 0xf7, 0xc1}},
			{"MASKMOVDQU", "MASKMOVDQU X1,X0", []byte{0x67, 0x66, 0x0f, 0xf7, 0xc1}},
			{"MONITOR", "MONITOR", []byte{0x67, 0x0f, 0x01, 0xc8}},
		} {
			t.Run(target.triple+"/"+form.name, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, "TEXT raw(SB),4,$0-0\n"+form.named+"\nRET\n")
				if encoded := x86AddressOverrideNamedBytes(t, target.arch, form.named); !bytes.HasPrefix(encoded, form.code[1:]) {
					t.Fatalf("named Go form has different physical opcode: %x, want prefix %x", encoded, form.code[1:])
				}
				assembly := "TEXT raw(SB),4,$0-0\n" + x86RawDisplacementDirectives(form.code) + "RET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"raw": {Name: "raw", Ret: Void}},
				})
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("implicit physical address override borrowed default addressing: %v", err)
				}

				// Keep the complete original default-address byte control.
				// Removing 0x67 cannot supply an initialized mask/data/DI or
				// a complete MMX/EMMS region to a bare public entry.
				control := "TEXT raw(SB),4,$0-0\n" + x86RawDisplacementDirectives(form.code[1:]) + "RET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, control)
				if form.name != "MONITOR" {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, control, "func raw()", target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("default raw mask store invented its native input owner", api, err)
						}
					}
					// The same physical register/opcode control has genuine LLVM
					// objects only with independently initialized named inputs.
					// This does not grant a raw numerical or implicit-address role.
					source, declaration := x86ImplicitMaskMoveOracleRegisters(target.arch, form.name, "Default", 1, 0)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("initialized default mask-store control lost its original opcode", api, err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							body := x86StringMemoryFunction(t, text, "Default")
							if !strings.Contains(body, "asm sideeffect") || !strings.Contains(body, strings.ToLower(form.name)) ||
								!strings.Contains(body, "~{memory}") || strings.Contains(body, "call void @llvm.masked.store") ||
								form.name == "MASKMOVQ" && !strings.Contains(body, "emms") {
								t.Fatal("default opcode lost its native access or MMX cleanup", api)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					}
					return
				}
				file, err = Parse(ArchAMD64, control)
				if err != nil {
					t.Fatal(err)
				}
				ir, err = Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"raw": {Name: "raw", Ret: Void}},
				})
				if err != nil {
					t.Fatalf("default-address control regressed: %v", err)
				}
				compileLLVMToObject(t, llc, target.triple, "implicit-address.ll", "implicit-address.o", ir)
			})
		}
	}
}

func TestX86RawAddressOverrideImplicitMaskedStoreAllRegisterFields(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, xmm := range []bool{false, true} {
			last := 7
			if xmm && mode == 64 {
				last = 15
			}
			for source := 0; source <= last; source++ {
				for mask := 0; mask <= last; mask++ {
					t.Run(fmt.Sprintf("mode%d/xmm%t/source%d/mask%d", mode, xmm, source, mask), func(t *testing.T) {
						code := []byte{0x67}
						if xmm {
							code = append(code, 0x66)
						}
						if source >= 8 || mask >= 8 {
							rex := byte(0x40)
							if source >= 8 {
								rex |= 4
							}
							if mask >= 8 {
								rex |= 1
							}
							code = append(code, rex)
						}
						code = append(code, 0x0f, 0xf7, byte(0xc0|(source&7)<<3|(mask&7)))
						physical, err := x86asm.Decode(code, mode)
						if err != nil || physical.Len != len(code) || physical.AddrSize != mode/2 {
							t.Fatalf("physical implicit store: %+v, %v", physical, err)
						}
						for _, instruction := range x86AddressOverrideDecoded(t, mode, code) {
							if instruction.Op == OpTEXT || instruction.Op == OpRET {
								continue
							}
							if !instruction.x86UnboundAddressOverride || instruction.x86AddressBits != mode/2 {
								t.Fatalf("implicit address restriction lost at register alias: %+v", instruction)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86RawAddressOverrideUnsupportedImplicitDecoderBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			// Go accepts its named VEX spelling, while the pinned x/arch
			// generic decoder does not implement this opcode. Do not grant
			// a legacy/default address interpretation to its raw bytes.
			x86LEAActualTargetGoObject(t, target.arch, target.triple, "TEXT raw(SB),4,$0-0\nVMASKMOVDQU X0,X1\nRET\n")
			for _, code := range [][]byte{
				{0xc5, 0xf9, 0xf7, 0xc1}, {0x67, 0xc5, 0xf9, 0xf7, 0xc1},
				{0x0f, 0x01, 0xfa}, {0x67, 0x0f, 0x01, 0xfa}, // MONITORX
			} {
				mode := 64
				if target.arch == "386" {
					mode = 32
				}
				if _, err := x86AddressOverrideDecode(mode, code); err == nil {
					t.Fatalf("unsupported implicit raw decoder acquired a consumer: %x", code)
				}
			}
			requireLEANativeGoObject(t, target.arch, "TEXT raw(SB),4,$0-0\nMONITORX\nRET\n", false)
		})
	}
}

func TestX86RawAddressOverrideDoesNotInventMemoryForRegisterForms(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, code := range [][]byte{{0x67, 0x8b, 0xc2}, {0x67, 0x89, 0xc2}, {0x67, 0x03, 0xc2}} {
			t.Run(fmt.Sprintf("mode%d/%x", mode, code), func(t *testing.T) {
				physical, err := x86asm.Decode(code, mode)
				if err != nil || physical.Len != len(code) {
					t.Fatalf("physical register control: %+v, %v", physical, err)
				}
				for _, instruction := range x86AddressOverrideDecoded(t, mode, code) {
					if instruction.x86UnboundAddressOverride || instruction.x86AddressBits != 0 {
						t.Fatalf("ignored register prefix gained physical memory semantics: %+v", instruction)
					}
				}
			})
		}
	}
}

func TestX86RawAddressOverrideRestrictionSurvivesNormalizationAndMutation(t *testing.T) {
	assembly := "TEXT raw(SB),4,$0-0\nBYTE $0x67\nBYTE $0x8b\nBYTE $0x07\nRET\n"
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 3; pass++ {
		file, err = normalizeX86RawFile(file, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		copy := *file
		copy.Funcs = append([]Func(nil), file.Funcs...)
		copy.Funcs[0].Instrs = append([]Instr(nil), file.Funcs[0].Instrs...)
		file = &copy
		found := false
		for _, instruction := range file.Funcs[0].Instrs {
			if instruction.Op != OpMOVL {
				continue
			}
			found = true
			if !instruction.x86UnboundAddressOverride || instruction.x86AddressBits != 32 {
				t.Fatal("normalization/copy lost restrictive decoder identity")
			}
			for _, width := range []int{0, 16, 32, 64, 128} {
				mutated := instruction
				mutated.x86AddressBits = width
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{mutated}}, FuncSig{Ret: Void}, nil)
				before := output.String()
				if _, err := ctx.lowerInstr(0, 0, mutated, nil, nil); !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
					t.Fatalf("width %d laundered decoder restriction: %v", width, err)
				}
			}
		}
		if !found {
			t.Fatal("normalization/copy lost source instruction")
		}
	}
}

func TestX86RawAddressOverrideCannotReuseDefaultCallerCertificate(t *testing.T) {
	instruction := Instr{Op: OpMOVL, Args: []Operand{
		{Kind: OpReg, Reg: AX}, {Kind: OpMem, Mem: MemRef{Base: DX}},
	}}
	x86CallerRecordMemory(&instruction, 1, 4, true)
	if !x86CallerMemoryCertified(instruction, 1) {
		t.Fatal("default-width certificate control is invalid")
	}
	for _, width := range []int{0, 16, 32, 64} {
		mutated := instruction
		mutated.x86UnboundAddressOverride = true
		mutated.x86AddressBits = width
		if x86CallerMemoryCertified(mutated, 1) {
			t.Fatalf("decoder restriction reused a default-width certificate at width %d", width)
		}
		// A change to the spelling or operands cannot turn a restrictive
		// decoder receipt into a positive LEA/address capability either.
		mutated.Op = "LEAQ"
		ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{mutated}}, FuncSig{Ret: Void}, nil)
		before := output.String()
		if _, err := ctx.lowerInstr(0, 0, mutated, nil, nil); !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
			t.Fatalf("changed opcode bypassed restrictive source identity: %v", err)
		}
	}
}

func TestX86RawAddressOverrideDefaultCallerControlsAndPhysicalSegments(t *testing.T) {
	for _, replacement := range []string{
		"MOVL $7,AX\nMOVL AX,(DX)", "MOVL (DI),AX\nADDL $7,AX\nMOVL AX,(DX)",
	} {
		for _, triple := range []string{
			"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
		} {
			t.Run(triple+"/"+replacement, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", replacement, 1)
				x86LEAActualTargetGoObject(t, "amd64", triple, assembly)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, segment := range []struct {
		prefix byte
		reg    Reg
		space  int
	}{{0x64, FS, 257}, {0x65, GS, 256}} {
		t.Run(string(segment.reg), func(t *testing.T) {
			code := []byte{segment.prefix, 0x8b, 0x07}
			found := false
			for _, instruction := range x86AddressOverrideDecoded(t, 64, code) {
				if instruction.Op == OpMOVL {
					found = true
					if instruction.x86UnboundAddressOverride || instruction.x86AddressBits != 0 || instruction.Args[0].Mem.Segment != segment.reg {
						t.Fatalf("ordinary segment/address identity changed: %+v", instruction)
					}
				}
			}
			if !found {
				t.Fatal("lost segmented MOVL control")
			}
			assembly := "TEXT raw(SB),4,$0-0\n" + x86RawDisplacementDirectives(code) + "RET\n"
			triple := "x86_64-unknown-linux-gnu"
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM22 llc required")
			}
			ir := x86UnboundVoidRawScalarFormatObject(t, assembly, "amd64", triple)
			x86PackedStringCompileObject(t, llc, triple, ir, "-O0")
			initialized := strings.Replace(assembly, x86RawDisplacementDirectives(code),
				"MOVQ $0,DI\n"+x86RawDisplacementDirectives(code), 1)
			x86LEAActualTargetGoObject(t, "amd64", triple, initialized)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, initialized, "func raw()", "amd64", triple, api)
				if err != nil || !strings.Contains(ir, fmt.Sprintf("load volatile i32, ptr addrspace(%d)", segment.space)) {
					t.Fatalf("initialized default-width physical segment was erased: %s: %v", api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			}
		})
	}
}

func TestX86RawAddressOverrideFiveTargetsAndThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, opcode := range []byte{0x8b, 0x89} {
			t.Run(fmt.Sprintf("%s/%02x", target.triple, opcode), func(t *testing.T) {
				assembly, sig, pkg := x86SourceStackNumericalFixture(target.arch,
					"@MOV x+0(FP),DI\n"+x86RawDisplacementDirectives([]byte{0x67, opcode, 0x07})+"@MOV AX,ret+@WORD(FP)\nRET")
				x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				opt := x86SourceStackOptions(target.arch, target.triple, sig)
				ir, err := Translate(file, opt)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("ordinary API acquired overridden pointer: %v", err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("module API acquired overridden pointer: %v", err)
				}
				translated, err := TranslateGoModule(pkg, []byte(assembly), GoModuleOptions{
					GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: opt.ResolveSym,
				})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("typed API acquired overridden pointer: %v", err)
				}
			})
		}
	}
}

func TestX86RawAddressOverrideRetainsGenericPhysicalMemoryWidth(t *testing.T) {
	for _, mode := range []int{32, 64} {
		arch := "amd64"
		if mode == 32 {
			arch = "386"
		}
		for _, opcode := range []byte{0x8b, 0x89} {
			t.Run(fmt.Sprintf("mode%d/%02x", mode, opcode), func(t *testing.T) {
				code := []byte{0x67, opcode, 0x07}
				assembly := "TEXT raw(SB),4,$0-0\n" + x86RawDisplacementDirectives(code) + "RET\n"
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				function, err := decodeX86RawDirectives(file.Funcs[0], arch)
				if err != nil {
					t.Fatal(err)
				}
				for _, instruction := range function.Instrs {
					if instruction.Op == OpMOVL {
						if instruction.x86AddressBits != mode/2 {
							t.Fatalf("decoded physical address width lost: got %d, want %d; %+v", instruction.x86AddressBits, mode/2, instruction)
						}
						return
					}
				}
				t.Fatal("decoded raw source lost its MOVL")
			})
		}
	}
}
