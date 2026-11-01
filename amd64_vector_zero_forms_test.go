package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86VectorZeroEveryGoOpcodeAttribute(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	tables := string(data)
	start := strings.Index(tables, "var _yvzeroall = []ytab{")
	if start < 0 {
		t.Fatal("actual Go zero-operand family disappeared")
	}
	table := strings.SplitN(tables[start:], "\n}", 2)[0]
	if strings.Count(table, "zcase:") != 1 || !strings.Contains(table, "{zcase: Zvex, zoffset: 2, args: argList{}},") {
		t.Fatalf("complete actual Go vector-zero operand table changed: %s", table)
	}
	if len(x86VectorZeroSpecs) != 2 || strings.Count(tables, "ytab: _yvzeroall,") != 2 {
		t.Fatal("incomplete vector-zero family")
	}
	for _, row := range []struct {
		op    Op
		width string
		first int
		bytes string
	}{
		{"VZEROUPPER", "vex128", 16, "c5 f8 77"},
		{"VZEROALL", "vex256", 0, "c5 fc 77"},
	} {
		start := strings.Index(tables, "{as: A"+string(row.op)+",")
		if start < 0 {
			t.Fatalf("actual Go omitted %s", row.op)
		}
		entry := strings.SplitN(tables[start:], "\n\t}},", 2)[0]
		if strings.Count(entry, "avxEscape") != 1 || !strings.Contains(entry, "ytab: _yvzeroall, prefix: Pavx,") || !strings.Contains(entry, "avxEscape | "+row.width+" | vex0F | vexW0, 0x77,") {
			t.Fatalf("complete actual Go zero attributes changed: %s", entry)
		}
		if x86VectorZeroSpecs[row.op].firstByte != row.first {
			t.Fatalf("%s implicit byte range differs", row.op)
		}
		for _, arch := range []string{"amd64", "386"} {
			listing, err := x86ExtensionGoListing(t, arch, string(row.op))
			if err != nil || !strings.Contains(listing, row.bytes) {
				t.Fatalf("actual Go %s/%s byte identity: %v\n%s", arch, row.op, err, listing)
			}
		}
	}
}

func TestX86VectorZeroDispatchAndImplicitModeRangeBeforeEmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range []Op{"VZEROUPPER", "VZEROALL"} {
			for _, identity := range []Op{"", opcode, Op(strings.ToLower(string(opcode))), "UNKNOWN", "VZEROALL.Z"} {
				var output strings.Builder
				ctx := &amd64Ctx{b: &output, goarch: arch, xRegSlot: map[int]string{}, yRegSlot: map[int]string{}, zRegSlot: map[int]string{}}
				for register := 0; register < 32; register++ {
					ctx.xRegSlot[register] = fmt.Sprintf("%%x%d", register)
					ctx.yRegSlot[register] = fmt.Sprintf("%%y%d", register)
					ctx.zRegSlot[register] = fmt.Sprintf("%%z%d", register)
				}
				ins := Instr{Op: identity}
				original := ins
				known, term, err := ctx.lowerVec(opcode, ins)
				conflict := identity == "UNKNOWN" || identity == "VZEROALL.Z"
				if !known || term || (err != nil) != conflict || conflict && output.Len() != 0 || !reflect.DeepEqual(ins, original) {
					t.Fatalf("dispatch identity %s/%s/%s: %t/%t/%v", arch, opcode, identity, known, term, err)
				}
				if conflict {
					continue
				}
				last, views := 16, 3
				if arch == "386" {
					last = 8
				}
				if opcode == "VZEROUPPER" {
					views = 2
				}
				if strings.Count(output.String(), "  store ") != last*views {
					t.Fatalf("%s/%s wrong implicit bank writes:\n%s", arch, opcode, output.String())
				}
				for register := last; register < 32; register++ {
					for _, bank := range []string{"x", "y", "z"} {
						if strings.Contains(output.String(), fmt.Sprintf("ptr %%%s%d\n", bank, register)) || strings.Contains(output.String(), fmt.Sprintf("ptr %%%s%d,", bank, register)) {
							t.Fatalf("%s touched excluded %s%d", opcode, bank, register)
						}
					}
				}
			}
			known, _, err := (&amd64Ctx{b: &strings.Builder{}, goarch: arch}).lowerVec(Op(string(opcode)+".Z"), Instr{})
			if !known || err == nil {
				t.Fatal("empty helper identity washed away a suffix")
			}
		}
	}
}

func TestX86VectorZeroTailAlignment(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []Op{"VZEROUPPER", "VZEROALL"} {
			t.Run(arch+"/"+string(opcode), func(t *testing.T) {
				var output strings.Builder
				ctx := &amd64Ctx{
					b: &output, goarch: arch,
					xRegSlot: map[int]string{0: "%x0"},
					yRegSlot: map[int]string{0: "%y0"},
					zRegSlot: map[int]string{0: "%z0"},
				}
				if _, _, err := ctx.lowerVectorZero(opcode, Instr{Op: opcode}); err != nil {
					t.Fatal(err)
				}
				stores := 0
				for _, line := range strings.Split(output.String(), "\n") {
					var width int
					if _, err := fmt.Sscanf(line, "  store <%d x i8>", &width); err != nil {
						continue
					}
					stores++
					alignment := width
					if opcode == "VZEROUPPER" {
						// Both 32- and 64-byte slots advance by 16. Neither
						// tail may inherit the full slot's natural alignment.
						alignment = 16
					}
					if !strings.HasSuffix(line, fmt.Sprintf(", align %d", alignment)) {
						t.Fatalf("tail store overstates or omits its alignment: %s", line)
					}
				}
				want := 3
				if opcode == "VZEROUPPER" {
					want = 2
				}
				if stores != want {
					t.Fatalf("got %d live stores, want %d", stores, want)
				}
			})
		}
	}
}

func TestX86VectorZeroCompleteGoFormsFiveObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	const source = "TEXT zeroforms(SB),4,$0-0\nVZEROUPPER\nVZEROALL\nWORD $0xf8c5\nBYTE $0x77\nWORD $0xfcc5\nBYTE $0x77\nRET\n"
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"zeroforms": {Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "vector-zero.ll", "vector-zero.o", ir)
		})
	}
}

func TestX86VectorZeroRejectsMalformedGoFormsBeforeEmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range []string{"VZEROUPPER", "VZEROALL"} {
			for _, tail := range []string{" X0", " AX", " K1", " $1", ".Z", ".BCST", ".SAE", ".RN_SAE"} {
				row := opcode + tail
				t.Run(arch+"/"+row, func(t *testing.T) {
					source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
					requireX86GoAssemblerResult(t, arch, source, false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before := output.String()
					ok, _, err := ctx.lowerVec(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1])
					if !ok || err == nil || output.String() != before {
						t.Fatalf("malformed zero form emitted/accepted: %t/%v", ok, err)
					}
				})
			}
		}
	}
}

func TestX86VectorZeroRawOpcodeLengthIdentity(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, prefix := range [][]byte{{0xc5, 0xf8}, {0xc5, 0xfc}, {0xc4, 0xe1, 0x78}, {0xc4, 0xe1, 0x7c}, {0xc4, 0xe1, 0xf8}, {0xc4, 0xe1, 0xfc}} {
			code := append(append([]byte(nil), prefix...), 0x77)
			t.Run(fmt.Sprintf("%d/%x", mode, code), func(t *testing.T) {
				instructions, err := decodeX86RawDirectiveGroup(code, mode, 0, "actual vector-zero bytes", nil)
				if err != nil || len(instructions) != 1 {
					t.Fatalf("raw zero failed: %+v/%v", instructions, err)
				}
				want := Op("VZEROUPPER")
				if prefix[len(prefix)-1]&4 != 0 {
					want = "VZEROALL"
				}
				if instructions[0].Op != want || len(instructions[0].Args) != 0 {
					t.Fatalf("raw %x became %s, want %s without operands", code, instructions[0].Op, want)
				}
			})
		}
	}
}

func TestX86VectorZeroReservedRawFormsFailClosed(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, code := range [][]byte{
			{0xc5, 0xf9, 0x77}, {0xc5, 0xfb, 0x77}, {0xc5, 0xe8, 0x77},
			{0xc4, 0xe1, 0xf9, 0x77}, {0xc4, 0xe1, 0xec, 0x77},
			{0x66, 0xc5, 0xf8, 0x77}, {0xf2, 0xc5, 0xfc, 0x77}, {0xf0, 0xc5, 0xf8, 0x77},
			{0xc5}, {0xc5, 0xf8}, {0xc4, 0xe1, 0xf8},
		} {
			t.Run(fmt.Sprintf("%d/%x", mode, code), func(t *testing.T) {
				instructions, err := decodeX86RawDirectiveGroup(code, mode, 0, "reserved zero encoding", nil)
				if err == nil {
					t.Fatalf("reserved/truncated raw %x accepted: %+v", code, instructions)
				}
				if strings.Contains(fmt.Sprint(instructions), "EMMS") {
					t.Fatalf("VEX zero was silently decoded as legacy EMMS: %+v", instructions)
				}
			})
		}
	}
}

func TestX86VectorZeroAllRawVEXFieldsAndModeDisambiguation(t *testing.T) {
	accepted := 0
	for _, mode := range []int{32, 64} {
		for _, vex3 := range []bool{false, true} {
			extensions := 1
			if vex3 {
				extensions = 8
			}
			for extension := 0; extension < extensions; extension++ {
				for payload := 0; payload < 256; payload++ {
					code := []byte{0xc5, byte(payload), 0x77}
					if vex3 {
						code = []byte{0xc4, byte(extension<<5) | 1, byte(payload), 0x77}
					}
					ins, length, known, err := decodedX86VectorZeroInstruction(code, mode)
					legacy := mode == 32 && code[1]&0xc0 != 0xc0
					valid := !legacy && payload&3 == 0 && payload&0x78 == 0x78
					if legacy {
						if known || err != nil {
							t.Fatalf("%x mode32 LES/LDS was claimed as VEX zero: %t/%v", code, known, err)
						}
						continue
					}
					if !known || (err == nil) != valid {
						t.Fatalf("%x mode%d validity: %t/%v want %t", code, mode, known, err, valid)
					}
					if !valid {
						continue
					}
					want := Op("VZEROUPPER")
					if payload&4 != 0 {
						want = "VZEROALL"
					}
					if ins.Op != want || len(ins.Args) != 0 || length != len(code) {
						t.Fatalf("%x mode%d changed zero-operation/length: %+v/%d", code, mode, ins, length)
					}
					accepted++
				}
			}
		}
	}
	if accepted != 46 {
		t.Fatalf("complete implicit VEX field axis accepted %d, want 46", accepted)
	}
}
