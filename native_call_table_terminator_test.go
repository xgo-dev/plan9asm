package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

func TestNativeCallTableTerminatorSourceAndModule(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			ops := []string{"CALL"}
			if arch == "arm64" {
				ops = append(ops, "BL")
			}
			for _, op := range ops {
				for _, slots := range []int{4, 2000} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", goos, arch, op, slots), func(t *testing.T) {
						source := "#include \"textflag.h\"\nTEXT callbackTable(SB),NOSPLIT|NOFRAME,$0-0\n" +
							strings.Repeat(op+" target(SB)\n", slots)
						listing := nativePhysicalOriginalObject(t, goos, arch, source)
						if strings.Count(listing, "\tCALL\t")+strings.Count(listing, "\tBL\t") != slots {
							t.Fatal("original Go table lost its complete call inventory", listing)
						}
						opts := NativeOptions{GOOS: goos, GOARCH: arch, PackagePath: "probe",
							Imports:     map[string]string{"target": "machine_target"},
							CodeEntries: map[string]string{"callbackTable": "probe.callback_table"}}
						assembly, _, err := TranslateNativeSource([]byte(source), opts)
						if err != nil {
							t.Fatal("original Go table rejected by source formatter", err)
						}
						ir := nativeAMD64PhysicalObjects(t, source, opts)
						trap, width, trapSize := "\tud2\n", 5, 2
						if arch == "arm64" {
							trap, width, trapSize = "\tbrk #0\n", 4, 4
						}
						if !strings.Contains(assembly, trap) || strings.Contains(assembly, "\tret") ||
							!strings.Contains(ir, "naked noinline") {
							t.Fatal("source/module continuation differs or invented a return/prototype", assembly, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							code := nativeAMD64ObjectCode(t, goos, ir, level)
							end := slots * width
							if len(code) < end+trapSize {
								t.Fatalf("short table object: %d bytes", len(code))
							}
							for slot := 0; slot < slots; slot++ {
								position := slot * width
								if arch == "amd64" && code[position] != 0xe8 ||
									arch == "arm64" && binary.LittleEndian.Uint32(code[position:position+4])&0xfc000000 != 0x94000000 {
									t.Fatalf("%s call slot %d changed at byte %d", level, slot, position)
								}
							}
							if arch == "amd64" && (code[end] != 0x0f || code[end+1] != 0x0b) ||
								arch == "arm64" && binary.LittleEndian.Uint32(code[end:end+4]) != 0xd4200000 {
								t.Fatalf("%s explicit trap moved the final slot boundary", level)
							}
						}
					})
				}
			}
		}
	}
}

func TestNativeCallTableRetainsUnprovedContinuationGuards(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			prefix := "TEXT callbackTable(SB),NOSPLIT|NOFRAME,$0-0\n"
			move := "MOVQ AX,DX\n"
			if arch == "arm64" {
				move = "MOVD R0,R1\n"
			}
			for _, row := range []struct{ name, source string }{
				{"unknown callee", prefix + "CALL unknown(SB)\n"},
				{"invalid operand", prefix + "CALL $1\n"},
				{"open continuation", prefix + "CALL target(SB)\n" + move},
				{"Go arguments", strings.Replace(prefix, "$0-0", "$0-8", 1) + "CALL target(SB)\n"},
				{"missing NOSPLIT", strings.Replace(prefix, "NOSPLIT|", "", 1) + "CALL target(SB)\n"},
				{"data callee", prefix + "CALL ·data(SB)\n"},
			} {
				t.Run(goos+"/"+arch+"/"+row.name, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					mod, err := TranslateNativeModule(ctx, []byte(row.source), NativeOptions{
						GOOS: goos, GOARCH: arch, PackagePath: "probe",
						Imports:     map[string]string{"target": "machine_target", "·data": "data_object"},
						CodeEntries: map[string]string{"callbackTable": "probe.callback_table"}})
					if err == nil {
						mod.Dispose()
						t.Fatal("call-table role acquired an unproved continuation or callee")
					}
					if !mod.IsNil() {
						t.Fatal("rejected source returned a partial module")
					}
				})
			}
		}
	}
}
