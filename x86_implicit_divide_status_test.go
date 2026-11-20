package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86ImplicitDivideCannotExposeUndefinedStatus(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ImplicitDivideOracle {
			if target.arch == "386" && row.bits == 64 {
				continue
			}
			for _, read := range []string{"SETCS BX", "SETPS BX", "SETEQ BX", "SETMI BX", "SETOS BX", "LAHF"} {
				t.Run(target.triple+"/"+row.name+"/"+read, func(t *testing.T) {
					body := x86ImplicitDivideInitializedBody(row.name, row.suffix, row.bits, "CX")
					result := "BX"
					if read == "LAHF" {
						result = "AH"
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-1\nMOVL $0,AX\nCMPL AX,$0\n%s%s\nMOVB %s,ret+0(FP)\nRET\n", body, read, result)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint8", target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("division exposed architecturally undefined status as a source value", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86ImplicitDividePostTransferFootprintsStayIndependent(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.name+" BX")
				var addresses [16]bool
				var canonical [16]uint8
				for index := range addresses {
					addresses[index], canonical[index] = true, 255
				}
				wantAddress, wantCanonical := addresses, canonical
				writes, width := []Reg{AX, DX}, int64(row.bits/8)
				if row.bits == 8 {
					writes, width = writes[:1], 2
				}
				for _, register := range writes {
					index, mask, _ := x86ResultGP(register, width, arch)
					wantAddress[index] = false
					wantCanonical[index] &^= mask
					if width == 4 && arch == "amd64" {
						wantCanonical[index] |= 0xf0
					}
				}
				if got := x86ResultCallerAddressesAfter(ins, addresses, nil, arch); got != wantAddress {
					t.Fatal("implicit output retained a pointer or revoked an unrelated one", got)
				}
				if got := x86RegisterCanonicalBytesAfter(ins, canonical, arch); got != wantCanonical {
					t.Fatal("implicit outputs acquired canonical bool bytes", got)
				}
				if _, known, _ := x86TypedInstructionByteEffect(ins.Op, ins, arch); known {
					t.Fatal("post-transfer footprint supplied standalone numerical division authority")
				}
			})
		}
	}
}
