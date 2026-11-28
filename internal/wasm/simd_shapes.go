package wasm

import "github.com/xgo-dev/plan9asm/internal/asm"

func isWasmV128(typ asm.LLVMType) bool {
	switch typ {
	case "<16 x i8>", "<8 x i16>", "<4 x i32>", "<2 x i64>", "<4 x float>", "<2 x double>":
		return true
	}
	return false
}

// wasmVecSupports restricts each operation to the lane shapes with a SIMD
// encoding. Go's assembler names follow cmd/internal/obj/wasm/a.out.go.
func wasmVecSupports(suffix string, lanes int, isFloat bool) bool {
	switch suffix {
	case "NARROWI16X8S", "NARROWI16X8U", "POPCNT", "RELAXEDSWIZZLE", "SHUFFLE", "SHUFFLE16",
		"SWIZZLE":
		return lanes == 16
	case "ABS", "ADD", "EQ", "NE", "NEG", "REPLACELANE", "SPLAT", "SUB":
		return true
	case "ADDSATS", "ADDSATU", "AVGRU", "EXTRACTLANES", "EXTRACTLANEU", "SUBSATS", "SUBSATU":
		return lanes >= 8
	case "EXTRACTLANE":
		return lanes <= 4
	case "ALLTRUE", "BITMASK", "GES", "GTS", "LES", "LTS", "RELAXEDLANESELECT", "SHL", "SHRS",
		"SHRU":
		return !isFloat
	case "GEU", "GTU", "LEU", "LTU", "MAXS", "MAXU", "MINS", "MINU":
		return !isFloat && lanes >= 4
	case "CEIL", "DIV", "FLOOR", "GE", "GT", "LE", "LT", "MAX", "MIN", "NEAREST", "PMAX", "PMIN",
		"RELAXEDMADD", "RELAXEDMAX", "RELAXEDMIN", "RELAXEDNMADD", "SQRT", "TRUNC":
		return isFloat
	case "CONVERTI32X4S", "CONVERTI32X4U", "DEMOTEF64X2ZERO":
		return isFloat && lanes == 4
	case "CONVERTLOWI32X4S", "CONVERTLOWI32X4U", "PROMOTELOWF32X4":
		return isFloat && lanes == 2
	case "EXTADDPAIRWISEI8X16S", "EXTADDPAIRWISEI8X16U", "EXTENDHIGHI8X16S", "EXTENDHIGHI8X16U",
		"EXTENDLOWI8X16S", "EXTENDLOWI8X16U", "EXTMULHIGHI8X16S", "EXTMULHIGHI8X16U", "EXTMULLOWI8X16S",
		"EXTMULLOWI8X16U", "NARROWI32X4S", "NARROWI32X4U", "Q15MULRSATS", "RELAXEDDOTI8X16I7X16S",
		"RELAXEDQ15MULRS":
		return lanes == 8
	case "DOTI16X8S", "EXTADDPAIRWISEI16X8S", "EXTADDPAIRWISEI16X8U", "EXTENDHIGHI16X8S",
		"EXTENDHIGHI16X8U", "EXTENDLOWI16X8S", "EXTENDLOWI16X8U", "EXTMULHIGHI16X8S",
		"EXTMULHIGHI16X8U", "EXTMULLOWI16X8S", "EXTMULLOWI16X8U", "RELAXEDDOTI8X16I7X16ADDS",
		"RELAXEDTRUNCF32X4S", "RELAXEDTRUNCF32X4U", "RELAXEDTRUNCF64X2S", "RELAXEDTRUNCF64X2SZERO",
		"RELAXEDTRUNCF64X2U", "RELAXEDTRUNCF64X2UZERO", "TRUNCSATF32X4S", "TRUNCSATF32X4U",
		"TRUNCSATF64X2SZERO", "TRUNCSATF64X2UZERO":
		return !isFloat && lanes == 4
	case "MUL":
		return lanes != 16
	case "EXTENDHIGHI32X4S", "EXTENDHIGHI32X4U", "EXTENDLOWI32X4S", "EXTENDLOWI32X4U",
		"EXTMULHIGHI32X4S", "EXTMULHIGHI32X4U", "EXTMULLOWI32X4S", "EXTMULLOWI32X4U":
		return !isFloat && lanes == 2
	}
	return false
}
