package plan9asm

import (
	"math/big"
	"testing"
)

// Round sqrt(value) by comparing integer squares with the exact rational.
// Neither the producer's restoring-sqrt algorithm nor host floating sqrt is
// used. For canonical positive binary80, sqrt cannot underflow or overflow its
// exponent range, even at the two reduced significand precisions.
func x87PortableSqrtSquareOracle(value *big.Rat, precision, rounding int) x87PortableBits {
	if value.Sign() < 0 || precision != 24 && precision != 53 && precision != 64 || rounding < 0 || rounding > 3 {
		panic("invalid finite square-root oracle input")
	}
	if value.Sign() == 0 {
		return x87PortableBits{}
	}
	numerator, denominator := new(big.Int).Set(value.Num()), new(big.Int).Set(value.Denom())
	highest := numerator.BitLen() - denominator.BitLen()
	if highest >= 0 {
		if numerator.Cmp(new(big.Int).Lsh(new(big.Int).Set(denominator), uint(highest))) < 0 {
			highest--
		}
	} else if new(big.Int).Lsh(new(big.Int).Set(numerator), uint(-highest)).Cmp(denominator) < 0 {
		highest--
	}
	unit := (highest >> 1) - precision + 1
	if shift := 2 * unit; shift < 0 {
		numerator.Lsh(numerator, uint(-shift))
	} else {
		denominator.Lsh(denominator, uint(shift))
	}
	floor := new(big.Int).Quo(numerator, denominator)
	lower := new(big.Int).Sqrt(floor)
	lowerSquare := new(big.Int).Mul(new(big.Int).Mul(lower, lower), denominator)
	upper := new(big.Int).Add(lower, big.NewInt(1))
	upperSquare := new(big.Int).Mul(new(big.Int).Mul(upper, upper), denominator)
	if lowerSquare.Cmp(numerator) > 0 || upperSquare.Cmp(numerator) <= 0 {
		panic("square-root interval does not enclose the exact rational")
	}
	if lowerSquare.Cmp(numerator) != 0 {
		// A midpoint is u+1/2. Compare its square after multiplying by four,
		// retaining the exact tie witness instead of approximating sqrt(value).
		midpoint := new(big.Int).Add(new(big.Int).Lsh(new(big.Int).Set(lower), 1), big.NewInt(1))
		midpoint.Mul(midpoint, midpoint)
		midpoint.Mul(midpoint, denominator)
		comparison := new(big.Int).Lsh(new(big.Int).Set(numerator), 2).Cmp(midpoint)
		if rounding == 2 || rounding == 0 && (comparison > 0 || comparison == 0 && lower.Bit(0) != 0) {
			lower.Add(lower, big.NewInt(1))
		}
	}
	exponent := unit + lower.BitLen() - 1 + 16383
	stored := new(big.Int).Set(lower)
	if shift := 64 - lower.BitLen(); shift >= 0 {
		stored.Lsh(stored, uint(shift))
	} else {
		stored.Rsh(stored, uint(-shift))
	}
	return x87PortableBits{stored.Uint64(), uint16(exponent)}
}

func TestX87PortableSqrtSquareIntervalOracle(t *testing.T) {
	for _, precision := range []int{24, 53, 64} {
		for rounding := 0; rounding < 4; rounding++ {
			for _, exponent := range []int{-16000, -2000, 0, 2000, 16000} {
				numerator, denominator := big.NewInt(1), big.NewInt(1)
				if exponent < 0 {
					denominator.Lsh(denominator, uint(-exponent))
				} else {
					numerator.Lsh(numerator, uint(exponent))
				}
				got := x87PortableSqrtSquareOracle(new(big.Rat).SetFrac(numerator, denominator), precision, rounding)
				want := x87PortableBits{1 << 63, uint16(16383 + exponent/2)}
				if got != want {
					t.Fatalf("exact power sqrt exponent=%d p=%d rc=%d: got %v want %v", exponent, precision, rounding, got, want)
				}
			}
		}
	}
	// (1+2^-24)^2 is an exactly representable 80-bit input whose square root
	// is an exact PC24 midpoint. Adjacent input bits distinguish both sides.
	for _, delta := range []int64{-1, 0, 1} {
		significand := uint64(0x8000010000008000)
		if delta < 0 {
			significand--
		} else if delta > 0 {
			significand++
		}
		input := x87PortableBits{significand, 0x3fff}
		value, valid := x87PortableRational(input)
		if !valid {
			t.Fatal("midpoint input is not canonical")
		}
		got := x87PortableSqrtSquareOracle(value, 24, 0)
		want := x87PortableBits{1 << 63, 0x3fff}
		if delta > 0 {
			want.significand += 1 << 40
		}
		if got != want {
			t.Fatalf("PC24 midpoint delta=%d got %v want %v", delta, got, want)
		}
	}
}
