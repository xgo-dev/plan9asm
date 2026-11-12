// Package gotoolprofile observes and verifies the Go toolchain inputs consumed
// by the assembly translator. It is shared by the translator CLI and external
// compatibility runners; neither observations nor serialized proofs grant new
// lowering permissions without the corresponding source and consumer checks.
//
// This package follows the translator's version. Compatibility runners should
// pin it and the translator executable to the same source revision.
package gotoolprofile
