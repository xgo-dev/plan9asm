module github.com/xgo-dev/plan9asm/cmd/plan9asm

go 1.24.0

require (
	github.com/xgo-dev/plan9asm v0.0.0
	golang.org/x/tools v0.42.0
)

require (
	github.com/xgo-dev/llvm v0.9.9 // indirect
	golang.org/x/arch v0.14.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
)

replace github.com/xgo-dev/plan9asm => ../..
