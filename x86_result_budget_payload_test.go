package plan9asm

// Independent logical byte-work oracle, not sizeof or a production charge.
// All CFG states carry these domains even when a particular source does not
// use MMX or K. FP/AUTO, canonical FP and optional aliases/stacks are additional.
const x86IndependentResultBasePayload = 16 + // GP initialized-byte masks
	16 + // Canonical GP masks
	256 + // All 32 physical Z-register byte-definedness masks
	8 + // Separate native MMX initialized-byte masks
	8 + // K initializedness
	1 + // Integer status FLAGS
	16 + // Opaque pointer identities
	16 + // Caller-address initializedness
	32 + // Actual caller-origin IDs
	1 + // Source shape discriminator
	2 + // Pending scan fact
	3 + // Predicate fact
	1 + // Direction flag
	1 + // Native string counter
	2 + // Adjacent LEA register identity and byte mask, not pointer or NUM facts
	12 // Adjacent shift: eight input-byte mask bytes and four typed byte fields
