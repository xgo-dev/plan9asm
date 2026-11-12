package main

import (
	"bytes"
	"fmt"
	"syscall"
	"unsafe"
)

func Raw(number, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr)

var kept []byte // The uintptr transport never supplies a GC root itself.

func main() {
	const sentinel = uintptr(0x123456789abcdef)
	pid, preserved := Raw(syscall.SYS_GETPID, 0, 0, sentinel, 0, 0, 0)
	if pid != uintptr(syscall.Getpid()) || preserved != sentinel {
		panic("getpid/register")
	}
	result, preserved := Raw(^uintptr(0), 0, 0, sentinel, 0, 0, 0)
	if result != ^uintptr(syscall.ENOSYS-1) || preserved != sentinel {
		panic("raw errno/register")
	}
	fmt.Println("ORIGINAL_RAW_SYSCALL_PASS getpid raw-errno preserved-DX")
	var pipes [2]int
	if err := syscall.Pipe(pipes[:]); err != nil {
		panic(err)
	}
	defer syscall.Close(pipes[0])
	message := []byte("raw-syscall-io")
	kept = make([]byte, 64)
	copy(kept[32:], message)
	for index := 0; index < 32; index++ {
		kept[index] = 0xa5
	}
	length := uintptr(len(message))
	result, preserved = Raw(syscall.SYS_WRITE, uintptr(pipes[1]), uintptr(unsafe.Pointer(&kept[32])), length, 0, 0, 0)
	syscall.Close(pipes[1])
	if result != length || preserved != length {
		panic("write/register")
	}
	result, preserved = Raw(syscall.SYS_READ, uintptr(pipes[0]), uintptr(unsafe.Pointer(&kept[3])), length, 0, 0, 0)
	if result != length || preserved != length || !bytes.Equal(kept[3:3+len(message)], message) {
		panic("read/register/memory")
	}
	for index := 0; index < 32; index++ {
		if (index < 3 || index >= 3+len(message)) && kept[index] != 0xa5 {
			panic("buffer canary")
		}
	}
	fmt.Println("ORIGINAL_RAW_SYSCALL_PASS read-write buffers-and-canaries")
}
